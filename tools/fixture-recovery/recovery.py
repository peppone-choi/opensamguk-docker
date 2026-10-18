#!/usr/bin/env python3
"""Explicit maintenance-window recovery. No existing fixture is ever deleted or SQL-rewritten."""
import argparse
import contextlib
import copy
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import stat
import time

from storage import Refused, need, private, newdir, put, write, read, digest, seal, verify_bundle, archive_root
from storage import canonical_path, isolated_output, overlaps
from transport import LocalIO
import runtime_binding as route

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('fresh_recovery_adapter', ROOT / 'tools/localhost-acceptance/harness.py')
fresh = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fresh)
DATA = ('gateway-postgres', 'game-postgres', 'gateway-redis', 'game-redis')
STOP = ('nginx', 'web-gateway', 'web-game', 'gateway-api', 'board-api', 'game-api', 'game-engine', *DATA)
START = (*DATA, 'gateway-api', 'board-api', 'game-api', 'game-engine', 'web-gateway', 'web-game', 'nginx')
STATE = ('{"Id":{{json .Id}},"Image":{{json .Image}},"RestartCount":{{json .RestartCount}},'
         '"Running":{{json .State.Running}},"Restarting":{{json .State.Restarting}},'
         '"Paused":{{json .State.Paused}},"Dead":{{json .State.Dead}},'
         '"Pid":{{json .State.Pid}},"ExitCode":{{json .State.ExitCode}},'
         '"OOMKilled":{{json .State.OOMKilled}},"Error":{{json (ne .State.Error "")}},'
         '"StartedAt":{{json .State.StartedAt}},"FinishedAt":{{json .State.FinishedAt}}}')
DAEMON = '{"ID":{{json .ID}},"SystemTime":{{json .SystemTime}}}'
STOP_FIELDS = ('Id', 'Image', 'RestartCount', 'Running', 'Restarting', 'Pid', 'ExitCode',
               'OOMKilled', 'Error', 'StartedAt', 'FinishedAt', 'Paused', 'Dead')
IMAGE = re.compile(r'sha256:[0-9a-f]{64}\Z')
SHA = re.compile(r'[0-9a-f]{40}\Z')
VOLUMES = ('gateway-pgdata', 'game-pgdata', 'gateway-redisdata', 'game-redisdata', 'profile-icons')


def timestamp_ns(value):
    """Keep Docker's nanoseconds and timezone offsets when bounding a signal interval."""
    need(isinstance(value, str), 'STOP_TIMESTAMP')
    match = re.fullmatch(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})', value)
    need(match is not None, 'STOP_TIMESTAMP')
    try:
        stamp = datetime.fromisoformat(match[1] + match[3].replace('Z', '+00:00'))
        delta = stamp - datetime(1970, 1, 1, tzinfo=timezone.utc)
    except ValueError:
        raise Refused('STOP_TIMESTAMP') from None
    result = (delta.days * 86400 + delta.seconds) * 10**9 + int((match[2] or '').ljust(9, '0'))
    need(result > 0, 'STOP_TIMESTAMP')
    return result


def stop_binding(record, model):
    # Only hashes enter the proof, never environment values or private config contents.
    return hashlib.sha256(json.dumps([record, model], sort_keys=True).encode()).hexdigest()


def checked_stop_state(state):
    need(isinstance(state, dict) and set(state) == set(STOP_FIELDS), 'STOP_STATE_FIELDS')
    need(all(type(state[k]) is bool for k in ('Running', 'Restarting', 'OOMKilled', 'Error', 'Paused', 'Dead')) and
         all(type(state[k]) is int and state[k] >= 0 for k in ('Pid', 'ExitCode', 'RestartCount')) and
         isinstance(state['Id'], str) and re.fullmatch('[a-f0-9]{64}', state['Id']) and
         isinstance(state['Image'], str) and IMAGE.fullmatch(state['Image']) and
         all(isinstance(state[k], str) for k in ('StartedAt', 'FinishedAt')), 'STOP_STATE_TYPES')
    return state


def validate_stop(attempt, service, record, model):
    need(isinstance(attempt, dict) and attempt.get('status') == 'PROVEN' and
         attempt.get('binding') == stop_binding(record, model) and
         re.fullmatch('[a-f0-9]{32}', attempt.get('nonce', '')), 'STOP_PROOF_MISSING')
    before, after = (checked_stop_state(attempt[key]) for key in ('before', 'after'))
    need(before['Running'] is True and before['Restarting'] is False and before['Pid'] > 0 and
         before['ExitCode'] == 0 and before['OOMKilled'] is False and before['Error'] is False and
         before['Paused'] is False and before['Dead'] is False,
         'STOP_BEFORE_STATE')
    need(all(before[k] == after[k] for k in ('Id', 'Image', 'StartedAt', 'RestartCount')) and
         IMAGE.fullmatch(before['Image']) and re.fullmatch('[a-f0-9]{64}', before['Id']) and
         before['Image'] == images(record, model)[service], 'STOP_INSTANCE_CHANGED')
    signal = attempt['signal']
    need(signal in ('SIGTERM', 'TERM', 'SIGINT', 'INT') and
         attempt['command'] == ['docker', 'kill', '--signal=' + signal, before['Id']], 'STOP_SIGNAL_PROOF')
    first, last = attempt['daemonBefore'], attempt['daemonAfter']
    need(isinstance(first['ID'], str) and first['ID'] and first['ID'] == last['ID'], 'STOP_DAEMON_CHANGED')
    need(timestamp_ns(before['StartedAt']) <= timestamp_ns(first['SystemTime']) <=
         timestamp_ns(after['FinishedAt']) <= timestamp_ns(last['SystemTime']), 'STOP_FINISH_INTERVAL')
    clean = (after['Running'] is False and after['Restarting'] is False and after['Pid'] == 0 and
             after['OOMKilled'] is False and after['Error'] is False and
             after['Paused'] is False and after['Dead'] is False)
    allowed = {0} if service in DATA else {0, 143 if signal in ('SIGTERM', 'TERM') else 130}
    need(clean and type(after['ExitCode']) is int and after['ExitCode'] in allowed,
         'UNCLEAN_DATA_STOP' if service in DATA else 'UNCLEAN_APP_STOP')


def permission(path, source):
    source = canonical_path(source)
    token = read(path)
    need(token.get('schema') == 1 and token.get('sourceCustody') == str(Path(source).absolute()), 'HANDOFF_TARGET')
    owner = os.environ.get('OPENSAMGUK_TASK_OWNER_SESSION', '')
    need(re.fullmatch('[a-f0-9-]{36}', owner) and token.get('ownerSession') == owner, 'HANDOFF_OWNER')
    expiry = datetime.fromisoformat(token.get('expiresAt', '').replace('Z', '+00:00'))
    need(expiry.tzinfo is not None and expiry > datetime.now(timezone.utc), 'HANDOFF_EXPIRED')
    need(token.get('scope') == 'F_FULL_RECOVERY' and token.get('windowId'), 'HANDOFF_SCOPE')
    need(token.get('sourceContractSha256') == digest(private(Path(source) / 'contract.json')), 'HANDOFF_PIN')
    return token


@contextlib.contextmanager
def heavy(meta, session, expires_at=None):
    parent = Path(meta) / '.locks'
    need(parent.is_dir() and not parent.is_symlink(), 'META_LOCK_DIRECTORY')
    path = parent / 'heavy-run'
    while True:
        if expires_at is not None:
            need(datetime.now(timezone.utc) < expires_at, 'HANDOFF_EXPIRED')
        try:
            path.mkdir(mode=0o700)
            break
        except FileExistsError:
            time.sleep(1)
    nonce = secrets.token_hex(16)
    owner = {'lane': 'fixture-recovery', 'session': session, 'nonce': nonce, 'driver_pid': os.getpid()}
    try:
        write(path / 'owner', owner)
        yield
    finally:
        if (path / 'owner').exists() and read(path / 'owner') == owner:
            (path / 'owner').unlink()
            path.rmdir()


def identity(record):
    return {key: record[key] for key in ('serverId', 'worldId', 'generation', 'origin')}


def version_args(source, app_sha, service):
    """Keep A's app identity while requiring the actual release SHA in backend build metadata."""
    return fresh.build_args(dict(source, appSha=app_sha), service)


def images(record, model):
    return {svc: record['images'][svc]['imageId'] if svc in fresh.SERVICES else
            record['supportImages'][spec['image']] for svc, spec in model['services'].items()}


def same_profile(record, source, code):
    need(fresh.profile(record) == fresh.profile(source) and
         fresh.startup_paused(record) == fresh.startup_paused(source), code)


def profile_smoke(directory, record):
    if fresh.profile(record) == 'tactical':
        fresh.tactical_smoke(directory, record)
    fresh.startup_pause_smoke(directory, record)


def selected_tree(directory, record, public=False):
    root = Path(directory) / 'topdown'
    selected = record.get('topdown')
    if selected is None:
        need(not root.exists(), 'UNSELECTED_TOPDOWN')
        return None
    fresh.topdown.settings(record)
    fresh.topdown.path_checked(root, True)
    need({p.name for p in root.iterdir()} == {selected['bakeId']}, 'TOPDOWN_ROOT')
    if public:
        need(stat.S_IMODE(root.stat().st_mode) == 0o755, 'TOPDOWN_PUBLIC_MODE')
    tree = root / selected['bakeId']
    fresh.topdown.validate(tree, selected['bakeId'], selected['manifestSha256'], selected['sourcePins'], public)
    return tree


def copy_private(source, dest, public_topdown=False):
    newdir(dest)
    for name in ('runtime.json', 'fixture.json', 'compose.json', 'contract.json', 'nginx.conf'):
        put(Path(dest) / name, private(Path(source) / name).read_bytes())
    for name in ('certs', 'battle-ws'):
        newdir(Path(dest) / name)
        for path in sorted(private(Path(source) / name, True).iterdir()):
            put(Path(dest) / name / path.name, private(path).read_bytes())
    record = read(Path(source) / 'contract.json')
    if route.active(record):
        route.snapshot(source, record, fresh)
        for name in route.PROOF_FILES:
            put(Path(dest) / name, private(Path(source) / name).read_bytes())
    tree = selected_tree(source, record)
    if tree is not None:
        if public_topdown:
            fresh.topdown.copy_bundle(tree, Path(dest), record['topdown'])
        else:
            # The backup remains wholly private; only the restored runtime is public.
            newdir(Path(dest) / 'topdown')
            target = newdir(Path(dest) / 'topdown' / tree.name)
            for path in sorted(tree.rglob('*')):
                out = target / path.relative_to(tree)
                if path.is_dir():
                    newdir(out)
                else:
                    put(out, fresh.topdown.read_file(path))
        selected_tree(dest, record, public_topdown)


def target_model(model, source, target, nonce, pins):
    """The equality test makes every environment value, alias and app identity immutable."""
    out = copy.deepcopy(model)
    project = 'osgfr' + nonce
    out['name'] = project
    labels = {fresh.NONCE_LABEL: nonce, fresh.SESSION_LABEL: source['session']}
    for kind in ('volumes', 'networks'):
        for key, spec in out[kind].items():
            spec['name'] = project + '_' + key
            spec['labels'] = dict(labels)
    for service, spec in out['services'].items():
        spec['labels'] = dict(labels)
        spec['image'] = pins[service]
        for mount in spec.get('volumes', []):
            if mount['type'] == 'bind':
                old = source['custody'] + '/'
                need(mount['source'].startswith(old), 'FOREIGN_BIND')
                mount['source'] = str(target) + '/runtime/' + mount['source'][len(old):]
    return out


class Recovery:
    def __init__(self, io):
        self.io = io
        fresh.run = io.run

    def bundle(self, path):
        m = verify_bundle(path)
        custody = Path(path) / 'custody'
        record = read(custody / 'contract.json')
        model = read(custody / 'compose.json')
        need(m['source'] == record and m['identity'] == identity(record) and
             m['pins'] == images(record, model), 'BUNDLE_SOURCE_BINDING')
        selected_tree(custody, record)
        proof = read(Path(path) / 'stop-proof.json')
        need(not proof.get('stopFailed') and set(proof.get('stopAttempts', {})) == set(STOP), 'BUNDLE_STOP_PROOF')
        for svc in STOP:
            validate_stop(proof['stopAttempts'][svc], svc, record, model)
        fresh.identity(record)
        fresh.validate_model(model, record)
        route.snapshot(custody, record, fresh)
        need(digest(custody / 'compose.json') == record['configSha256'] and
             digest(custody / 'nginx.conf') == record.get('runtimeNginxSha256', record['nginxSha256']) and
             fresh.tree_hash(custody / 'certs') == record['certsSha256'], 'BUNDLE_CUSTODY_BINDING')
        need(model == fresh.model_for(record, read(custody / 'runtime.json')), 'BUNDLE_APP_CONFIG')
        return m

    def target(self, path):
        path = private(path, True)
        t = read(path / 'target.json')
        m = self.bundle(t['bundle'])
        rec = t['record']
        need({k: v for k, v in rec.items() if k.startswith('runtime') or k == 'battleRouting'} ==
             {k: v for k, v in m['source'].items() if k.startswith('runtime') or k == 'battleRouting'} and
             rec.get('dockerSha') == m['source'].get('dockerSha'), 'TARGET_RUNTIME_PROVENANCE')
        if route.active(m['source']):
            need(t.get('runtimeBinding') == route.copied_binding(path / 'runtime',
                 Path(t['bundle']) / 'custody', m['source'], fresh), 'TARGET_RUNTIME_COPY_BINDING')
        else:
            need('runtimeBinding' not in t, 'UNEXPECTED_RUNTIME_COPY_BINDING')
        same_profile(rec, m['source'], 'TARGET_PROFILE_BINDING')
        need(rec.get('topdown') == m['source'].get('topdown'), 'TARGET_TOPDOWN_BINDING')
        selected_tree(path / 'runtime', rec, True)
        need(re.fullmatch('[a-f0-9]{16}', rec.get('nonce', '')) and rec['nonce'] != m['source']['nonce'] and
             rec['project'] == 'osgfr' + rec['nonce'] and rec['custody'] == str(path) and
             rec['session'] == m['source']['session'] and identity(rec) == m['identity'], 'TARGET_IDENTITY')
        need(set(t['pins']) == set(m['pins']) and
             all(t['pins'][s] == m['pins'][s] for s in m['pins'] if s not in fresh.SERVICES), 'TARGET_SUPPORT_IMAGES')
        model = read(path / 'compose.json')
        expected = target_model(read(Path(t['bundle']) / 'custody/compose.json'), m['source'], path, rec['nonce'], t['pins'])
        need(model == expected and digest(path / 'compose.json') == t['composeSha256'], 'TARGET_CONFIG_CHANGED')
        need(images(rec, model) == t['pins'], 'TARGET_IMAGE_BINDING')
        if rec['appSha'] == m['source']['appSha']:
            need(t['pins'] == m['pins'], 'TARGET_A_IMAGES')
        else:
            for svc in fresh.SERVICES:
                labels = fresh.inspect_image(t['pins'][svc])['Config']['Labels']
                need(t['pins'][svc] != m['pins'][svc] and
                     labels.get('org.opencontainers.image.revision') == rec['appSha'] and
                     labels.get('org.opensamguk.local.source-tree') == rec['sourceTreeSha256'] and
                     labels.get('org.opensamguk.local.build-args') == hashlib.sha256(json.dumps(
                         version_args(m['source'], rec['appSha'], svc), sort_keys=True).encode()).hexdigest(), 'TARGET_B_IMAGES')
        return t, model

    def source(self, path):
        directory, record = fresh.load(path)
        need(record.get('status') == 'SMOKE_PASSED', 'SOURCE_NOT_ACCEPTED')
        model = (route.live_model(directory, record, fresh) if route.active(record)
                 else fresh.verify_files(directory, record))
        fresh.verify_images(record)
        self.verify(record, model, healthy=False)
        return directory, record, model

    def verify(self, record, model, healthy=False, partial=False):
        if route.active(record):
            if record['project'].startswith('osgfr'):
                self.target(record['custody'])
            else:
                route.live_model(record['custody'], record, fresh)
        selected_tree(Path(record['custody']) / ('runtime' if record['project'].startswith('osgfr') else ''), record, True)
        inventory = fresh.inventory(record)
        fresh.assert_owned(record, inventory)
        if not partial:
            need(len(inventory['container']) == 11 and len(inventory['volume']) == 5
                 and len(inventory['network']) == 1, 'RESOURCE_SET')
        need({v['Name'] for v in inventory['volume']} <=
             {v['name'] for v in model['volumes'].values()}, 'UNEXPECTED_VOLUME')
        need({n['Name'] for n in inventory['network']} <= {record['project'] + '_local'}, 'UNEXPECTED_NETWORK')
        by_service = {c['Config']['Labels'].get('com.docker.compose.service'): c for c in inventory['container']}
        need(len(by_service) == len(inventory['container']) and
             (set(by_service) <= set(model['services']) if partial else set(by_service) == set(model['services'])), 'SERVICE_SET')
        own_ids = {c['Id'] for c in by_service.values()}
        for volume in inventory['volume']:
            info = json.loads(self.io.run(['docker', 'volume', 'inspect', '--format',
                '{"Driver":{{json .Driver}},"Options":{{json .Options}}}', volume['Name']]))
            need(info['Driver'] == 'local' and not info['Options'], 'REMOTE_VOLUME')
            consumers = self.io.run(['docker', 'ps', '-aq', '--filter', 'volume=' + volume['Name']]).decode().split()
            need(all(any(cid.startswith(c) for cid in own_ids) for c in consumers), 'FOREIGN_VOLUME_CONSUMER')
        for network in inventory['network']:
            need(network['Driver'] == 'bridge' and set(network.get('Containers', {})) <= own_ids, 'FOREIGN_NETWORK')
        if record.get('topdown'):
            all_ids = set(self.io.run(['docker', 'ps', '-aq', '--no-trunc']).decode().split())
            need(own_ids <= all_ids and all(re.fullmatch('[a-f0-9]{64}', cid) for cid in all_ids), 'CONSUMER_INVENTORY')
            for cid in sorted(all_ids - own_ids):
                row = json.loads(self.io.run(['docker', 'inspect', '--format',
                    '{"Id":{{json .Id}},"Mounts":{{json .Mounts}}}', cid]))
                need(row.get('Id') == cid and isinstance(row.get('Mounts'), list), 'CONSUMER_INSPECT')
                for mount in row['Mounts']:
                    if mount.get('Type') == 'bind':
                        source = mount.get('Source')
                        need(isinstance(source, str) and Path(source).is_absolute(), 'CONSUMER_BIND')
                        # Alias normalization can only reject a foreign consumer, never authorize one.
                        candidate = source.removeprefix('/host_mnt') if source.startswith('/host_mnt/') else source
                        need(not fresh.topdown.overlap(Path(candidate), Path(record['custody'])), 'FOREIGN_BIND_CONSUMER')
        pins = images(record, model)
        for svc, row in by_service.items():
            need(row['Image'] == pins[svc], 'RUNTIME_IMAGE')
            need(set(row['NetworkSettings']['Networks']) == {record['project'] + '_local'}, 'RUNTIME_NETWORK')
            ports = row['HostConfig'].get('PortBindings') or {}
            need(ports == ({'443/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '443'}]} if svc == 'nginx' else {}), 'RUNTIME_PORT')
            fresh.verify_mounts(row.get('Mounts', []), model['services'][svc], model)
        if healthy:
            need(all(c['State']['Running'] and c['State'].get('Health', {}).get('Status') == 'healthy'
                     for c in by_service.values()), 'SERVICE_NOT_HEALTHY')
        if route.active(record) and not partial:
            route.runtime_aliases(record, by_service.values())
        return by_service

    def state(self, cid):
        state = checked_stop_state(json.loads(self.io.run(['docker', 'inspect', '--format', STATE, cid])))
        need(state['Id'] == cid, 'STOP_INSTANCE_CHANGED')
        return state

    def daemon(self):
        result = json.loads(self.io.run(['docker', 'info', '--format', DAEMON]))
        need(isinstance(result.get('ID'), str) and result['ID'], 'STOP_DAEMON_ID')
        timestamp_ns(result.get('SystemTime'))
        return result

    def wait(self, cid, running, clean=False, timeout=180):
        deadline = time.monotonic() + timeout
        while True:
            state = self.state(cid)
            if state['Running'] == running:
                need(not clean or (state['ExitCode'] == 0 and not state['OOMKilled']), 'UNCLEAN_DATA_STOP')
                return state
            need(time.monotonic() < deadline, 'NORMAL_STOP_TIMEOUT')
            time.sleep(0.25)

    def stopped_proof(self, record, model, journal, rows, services=STOP):
        need(not journal.get('stopFailed'), 'STOP_PREVIOUS_FAILURE')
        daemon = self.daemon()
        for svc in services:
            attempt = journal.get('stopAttempts', {}).get(svc)
            validate_stop(attempt, svc, record, model)
            need(svc in rows and rows[svc]['Id'] == attempt['before']['Id'] and
                 rows[svc]['Image'] == attempt['before']['Image'] and
                 daemon['ID'] == attempt['daemonAfter']['ID'] and
                 timestamp_ns(daemon['SystemTime']) >= timestamp_ns(attempt['daemonAfter']['SystemTime']) and
                 self.state(rows[svc]['Id']) == attempt['after'], 'STOP_INSTANCE_CHANGED')

    def stop(self, record, model, journal, journal_path, services=STOP, partial=False):
        rows = self.verify(record, model, partial=partial)
        failure = Refused('STOP_PREVIOUS_FAILURE') if journal.get('stopFailed') else None
        for svc in services:
            if svc not in rows:
                continue
            cid = rows[svc]['Id']
            attempt = journal.setdefault('stopAttempts', {}).get(svc)
            try:
                state = self.state(cid)
                need(state['Image'] == rows[svc]['Image'], 'STOP_INSTANCE_CHANGED')
                if attempt is not None:
                    validate_stop(attempt, svc, record, model)
                    need(state == attempt['after'] and cid == attempt['before']['Id'], 'STOP_INSTANCE_CHANGED')
                    continue
                need(state['Running'] is True and state['Restarting'] is False and state['Pid'] > 0 and
                     state['ExitCode'] == 0 and state['OOMKilled'] is False and state['Error'] is False and
                     state['Paused'] is False and state['Dead'] is False,
                     'STOP_BEFORE_STATE')
                timestamp_ns(state['StartedAt'])
                signal = json.loads(self.io.run(['docker', 'image', 'inspect', '--format',
                                                 '{{json .Config.StopSignal}}', rows[svc]['Image']])) or 'SIGTERM'
                need(signal in ('SIGTERM', 'SIGINT', 'TERM', 'INT'), 'UNSAFE_STOP_SIGNAL')
                daemon = self.daemon()
                need(self.state(cid) == state and timestamp_ns(state['StartedAt']) <= timestamp_ns(daemon['SystemTime']),
                     'STOP_INSTANCE_CHANGED')
                attempt = {'nonce': secrets.token_hex(16), 'binding': stop_binding(record, model),
                           'status': 'SIGNAL_PENDING', 'before': state, 'daemonBefore': daemon, 'signal': signal,
                           'command': ['docker', 'kill', '--signal=' + signal, cid]}
                journal['stopAttempts'][svc] = attempt
                journal['phase'] = 'STOPPING_' + svc
                journal.setdefault('stopped', {})[svc] = cid
                write(journal_path, journal, replace=journal_path.exists())
                # No forced-stop fallback; an unknown child result never authorizes a later exit143.
                self.io.run(attempt['command'])
                attempt['status'] = 'SIGNAL_SENT'
                write(journal_path, journal, replace=True)
                attempt['after'] = self.wait(cid, False)
                attempt['daemonAfter'] = self.daemon()
                candidate = dict(attempt, status='PROVEN')
                validate_stop(candidate, svc, record, model)
                attempt['status'] = 'PROVEN'
                write(journal_path, journal, replace=True)
            except Exception as exc:
                # Preserve the first failure while still stopping other owned services for cleanup.
                failure = failure or exc
                journal['stopFailed'] = True
                if attempt is not None:
                    attempt['status'] = 'FAILED'
                journal['phase'] = 'STOP_FAILED'
                write(journal_path, journal, replace=journal_path.exists())
        if failure is None:
            try:
                self.stopped_proof(record, model, journal, rows, services=set(services) & set(rows))
            except Exception as exc:
                failure = exc
                journal['stopFailed'] = True
        journal['phase'] = 'STOP_FAILED' if failure else 'STOPPED'
        write(journal_path, journal, replace=journal_path.exists())
        if failure:
            raise failure
        return rows

    def wait_healthy(self, record, model, services=START, timeout=180):
        end = time.monotonic() + timeout
        while True:
            rows = self.verify(record, model)
            if all(rows[s]['State']['Running'] and
                   rows[s]['State'].get('Health', {}).get('Status') == 'healthy' for s in services):
                return
            need(time.monotonic() < end, 'HEALTH_TIMEOUT')
            time.sleep(.25)

    def resume(self, bundle):
        m = self.bundle(bundle) if (Path(bundle) / 'manifest.json').exists() else None
        j = read(Path(bundle) / 'journal.json')
        source = read(Path(bundle) / 'custody/contract.json')
        model = read(Path(bundle) / 'custody/compose.json')
        original = self.verify(source, model)
        need({s: c['Id'] for s, c in original.items()} == j['originalIds'], 'ORIGINAL_IDS_CHANGED')
        # All recovery copies must be stopped before the original is allowed to regain 443.
        targets_stopped_cleanly = True
        for target in j.get('targets', []):
            t, target_compose = self.target(target)
            rows = self.verify(t['record'], target_compose, partial=True)
            need(not any(self.state(c['Id'])['Running'] for c in rows.values()), 'TARGET_STILL_RUNNING')
            try:
                need(t['phase'] == 'STOPPED_PRESERVED' and set(rows) == set(STOP), 'TARGET_STOP_NOT_ACCEPTED')
                self.stopped_proof(t['record'], target_compose, read(Path(target) / 'stop.json'), rows)
            except Exception:
                targets_stopped_cleanly = False
        def original_state(svc, cid):
            before = j.get('stopAttempts', {}).get(svc, {}).get('before')
            current = self.state(cid)
            need(svc in original and original[svc]['Id'] == cid and before is not None and
                 all(current[k] == before[k] for k in ('Id', 'Image', 'StartedAt', 'RestartCount')),
                 'ORIGINAL_RUN_CHANGED')
            return current

        # Check every original run before starting any dependency after an external change.
        for svc, cid in j.get('stopped', {}).items():
            original_state(svc, cid)
        self.io.port_free()
        for svc in START:
            cid = j.get('stopped', {}).get(svc)
            if cid and not original_state(svc, cid)['Running']:
                self.io.run(['docker', 'start', cid])
                self.wait(cid, True)
            if svc == DATA[-1]:
                self.wait_healthy(source, model, DATA)
            if svc == 'gateway-api':
                self.wait_healthy(source, model, ('gateway-api',))
        self.wait_healthy(source, model)
        self.verify(source, model, healthy=True)
        if m:
            cp = m['checkpoint']
            need(self.checkpoint(Path(source['custody']), source, cp['generalId'], cp['requestId']) == cp,
                 'ORIGINAL_CHECKPOINT_CHANGED')
            probe = self.io.user_probe(Path(source['custody']), m['identity'], cp['generalId'], cp['requestId'])
            need(probe.get('login') is True and probe.get('resolved') is True, 'ORIGINAL_USER_PROBE')
            j['originalObservation'] = {'checkpoint':cp,'user':probe,'logs':{
                s:self.io.log_summary(row['Id'],cp['requestId']) for s,row in original.items()}}
        j['phase'] = 'ORIGINAL_RESUMED'
        write(Path(bundle) / 'journal.json', j, replace=True)
        observed = [read(Path(p) / 'target.json') for p in j.get('targets', [])]
        complete = any(t.get('rollbackFrom') and (t.get('observation') or {}).get('rollback') is True for t in observed)
        return {'phase': j['phase'], 'backupComplete': bool(m),
                'fullFlowObserved': bool(m and complete and targets_stopped_cleanly and not j.get('stopFailed'))}

    def volume_command(self, record, image, volume, mode, path, incoming=False):
        need(IMAGE.fullmatch(image), 'IMAGE_ID')
        args = ['docker', 'run', '--rm', '--pull', 'never', '--network', 'none', '--read-only', '--memory', '32m',
                '--pids-limit', '32', '--label', fresh.NONCE_LABEL + '=' + record['nonce'],
                '--label', fresh.SESSION_LABEL + '=' + record['session']]
        if incoming:
            args.append('-i')
        args += ['--mount', f'type=volume,source={volume},target=/volume' + (',readonly' if not incoming else ''), image]
        args += ['tar', '-xpf' if incoming else '-cpf', '-', '-C', '/volume']
        if not incoming:
            args.append('.')
        self.io.stream(args, path, incoming=incoming)

    def backup(self, source_path, output, general_id, request_id):
        output = isolated_output(output, [source_path])
        directory, record, model = self.source(source_path)
        rows = self.verify(record, model, healthy=True)
        probe = self.io.user_probe(directory, identity(record), general_id, request_id)
        need(probe.get('login') is True and probe.get('resolved') is True and
             probe.get('generalId') == general_id and probe.get('requestId') == request_id, 'SOURCE_USER_PROBE')
        output = newdir(output)
        copy_private(directory, output / 'custody')
        newdir(output / 'data')
        j = {'schema': 1, 'phase': 'PREPARED', 'source': str(directory), 'stopped': {}, 'targets': [],
             'originalIds': {s: c['Id'] for s, c in rows.items()}}
        write(output / 'journal.json', j)
        try:
            self.stop(record, model, j, output / 'journal.json', services=STOP[:-len(DATA)])
            checkpoint = self.checkpoint(directory, record, general_id, request_id)
            self.stop(record, model, j, output / 'journal.json', services=DATA)
            self.stopped_proof(record, model, j, rows)
            write(output / 'stop-proof.json', {'stopAttempts': j['stopAttempts']})
            roots = {}
            pg = record['supportImages']['postgres:16-alpine']
            for name in VOLUMES:
                dest = output / 'data' / (name + '.tar')
                self.volume_command(record, pg, model['volumes'][name]['name'], 'backup', dest)
                roots[name] = archive_root(dest)
            pins = images(record, model)
            self.io.stream(['docker', 'image', 'save', *sorted(set(pins.values()))], output / 'images.tar')
            archive_root(output / 'images.tar')
            self.stopped_proof(record, model, j, self.verify(record, model))
            m = {'schema': 1, 'status': 'BACKUP_COMPLETE', 'source': record, 'pins': pins,
                 'identity': identity(record), 'checkpoint': checkpoint, 'volumes': roots,
                 'files': seal(output)}
            write(output / 'manifest.json', m)
            verify_bundle(output)
            return {'phase': 'BACKUP_COMPLETE', 'volumes': len(roots), 'originalStopped': True}
        except BaseException:
            j['phase'] = 'BACKUP_FAILED'
            write(output / 'journal.json', j, replace=True)
            try:
                self.resume(output)
            except BaseException:
                j['phase'] = 'RESUME_REQUIRED'
                write(output / 'journal.json', j, replace=True)
            raise

    def checkpoint(self, directory, record, gid, rid):
        need(type(gid) is int and gid > 0 and
             re.fullmatch('[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}', rid), 'CHECKPOINT_INPUT')
        query = f"""BEGIN READ ONLY;
        SELECT json_build_object('generalId',g.id,'userId',g.user_id,'nationId',g.nation_id,
          'requestId','{rid}','appliedCount',(SELECT count(*) FROM command_result WHERE world_id=160
          AND request_id='{rid}' AND terminal_status='APPLIED' AND ok=true),
          'terminalVersion',(SELECT committed_world_version FROM command_result WHERE world_id=160
          AND request_id='{rid}' AND terminal_status='APPLIED' AND ok=true ORDER BY result_seq DESC LIMIT 1),
          'logCount',(SELECT count(*) FROM log_entry WHERE world_id=160 AND general_id={gid}
          AND meta->'refs'->>'requestId'='{rid}'))
        FROM general g WHERE world_id=160 AND id={gid}; COMMIT;"""
        value = json.loads(fresh.sql(directory, record, 'game-postgres', query))
        need(value.get('generalId') == gid and value.get('appliedCount') == 1 and
             type(value.get('terminalVersion')) is int and value.get('logCount', 0) > 0, 'CHECKPOINT_REQUEST')
        return value

    def version(self, bundle, app_sha, pins, output, source_path):
        m = self.bundle(bundle)
        output = isolated_output(output, [m['source']['custody'], bundle, source_path])
        need(SHA.fullmatch(app_sha) and app_sha != m['source']['appSha'], 'DIFFERENT_VERSION_REQUIRED')
        need(set(pins) == set(fresh.SERVICES), 'SIX_VERSION_IMAGES')
        source_tree = set()
        dockerfiles = {}
        for svc, image in pins.items():
            need(IMAGE.fullmatch(image) and image != m['pins'][svc], 'DIFFERENT_VERSION_IMAGES')
            actual = fresh.inspect_image(image)
            labels = actual.get('Config', {}).get('Labels', {})
            need(actual['Id'] == image and labels.get('org.opencontainers.image.revision') == app_sha, 'VERSION_IMAGE_SOURCE')
            expected = hashlib.sha256(json.dumps(version_args(m['source'], app_sha, svc), sort_keys=True).encode()).hexdigest()
            need(labels.get('org.opensamguk.local.build-args') == expected, 'VERSION_APP_IDENTITY')
            need(re.fullmatch('[a-f0-9]{64}', labels.get('org.opensamguk.local.dockerfile', '')), 'VERSION_DOCKERFILE')
            dockerfiles[svc] = hashlib.sha256(fresh.git(source_path, 'show', app_sha + ':docker/' + svc + '.Dockerfile')).hexdigest()
            need(labels['org.opensamguk.local.dockerfile'] == dockerfiles[svc], 'VERSION_DOCKERFILE_SOURCE')
            source_tree.add(labels.get('org.opensamguk.local.source-tree'))
        need(len(source_tree) == 1 and re.fullmatch('[a-f0-9]{64}', next(iter(source_tree)) or ''), 'VERSION_SOURCE_TREE')
        need(fresh.archive_tree_hash(fresh.source_archive(source_path, app_sha)) == next(iter(source_tree)),
             'VERSION_TRACKED_SOURCE')
        selected = m['source'].get('topdown')
        if selected is not None:
            candidate_pins = fresh.topdown.source_pins(lambda path: fresh.git(source_path, 'show', app_sha + ':' + path))
            need(candidate_pins == selected['sourcePins'], 'VERSION_TOPDOWN_SOURCE')
        version_record = {'schema': 1, 'appSha': app_sha, 'images': pins,
                       'identity': m['identity'], 'sourceTreeSha256': next(iter(source_tree)), 'dockerfiles': dockerfiles}
        version_record.update({key: m['source'][key] for key in ('profile', 'startupPaused') if key in m['source']})
        if selected is not None:
            version_record['topdown'] = selected
        write(output, version_record)
        return {'phase': 'VERSION_PINNED', 'appSha': app_sha}

    def restore(self, bundle, target, version=None):
        m = self.bundle(bundle)
        source = m['source']
        target = isolated_output(target, [source['custody'], bundle])
        model = read(Path(bundle) / 'custody/compose.json')
        rows = self.verify(source, model)
        need(not any(self.state(c['Id'])['Running'] for c in rows.values()), 'ORIGINAL_MUST_BE_STOPPED')
        self.io.port_free()
        pins = dict(m['pins'])
        app_sha = source['appSha']
        if version:
            v = read(version)
            same_profile(v, source, 'VERSION_PROFILE_BINDING')
            need(v.get('topdown') == source.get('topdown'), 'VERSION_TOPDOWN_BINDING')
            need(v.get('schema') == 1 and v.get('identity') == m['identity'] and
                 v.get('appSha') != app_sha and SHA.fullmatch(v.get('appSha', '')), 'VERSION_INPUT')
            need(set(v.get('images', {})) == set(fresh.SERVICES), 'SIX_VERSION_IMAGES')
            for svc, image in v['images'].items():
                actual = fresh.inspect_image(image)
                labels = actual.get('Config', {}).get('Labels', {})
                need(IMAGE.fullmatch(image) and image != pins[svc] and actual['Id'] == image and
                     labels.get('org.opencontainers.image.revision') == v['appSha'] and
                     labels.get('org.opensamguk.local.source-tree') == v['sourceTreeSha256'] and
                     labels.get('org.opensamguk.local.dockerfile') == v['dockerfiles'][svc] and
                     labels.get('org.opensamguk.local.build-args') == hashlib.sha256(json.dumps(
                         version_args(source, v['appSha'], svc), sort_keys=True).encode()).hexdigest(), 'VERSION_IMAGE_CHANGED')
            pins.update(v['images'])
            app_sha = v['appSha']
        else:
            refs = {fresh.image_ref(source, s): m['pins'][s] for s in fresh.SERVICES}
            refs.update(source['supportImages'])
            for tag, expected in refs.items():
                current = set(self.io.run(['docker', 'image', 'ls', '--no-trunc', '--format',
                    '{{.ID}}', '--filter', 'reference=' + tag]).decode().split())
                need(current <= {expected}, 'IMAGE_IMPORT_TAG_COLLISION')
            self.io.stream(['docker', 'image', 'load'], Path(bundle) / 'images.tar', incoming=True)
        for image in pins.values():
            need(fresh.inspect_image(image)['Id'] == image, 'IMAGE_MISSING')
        target = newdir(target)
        copy_private(Path(bundle) / 'custody', target / 'runtime', public_topdown=True)
        nonce = secrets.token_hex(8)
        rec = dict(source, nonce=nonce, project='osgfr' + nonce, custody=str(target), appSha=app_sha)
        if version:
            rec['sourceTreeSha256'] = v['sourceTreeSha256']
        rec['images'] = {s: {'imageId': pins[s]} for s in fresh.SERVICES}
        rec['supportImages'] = {p: p for s, p in pins.items() if s not in fresh.SERVICES}
        transformed = target_model(model, source, target, nonce, pins)
        need(all(transformed['services'][s].get('environment') == model['services'][s].get('environment')
                 for s in model['services']), 'APP_ENV_CHANGED')
        write(target / 'compose.json', transformed)
        t = {'schema': 1, 'bundle': str(Path(bundle).absolute()), 'record': rec, 'pins': pins,
             'composeSha256': digest(target / 'compose.json'), 'phase': 'PREPARED', 'observation': None}
        if route.active(source):
            t['runtimeBinding'] = route.copied_binding(target / 'runtime',
                Path(bundle) / 'custody', source, fresh)
        write(target / 'target.json', t)
        j = read(Path(bundle) / 'journal.json')
        j['targets'].append(str(target))
        write(Path(bundle) / 'journal.json', j, replace=True)
        fresh.assert_owned(rec, fresh.inventory(rec), empty=True)
        for name, spec in transformed['volumes'].items():
            self.io.run(['docker', 'volume', 'create', '--label', fresh.NONCE_LABEL + '=' + nonce,
                         '--label', fresh.SESSION_LABEL + '=' + rec['session'], '--label',
                         fresh.PROJECT_LABEL + '=' + rec['project'], spec['name']])
            empty = self.io.run(['docker', 'run', '--rm', '--pull', 'never', '--network', 'none', '--read-only',
                '--mount', 'type=volume,source=' + spec['name'] + ',target=/volume,readonly',
                source['supportImages']['postgres:16-alpine'], 'find', '/volume', '-mindepth', '1', '-print', '-quit'])
            need(not empty.strip(), 'TARGET_VOLUME_NOT_EMPTY')
            self.volume_command(rec, source['supportImages']['postgres:16-alpine'], spec['name'],
                                'restore', Path(bundle) / 'data' / (name + '.tar'), incoming=True)
            path = target / (name + '-restored.tar')
            self.volume_command(rec, source['supportImages']['postgres:16-alpine'], spec['name'], 'verify', path)
            need(archive_root(path) == m['volumes'][name], 'RESTORE_CONTENT_MISMATCH')
        t['phase'] = 'DATA_VERIFIED'
        write(target / 'target.json', t, replace=True)
        self.io.run(['docker', 'compose', '--project-name', rec['project'], '--env-file', '/dev/null',
            '--project-directory', str(target), '-f', str(target / 'compose.json'), 'up', '-d',
            '--no-build', '--pull', 'never', '--wait', '--wait-timeout', '600'], timeout=660)
        self.verify(rec, transformed, healthy=True)
        profile_smoke(target, rec)
        t['phase'] = 'RUNNING_NOT_ACCEPTED'
        write(target / 'target.json', t, replace=True)
        return {'phase': t['phase'], 'appSha': app_sha, 'resourceNonce': nonce}

    def observe(self, target):
        target = private(target, True)
        t, target_compose = self.target(target)
        need(t['phase'] == 'RUNNING_NOT_ACCEPTED', 'TARGET_OBSERVATION_PHASE')
        m = self.bundle(t['bundle'])
        need(digest(target / 'compose.json') == t['composeSha256'], 'TARGET_CONFIG_CHANGED')
        rows = self.verify(t['record'], target_compose, healthy=True)
        sid = m['identity']['serverId']
        world = fresh.sql(target, t['record'], 'game-postgres',
            "BEGIN READ ONLY; SELECT string_agg(id::text,',' ORDER BY id) FROM world_state; COMMIT;")
        registry = fresh.sql(target, t['record'], 'gateway-postgres',
            "BEGIN READ ONLY; SELECT count(*) FROM game_server s JOIN game_server_publication p USING(server_id) "
            f"WHERE s.server_id='{sid}' AND s.generation=0 AND p.state='PUBLIC' AND p.revision=1; COMMIT;")
        need(world == '160' and registry == '1', 'STRICT_SMOKE_IDENTITY')
        profile_smoke(target, t['record'])
        fresh.topdown.smoke(t['record'], lambda path: self.io.run([
            'docker', 'exec', rows['game-api']['Id'], 'curl', '-fsS', '--max-time', '15',
            'http://localhost:8081' + path]))
        before = m['checkpoint']
        after = self.checkpoint(target, t['record'], before['generalId'], before['requestId'])
        need(after == before, 'CHECKPOINT_CHANGED')
        probe = self.io.user_probe(target / 'runtime', m['identity'], before['generalId'], before['requestId'])
        need(probe.get('login') is True and probe.get('resolved') is True and
             probe.get('generalId') == before['generalId'] and probe.get('requestId') == before['requestId'], 'USER_PROBE')
        # No raw logs/auth bodies are returned; CLI captures only private stderr/stdout.
        t['observation'] = {'phase': 'USER_OBSERVED', 'appSha': t['record']['appSha'],
                            'checkpoint': after, 'user': probe, 'images': t['pins'],
                            'logs':{s:self.io.log_summary(row['Id'],before['requestId']) for s,row in rows.items()}}
        if t.get('rollbackFrom'):
            b = read(Path(t['rollbackFrom']) / 'target.json')
            need(b['phase'] == 'STOPPED_PRESERVED' and b.get('observation') and
                 b['record']['appSha'] != t['record']['appSha'] == m['source']['appSha'], 'ROLLBACK_VERSION_CHAIN')
            t['observation']['rollback'] = True
        t['phase'] = 'USER_OBSERVED'
        write(target / 'target.json', t, replace=True)
        return {'phase': t['phase'], 'appSha': t['record']['appSha'], 'appliedCount': after['appliedCount']}

    def stop_target(self, target):
        target = private(target, True)
        t, target_compose = self.target(target)
        need(digest(target / 'compose.json') == t['composeSha256'], 'TARGET_CONFIG_CHANGED')
        journal_path = target / 'stop.json'
        journal = read(journal_path) if journal_path.exists() else {}
        rows = self.verify(t['record'], target_compose, partial=True)
        need(all(s in rows and rows[s]['Id'] == cid for s, cid in journal.get('stopped', {}).items()), 'TARGET_IDS_CHANGED')
        try:
            self.stop(t['record'], target_compose, journal, journal_path, partial=True)
        except BaseException:
            t['phase'] = 'STOP_FAILED_PRESERVED'
            write(target / 'target.json', t, replace=True)
            raise
        t['phase'] = 'STOPPED_PRESERVED' if set(rows) == set(STOP) else 'STOPPED_PARTIAL_PRESERVED'
        write(target / 'target.json', t, replace=True)
        return {'phase': t['phase']}

    def rollback(self, bundle, prior_target, target):
        m = self.bundle(bundle)
        target = isolated_output(target, [m['source']['custody'], bundle, prior_target])
        b, b_model = self.target(prior_target)
        need(b['bundle'] == str(Path(bundle).absolute()) and b['observation'] is not None and
             b['record']['appSha'] != m['source']['appSha'] and
             b['observation']['appSha'] == b['record']['appSha'] and
             b['phase'] == 'STOPPED_PRESERVED', 'B_NOT_OBSERVED_AND_STOPPED')
        rows = self.verify(b['record'], b_model)
        need(b['observation']['images'] == b['pins'] and
             all(b['pins'][s] != m['pins'][s] and fresh.inspect_image(b['pins'][s])['Config']['Labels'].get(
                 'org.opencontainers.image.revision') == b['record']['appSha'] for s in fresh.SERVICES), 'B_VERSION_NOT_PROVEN')
        need(not any(self.state(c['Id'])['Running'] for c in rows.values()), 'B_STILL_RUNNING')
        self.stopped_proof(b['record'], b_model, read(Path(prior_target) / 'stop.json'), rows)
        result = self.restore(bundle, target)
        t = read(Path(target) / 'target.json')
        t['rollbackFrom'] = str(Path(prior_target).absolute())
        write(Path(target) / 'target.json', t, replace=True)
        return result


def authorize_inputs(a, token):
    for name in ('source_custody', 'bundle', 'target', 'logs', 'output', 'from_target', 'source', 'version', 'meta', 'handoff'):
        if getattr(a, name, None) is not None:
            setattr(a, name, canonical_path(getattr(a, name)))
    bundle = getattr(a, 'bundle', None)
    if a.action in ('observe', 'stop-target'):
        bundle = read(a.target / 'target.json')['bundle']
    if bundle and a.action != 'backup':
        source = read(Path(bundle) / 'custody/contract.json')
        need(source['custody'] == str(a.source_custody.absolute()) and
             digest(Path(bundle) / 'custody/contract.json') == token['sourceContractSha256'], 'HANDOFF_BUNDLE')
    protected = [a.source_custody]
    outputs = [a.logs]
    if a.action == 'backup': outputs.append(a.bundle)
    elif bundle: protected.append(bundle)
    if a.action in ('restore', 'rollback'): outputs.append(a.target)
    if a.action in ('observe', 'stop-target'): protected.append(a.target)
    if a.action == 'rollback': protected.append(a.from_target)
    if a.action == 'pin-version':
        outputs.append(a.output)
        protected.append(a.source)
    for path in outputs:
        isolated_output(path, protected)
    need(not any(overlaps(a, b) for i, a in enumerate(outputs) for b in outputs[i+1:]),
         'OUTPUTS_OVERLAP')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--handoff', required=True, type=Path)
    parser.add_argument('--source-custody', required=True, type=Path)
    parser.add_argument('--meta', required=True, type=Path)
    parser.add_argument('--logs', required=True, type=Path)
    sub = parser.add_subparsers(dest='action', required=True)
    p = sub.add_parser('backup'); p.add_argument('--bundle', required=True, type=Path)
    p.add_argument('--general-id', required=True, type=int); p.add_argument('--request-id', required=True)
    p = sub.add_parser('pin-version'); p.add_argument('--bundle', required=True, type=Path)
    p.add_argument('--app-sha', required=True); p.add_argument('--image', action='append', default=[])
    p.add_argument('--source', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    p = sub.add_parser('restore'); p.add_argument('--bundle', required=True, type=Path)
    p.add_argument('--target', required=True, type=Path); p.add_argument('--version', type=Path)
    for action in ('observe', 'stop-target'):
        p = sub.add_parser(action); p.add_argument('--target', required=True, type=Path)
    p = sub.add_parser('rollback'); p.add_argument('--bundle', required=True, type=Path)
    p.add_argument('--from-target', required=True, type=Path); p.add_argument('--target', required=True, type=Path)
    p = sub.add_parser('resume-original'); p.add_argument('--bundle', required=True, type=Path)
    a = parser.parse_args()
    try:
        token = permission(a.handoff, a.source_custody)
        authorize_inputs(a, token)
        logs = newdir(a.logs)
        io = LocalIO(logs)
        common = Path(fresh.git(ROOT, 'rev-parse', '--git-common-dir').decode().strip())
        if not common.is_absolute():
            common = ROOT / common
        need(os.path.samefile(common, a.meta / 'projects/opensamguk-docker/.git'), 'META_REPOSITORY_MISMATCH')
        io.local()
        with heavy(a.meta, token['ownerSession'], datetime.fromisoformat(token['expiresAt'].replace('Z', '+00:00'))):
            r = Recovery(io)
            if a.action == 'backup':
                result = r.backup(a.source_custody, a.bundle, a.general_id, a.request_id)
            elif a.action == 'pin-version':
                pins = dict(value.split('=', 1) for value in a.image)
                need(len(pins) == len(a.image), 'DUPLICATE_IMAGE')
                result = r.version(a.bundle, a.app_sha, pins, a.output, a.source)
            elif a.action == 'restore': result = r.restore(a.bundle, a.target, a.version)
            elif a.action == 'observe': result = r.observe(a.target)
            elif a.action == 'stop-target': result = r.stop_target(a.target)
            elif a.action == 'rollback': result = r.rollback(a.bundle, a.from_target, a.target)
            else: result = r.resume(a.bundle)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (Exception, KeyboardInterrupt):
        print('{"phase":"REFUSED_OR_FAILED","preserved":true}')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
