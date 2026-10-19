#!/usr/bin/env python3
"""Build and run a fresh, owned localhost stack. Never read a deployment env file."""
import argparse
import base64
import contextlib
import datetime
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.request
import ssl
import importlib.util

# Recovery callers load this harness by file path; resolve its own helper, never another checkout's module.
_topdown_spec = importlib.util.spec_from_file_location('localhost_topdown', Path(__file__).with_name('topdown_bundle.py'))
topdown = importlib.util.module_from_spec(_topdown_spec)
_topdown_spec.loader.exec_module(topdown)
_observation_spec = importlib.util.spec_from_file_location('localhost_engine_observation', Path(__file__).with_name('engine_observation.py'))
observation = importlib.util.module_from_spec(_observation_spec)
_observation_spec.loader.exec_module(observation)
_qa_spec = importlib.util.spec_from_file_location('localhost_hostinger_qa', Path(__file__).with_name('hostinger_qa.py'))
qa = importlib.util.module_from_spec(_qa_spec)
_qa_spec.loader.exec_module(qa)

ROOT = Path(__file__).resolve().parents[2]
SERVICES = ('gateway-api', 'board-api', 'game-api', 'game-engine', 'web-gateway', 'web-game')
NONCE_LABEL = 'org.opensamguk.local.nonce'
SESSION_LABEL = 'org.opensamguk.local.session'
PROJECT_LABEL = 'com.docker.compose.project'
SUPPORT_IMAGES = ('postgres:16-alpine', 'redis:7-alpine', 'nginx:1.30.5-alpine')
GIB = 1024 ** 3
ORIGIN = 'https://localhost'
TACTICAL_KEY = 'BATTLE_JOIN_TICKET_KEY_BASE64'
STARTUP_PAUSE_ENV = 'OPENSAMGUK_DAEMON_STARTUP_PAUSED'
TACTICAL_API = {'BATTLE_SESSION_ENABLED': 'true', 'BATTLE_JOIN_TICKET_ENABLED': 'true',
                'BATTLE_V3_COMMAND_INGRESS_ENABLED': 'true', 'BATTLE_V3_PROJECTION_ENABLED': 'true',
                'BATTLE_WS_ALLOWED_ORIGINS': ORIGIN}
TACTICAL_ENGINE = {'BATTLE_PIPELINE_ENABLED': 'true', 'BATTLE_PIPELINE_API_BASE_URL': 'http://game-api:8081'}
LEGACY_TACTICAL_DOCKER = 'd35b3815e4f3edea119c4eff3b9678766be756b7'
ROUTE_FILE = 'localhost-allowlist.map'
ROUTE_ORIGINAL = 'tactical-route-original-contract.json'
ROUTE_ORIGINAL_NGINX = 'tactical-route-original-nginx.conf'
ROUTE_PROOF = 'tactical-route-recovery.json'
# Inspect projections exclude Env, command arguments, health logs and volume driver options.
IMAGE_FORMAT = '{"Id":{{json .Id}},"RepoTags":{{json .RepoTags}},"Config":{"Labels":{{json (index .Config "Labels")}}}}'
CONTAINER_FORMAT = ('{"Id":{{json .Id}},"Name":{{json .Name}},"Image":{{json .Image}},'
    '"Config":{"Labels":{{json (index .Config "Labels")}}},"State":{"Running":{{json .State.Running}},'
    '"Health":{"Status":{{with index .State "Health"}}{{json .Status}}{{else}}null{{end}}}},'
    '"HostConfig":{"PortBindings":{{json .HostConfig.PortBindings}},"CgroupParent":{{json .HostConfig.CgroupParent}},'
    '"Memory":{{.HostConfig.Memory}},"MemorySwap":{{.HostConfig.MemorySwap}},"NanoCpus":{{.HostConfig.NanoCpus}}},"Mounts":{{json .Mounts}},'
    '"NetworkSettings":{"Networks":{{json .NetworkSettings.Networks}}}}')
NETWORK_FORMAT = ('{"Id":{{json .Id}},"Name":{{json .Name}},"Labels":{{json (index . "Labels")}},'
                  '"Driver":{{json .Driver}},"Containers":{{with index . "Containers"}}{{json .}}{{else}}{}{{end}}}')
VOLUME_FORMAT = '{"Name":{{json .Name}},"Labels":{{json (index . "Labels")}}}'


class Refused(RuntimeError):
    pass


qa.Refused = Refused


class ObservationNoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Refused('Public observation redirect refused')


def require(condition, message):
    if not condition:
        raise Refused(message)


def run(args, *, input=None, timeout=60, cwd=None, log_path=None):
    # Never echo argv, child output or environment: these may contain new fixtures.
    env = {k: os.environ[k] for k in ('PATH', 'HOME', 'TMPDIR', 'DOCKER_HOST',
           'DOCKER_CONTEXT', 'DOCKER_CONFIG', 'SSH_AUTH_SOCK') if k in os.environ}
    env.update(LANG='C.UTF-8', COMPOSE_DISABLE_ENV_FILE='1', NEXT_TELEMETRY_DISABLED='1')
    if args[0] == 'docker' and args[1:3] != ['context', 'inspect']:
        # DOCKER_CONTEXT overrides DOCKER_HOST; a remote daemon would violate localhost custody.
        endpoint = env.get('DOCKER_HOST') if not env.get('DOCKER_CONTEXT') else None
        if endpoint is None:
            endpoint = run(['docker', 'context', 'inspect', '--format', '{{.Endpoints.docker.Host}}']).decode().strip()
        require(endpoint.startswith('unix:///') and '\n' not in endpoint, 'Only a local Unix Docker endpoint is allowed')
    log = None
    try:
        if log_path is not None:
            log = os.fdopen(os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb')
        p = subprocess.run(args, input=input, stdout=log if log else subprocess.PIPE,
                           stderr=subprocess.STDOUT if log else subprocess.PIPE, cwd=cwd, env=env, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise Refused('Command timed out; owned resources and custody preserved') from None
    finally:
        if log is not None:
            log.close()
    require(p.returncode == 0, 'Command failed; private output suppressed, custody preserved')
    return p.stdout or b''


def git(repo, *args):
    return run(['git', '-C', str(repo), *args])


def sha(data):
    return hashlib.sha256(data).hexdigest()


def private_write(path, data, replace=False):
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if replace else os.O_EXCL) | os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(data)


def write_json(path, data, replace=False):
    private_write(path, (json.dumps(data, indent=2) + '\n').encode(), replace)


def private_path(path, directory=False):
    path = Path(path).absolute()
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'Symlink custody refused')
    mode = path.stat()
    require(mode.st_uid == os.getuid() and not mode.st_mode & 0o077, 'Custody must be private and owned')
    require(stat.S_ISDIR(mode.st_mode) if directory else stat.S_ISREG(mode.st_mode), 'Wrong custody file type')
    return path


def identity(record, read_only=False):
    profile(record)
    startup_paused(record)
    observation.selected(record)
    nonce = record.get('nonce', '')
    require(re.fullmatch('[a-f0-9]{16}', nonce), 'Invalid nonce')
    require(record.get('project') == qa.project(record) and record.get('serverId') == 'lha' + nonce,
            'Project/server identity mismatch')
    require(record.get('origin') == qa.origin(record) and record.get('worldId') == 160 and record.get('generation') == 0,
            'Local identity mismatch')
    require(re.fullmatch('[a-f0-9]{40}', record.get('appSha', '')) and
            re.fullmatch('[a-f0-9]{40}', record.get('dockerSha', '')), 'Full source SHA required')
    require(re.fullmatch('[a-f0-9-]{36}', record.get('session', '')), 'Invalid writer session')
    require(read_only or record.get('session') == os.environ.get('OPENSAMGUK_TASK_OWNER_SESSION'), 'Writer session mismatch')


def load(directory, read_only=False):
    directory = private_path(directory, True)
    record = json.loads(private_path(directory / 'contract.json').read_bytes())
    identity(record, read_only)
    require(record['custody'] == str(directory), 'Custody path mismatch')
    return directory, record


def labels(record):
    return {NONCE_LABEL: record['nonce'], SESSION_LABEL: record['session']}


def image_ref(record, service):
    return f"opensamguk-local/{service}:{record['appSha']}-{record['nonce']}"


def profile(record):
    value = record.get('profile', 'standard')
    require(value in ('standard', 'tactical'), 'Unknown local fixture profile')
    return value


def battle_route_bytes(record):
    identity(record, read_only=True)
    return ('"' + record['serverId'] + '" "http://s' + record['serverId'] + '-game-api:8081";\n').encode()


def battle_route_binding(record):
    return {'schema': 1, 'file': ROUTE_FILE, 'sha256': sha(battle_route_bytes(record))}


def verify_battle_route(directory, record, legacy=False):
    require({key for key in record if 'battlerout' in re.sub('[^a-z]', '', key.lower())} <= {'battleRouting'},
            'Unknown battle routing contract key')
    route = private_path(directory / 'battle-ws', True)
    files = list(route.iterdir())
    if profile(record) == 'standard' or legacy:
        require(not legacy or (record.get('dockerSha') == LEGACY_TACTICAL_DOCKER and
                profile(record) == 'tactical' and record.get('status') == 'RUNNING' and
                not any(key.startswith('runtimeVerifier') for key in record)), 'Invalid legacy route admission')
        require('battleRouting' not in record and not files, 'Unexpected battle routing')
        return
    require(record.get('battleRouting') == battle_route_binding(record) and
            {path.name for path in files} == {ROUTE_FILE}, 'Tactical battle routing binding differs')
    path = private_path(route / ROUTE_FILE)
    require(path.stat().st_nlink == 1 and path.read_bytes() == battle_route_bytes(record),
            'Tactical battle routing bytes or links differ')
    if 'runtimeVerifierHarnessSha256' in record:
        verify_route_recovery_binding(directory, record)


def route_verifier_identity(expected_head):
    require(re.fullmatch('[a-f0-9]{40}', expected_head or '') and
            git(ROOT, 'rev-parse', 'HEAD').decode().strip() == expected_head, 'Exact route verifier head required')
    require(not git(ROOT, 'status', '--porcelain', '--untracked-files=all').strip() and
            not git(ROOT, 'ls-files', '--others', '--ignored', '--exclude-standard').strip(),
            'Route verifier must be clean')
    source = git(ROOT, 'show', expected_head + ':tools/localhost-acceptance/harness.py')
    require(source == Path(__file__).read_bytes(), 'Route verifier source differs')
    return {'runtimeVerifierHead': expected_head, 'runtimeVerifierPath': str(ROOT),
            'runtimeVerifierHarnessSha256': sha(source)}


def route_nginx_transition(record, revision):
    original = git(ROOT, 'show', record['dockerSha'] + ':infra/nginx/nginx.conf')
    pattern = b'location ~ "^/api/battle-ws/'
    block = b'        location /api/battle-ws/ {\n            access_log off;\n            return 404;\n        }\n'
    alias = b'        location = /ws/battles {\n            access_log off;\n            return 404;\n        }\n        location /ws/battles/ {\n            access_log off;\n            return 404;\n        }\n'
    require(original.count(pattern) == 2 and original.count(block) == 2, 'Original nginx route shape differs')
    expected = original.replace(pattern, b'location ~ "^/(?:api/battle-ws|ws/battles)/').replace(block, block + alias)
    current = git(ROOT, 'show', revision + ':infra/nginx/nginx.conf')
    require(current == expected and sha(original) == record['nginxSha256'],
            'Only the exact canonical two-block battle alias transition is allowed')
    return original, current


def nginx_file_identity(path):
    mode = private_path(path).stat()
    require(mode.st_nlink == 1 and stat.S_IMODE(mode.st_mode) == 0o600, 'Private single-link nginx file required')
    return {'device': mode.st_dev, 'inode': mode.st_ino}


def write_bound_nginx(path, expected, replacement, identity):
    require(nginx_file_identity(path) == identity, 'Bound nginx inode changed')
    fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
    with os.fdopen(fd, 'r+b') as stream:
        mode = os.fstat(stream.fileno())
        require({'device': mode.st_dev, 'inode': mode.st_ino} == identity and mode.st_uid == os.getuid() and
                stat.S_ISREG(mode.st_mode) and stat.S_IMODE(mode.st_mode) == 0o600 and mode.st_nlink == 1,
                'Opened nginx file identity or ownership differs')
        require(stream.read() == expected, 'Bound nginx bytes changed before write')
        try:
            stream.seek(0); stream.write(replacement); stream.truncate(); stream.flush(); os.fsync(stream.fileno())
        except BaseException:
            stream.seek(0); stream.write(expected); stream.truncate(); stream.flush(); os.fsync(stream.fileno())
            raise
    require(nginx_file_identity(path) == identity and path.read_bytes() == replacement,
            'Bound nginx in-place write differs')


def verify_route_recovery_binding(directory, record):
    proof = json.loads(private_path(directory / ROUTE_PROOF).read_bytes())
    original_bytes = private_path(directory / ROUTE_ORIGINAL).read_bytes()
    original = json.loads(original_bytes)
    require(original.get('dockerSha') == LEGACY_TACTICAL_DOCKER and
            original.get('profile') == 'tactical' and original.get('status') == 'RUNNING' and
            'battleRouting' not in original and 'runtimeVerifierHarnessSha256' not in original,
            'Original tactical failure binding differs')
    verifier = route_verifier_identity(record.get('runtimeVerifierHead'))
    old_nginx, new_nginx = route_nginx_transition(original, verifier['runtimeVerifierHead'])
    require(private_path(directory / ROUTE_ORIGINAL_NGINX).read_bytes() == old_nginx,
            'Original nginx failure config differs')
    config = {'runtimeNginxSha256': sha(new_nginx),
              'runtimeNginxFileIdentity': nginx_file_identity(directory / 'nginx.conf')}
    expected = {**original, **verifier, **config, 'battleRouting': battle_route_binding(original)}
    require(record.get('status') in ('RUNNING', 'SMOKE_PASSED') and
            {**record, 'status': 'RUNNING'} == expected and
            proof == {'schema': 1, 'originalContractSha256': sha(original_bytes), **verifier,
                      **config, 'battleRouting': expected['battleRouting']}, 'Recovered contract differs from original inputs')


def tactical_key(value):
    require(isinstance(value, str), 'Dedicated tactical signing key is missing')
    try:
        decoded = base64.b64decode(value, validate=True)
    except ValueError:
        raise Refused('Dedicated tactical signing key is invalid') from None
    require(len(decoded) == 32 and base64.b64encode(decoded).decode() == value,
            'Dedicated tactical signing key is invalid')
    return value


def startup_pause_key(name):
    return 'startuppaus' in re.sub(r'[^a-z0-9]', '', name.lower())


def startup_paused(record):
    require({key for key in record if startup_pause_key(key)} <= {'startupPaused'},
            'Unknown startup pause contract key')
    value = record.get('startupPaused', False)
    require(type(value) is bool, 'Startup pause contract must be boolean')
    return value


def profile_fixtures(record, fixtures):
    if profile(record) == 'standard':
        return fixtures
    require(TACTICAL_KEY not in fixtures, 'Fresh tactical fixture key required')
    return {**fixtures, TACTICAL_KEY: base64.b64encode(secrets.token_bytes(32)).decode()}


def build_args(record, service):
    if service == 'web-gateway':
        return {'NEXT_PUBLIC_GAME_URL': qa.origin(record) + '/game/' + record['serverId'],
                'NEXT_PUBLIC_TOPDOWN_SCREENS': '1'}
    if service == 'web-game':
        return {'NEXT_PUBLIC_GATEWAY_URL': qa.origin(record), 'GATEWAY_WEB_URL': 'http://web-gateway:3000',
                'ASSET_PREFIX': '/game', 'NEXT_PUBLIC_TOPDOWN_SCREENS': '1'}
    return {'IMAGE_TAG': record['appSha']}


def registry(record):
    sid = record['serverId']
    return [{'id': sid, 'name': 'Local acceptance', 'generation': 0,
             'gameUrl': qa.origin(record) + '/game/' + sid, 'gameApiUrl': f'http://s{sid}-game-api:8081',
             'gameEngineUrl': f'http://s{sid}-game-engine:8082',
             'deployProject': 'opensamguk-s' + sid, 'scenarioCode': 'scenario_3190'}]


def substitute(value, values):
    if isinstance(value, dict):
        return {k: substitute(v, values) for k, v in value.items()}
    if isinstance(value, list):
        return [substitute(v, values) for v in value]
    if isinstance(value, str):
        value = re.sub(r'@([A-Za-z0-9_-]+)@', lambda m: values[m[1]], value)
        require('@' not in value and '${' not in value, 'Unresolved compose input')
    return value


def model_for(record, fixtures):
    paused = startup_paused(record)
    values = dict(fixtures)
    values.update(CUSTODY=record['custody'], PROJECT=record['project'], NONCE=record['nonce'],
                  SESSION=record['session'], SERVER_ID=record['serverId'],
                  REGISTRY=json.dumps(registry(record), separators=(',', ':')))
    values.update({'IMAGE_' + s: image_ref(record, s) for s in SERVICES})
    model = substitute(json.loads((ROOT / 'docker-compose.localhost-acceptance.yml').read_bytes()), values)
    if profile(record) == 'tactical':
        key = tactical_key(fixtures.get(TACTICAL_KEY))
        require(key not in [value for name, value in fixtures.items() if name != TACTICAL_KEY],
                'Dedicated tactical signing key must not be reused')
        model['services']['game-api']['environment'].update({**TACTICAL_API, 'BATTLE_WS_ALLOWED_ORIGINS': qa.origin(record), TACTICAL_KEY: key})
        model['services']['game-engine']['environment'].update(TACTICAL_ENGINE)
    map_env, map_mounts = topdown.settings(record)
    model['services']['game-api']['environment'].update(map_env)
    if map_mounts:
        model['services']['game-api']['volumes'] = map_mounts
    if paused:
        model['services']['game-engine']['environment'][STARTUP_PAUSE_ENV] = 'true'
    model['services']['game-api']['environment'].update(observation.environment(record))
    qa.apply(model, record)
    validate_model(model, record)
    return model


def validate_model(model, record):
    qa.validate(model, record)
    expected_services = set(SERVICES) | {'gateway-postgres', 'game-postgres', 'gateway-redis', 'game-redis', 'nginx'}
    require(model.get('name') == record['project'] and set(model.get('services', {})) == expected_services,
            'Unexpected project or service')
    require(set(model.get('networks', {})) == {'local'} and
            set(model.get('volumes', {})) == {'gateway-pgdata', 'game-pgdata', 'gateway-redisdata', 'game-redisdata', 'profile-icons'},
            'Unexpected network or volume')
    for kind in ('networks', 'volumes'):
        for name, spec in model[kind].items():
            require(set(spec) <= {'name', 'labels', 'driver', 'ipam'} and not spec.get('external') and
                    spec.get('name') == record['project'] + '_' + name and
                    spec.get('labels') == labels(record), 'Foreign network or volume')
            require(spec.get('driver', 'bridge' if kind == 'networks' else 'local') ==
                    ('bridge' if kind == 'networks' else 'local'), 'Foreign resource driver')
    allowed_binds = {'/etc/nginx/nginx.conf': 'nginx.conf', '/etc/nginx/certs': 'certs', '/etc/nginx/battle-ws': 'battle-ws'}
    map_env, map_mounts = topdown.settings(record)
    require(model['services']['game-api'].get('volumes', []) == map_mounts, 'Topdown mount differs from explicit pin')
    require(model['services']['game-api'].get('networks', {}).get('local', {}).get('aliases') ==
            ['s' + record['serverId'] + '-game-api'], 'Owned game API alias differs')
    for name, svc in model['services'].items():
        pause_env = {key: value for key, value in svc.get('environment', {}).items() if startup_pause_key(key)}
        require(pause_env == ({STARTUP_PAUSE_ENV: 'true'} if name == 'game-engine' and startup_paused(record) else {}),
                'Startup pause environment differs from its contract or service')
        require({k: v for k, v in svc.get('environment', {}).items() if k.startswith('TOPDOWN_')} ==
                (map_env if name == 'game-api' else {}), 'Topdown environment differs from explicit pin')
        require(not set(svc) & {'build', 'container_name', 'privileged', 'network_mode', 'pid', 'ipc', 'devices',
                                'volumes_from', 'env_file', 'cap_add', 'extends', 'configs', 'secrets', 'external_links'},
                'Unsafe service option')
        require(svc.get('labels') == labels(record) and set(svc.get('networks', {})) == {'local'},
                'Service ownership/network mismatch')
        require(svc.get('ports', []) == ([{'target': 443, 'published': str(qa.port(record)), 'host_ip': '127.0.0.1', 'protocol': 'tcp'}]
                if name == 'nginx' else []), 'Only loopback TLS publish is allowed')
        require(svc.get('image') == (image_ref(record, name) if name in SERVICES else
                'nginx:1.30.5-alpine' if name == 'nginx' else
                'postgres:16-alpine' if name.endswith('postgres') else 'redis:7-alpine'), 'Unexpected image')
        for mount in svc.get('volumes', []):
            if mount['type'] == 'bind':
                target = mount.get('target')
                require((name == 'nginx' and target in allowed_binds and mount.get('read_only') is True and
                         mount['source'] == record['custody'] + '/' + allowed_binds[target]) or
                        (name == 'game-api' and map_mounts and mount == map_mounts[0]), 'Foreign host bind')
            else:
                require(mount['type'] == 'volume' and mount['source'] in model['volumes'], 'Foreign volume mount')
    require('JWT_PRIVATE_KEY' not in model['services']['game-api']['environment'] and
            'JWT_PRIVATE_KEY' not in model['services']['board-api']['environment'], 'Private key escaped issuer')
    validate_profile_model(model, record)
    observation.validate_model(model, record)


def validate_profile_model(model, record):
    tactical = profile(record) == 'tactical'
    reserved = set(TACTICAL_API) | set(TACTICAL_ENGINE) | {TACTICAL_KEY}
    for service, spec in model['services'].items():
        allowed = (set(TACTICAL_API) | {TACTICAL_KEY} if service == 'game-api' else
                   set(TACTICAL_ENGINE) if service == 'game-engine' else set()) if tactical else set()
        require(not ((reserved & set(spec.get('environment', {}))) - allowed),
                'Tactical configuration escaped its profile or service')
    if not tactical:
        return
    api = model['services']['game-api']['environment']
    engine = model['services']['game-engine']['environment']
    require(all(api.get(key) == value for key, value in {**TACTICAL_API, 'BATTLE_WS_ALLOWED_ORIGINS': qa.origin(record)}.items()) and
            all(engine.get(key) == value for key, value in TACTICAL_ENGINE.items()),
            'Tactical runtime configuration differs from its contract')
    key = tactical_key(api.get(TACTICAL_KEY))
    require(api.get('SERVER_ID') == record['serverId'] and
            api.get('OPENSAMGUK_WORLD_ID') == engine.get('OPENSAMGUK_WORLD_ID') == str(record['worldId']),
            'Tactical server or world binding differs')
    require(sum(value == key for spec in model['services'].values()
                for value in spec.get('environment', {}).values()) == 1,
            'Dedicated tactical signing key must stay in game-api')


def inventory(record):
    """Discover by either name or label. Names alone never authorize reuse/deletion."""
    result = {}
    for kind, listing, inspection in [('container', ['ps', '-aq'], ['inspect']),
            ('network', ['network', 'ls', '-q'], ['network', 'inspect']),
            ('volume', ['volume', 'ls', '-q'], ['volume', 'inspect'])]:
        ids = set()
        for filt in (f'label={PROJECT_LABEL}={record["project"]}',
                     f'label={NONCE_LABEL}={record["nonce"]}', f'name={record["project"]}'):
            ids.update(run(['docker', *listing, '--filter', filt]).decode().split())
        rows = []
        for rid in sorted(ids):
            projection = {'container': CONTAINER_FORMAT, 'network': NETWORK_FORMAT, 'volume': VOLUME_FORMAT}[kind]
            row = json.loads(run(['docker', *inspection, '--format', projection, rid]))
            rows.append(row)
        result[kind] = rows
    return result


def assert_owned(record, resources, empty=False):
    for kind, rows in resources.items():
        for row in rows:
            own = row.get('Config', {}).get('Labels', {}) if kind == 'container' else row.get('Labels', {})
            name = row.get('Name', '').lstrip('/')
            require(own and all(own.get(k) == v for k, v in {**labels(record), PROJECT_LABEL: record['project']}.items())
                    and name.startswith(record['project'] + ('-' if kind == 'container' else '_')),
                    'Foreign resource found; preserved')
    require(not empty or not any(resources.values()), 'Project/nonce already exists; fresh resources required')


def port_free(record=None):
    if record is not None and qa.selected(record):
        return qa.free_port()
    with socket.socket() as sock:
        try:
            sock.bind(('127.0.0.1', 443))
        except OSError as error:
            if error.errno != errno.EACCES:
                raise Refused('Loopback 443 unavailable; no port/origin substitution') from None
            # macOS nonroot bind is denied even when Desktop's privileged port mapper can publish.
            # A refused TCP connection rules out a listener; Docker's bind is still authoritative.
            with socket.socket() as probe:
                probe.settimeout(2)
                require(probe.connect_ex(('127.0.0.1', 443)) == errno.ECONNREFUSED,
                        'Loopback 443 listener or uncertain port state; preserved')


def resource_gate(directory, phase, record=None):
    require(phase in ('build', 'startup', 'gateway-repair'), 'Unknown resource phase')
    minimum = {'build': 12, 'startup': 8, 'gateway-repair': 8}[phase]
    require(shutil.disk_usage(directory).free >= minimum * GIB,
            f'At least {minimum} GiB free disk required for {phase}')
    if record is not None and qa.selected(record):
        return qa.admission(record, 'build' if phase == 'build' else 'startup')
    info = json.loads(run(['docker', 'info', '--format', '{"NCPU":{{json .NCPU}},"MemTotal":{{json .MemTotal}}}'], timeout=30))
    require(info['NCPU'] >= 2 and info['MemTotal'] >= 6 * GIB, 'Docker needs 2 CPUs and 6 GiB memory')
    # Account for other running stacks without reading their environments or logs.
    stats = run(['docker', 'stats', '--no-stream', '--format', '{{json .}}'], timeout=30).decode().splitlines()
    used = 0
    for line in stats:
        usage = json.loads(line)['MemUsage'].split('/')[0].strip()
        match = re.fullmatch(r'([0-9.]+)([KMGT]?i?B)', usage)
        require(match is not None, 'Cannot assess Docker memory')
        units = {'B': 1, 'kB': 1000, 'KB': 1000, 'MB': 1000**2, 'GB': 1000**3,
                 'KiB': 1024, 'MiB': 1024**2, 'GiB': GIB, 'TiB': 1024**4}
        used += float(match[1]) * units[match[2]]
    available_minimum = 768 * 1024**2 if phase == 'gateway-repair' else 6 * GIB
    require(info['MemTotal'] - used >= available_minimum, 'Insufficient available Docker memory for phase')
    # Match the managed QA bound in app tools/qa/local-stack.py; VM capacity is checked separately.
    require(os.getloadavg()[1] <= 400, 'Host load5 exceeds the managed QA limit of 400')


@contextlib.contextmanager
def heavy(meta, record, phase):
    require(phase in ('build', 'startup', 'gateway-repair', 'route-repair', 'cleanup'), 'Unknown resource phase')
    if qa.selected(record):
        with qa.lock('host-heavy.lock'):
            if phase not in ('cleanup', 'route-repair'):
                resource_gate(record['custody'], phase, record)
            yield
        return
    lock = Path(meta).resolve() / '.locks/heavy-run'
    require((Path(meta) / 'bin/start-task').is_file(), 'Managed meta root required')
    lock.parent.mkdir(exist_ok=True)
    nonce = secrets.token_hex(16)
    while True:
        try:
            lock.mkdir(mode=0o700)
            break
        except FileExistsError:
            print('Waiting for shared heavy-run owner', flush=True)
            time.sleep(10)
    owner = lock / 'owner'
    marker = f"LHA {nonce} driver-pid={os.getpid()} session={record['session']}\n"
    try:
        private_write(owner, marker.encode())
        if phase == 'route-repair':
            # A reload admits no container or image workload, like resume-startup.
            resume_capacity()
        elif phase != 'cleanup':
            resource_gate(record['custody'], phase)
        yield
    finally:
        if owner.is_file() and not owner.is_symlink() and owner.read_text() == marker:
            owner.unlink()
            lock.rmdir()


def source_archive(repo, revision):
    require(re.fullmatch('[a-f0-9]{40}', revision), 'Exact full SHA required')
    # Inspect names/status only, never an untracked .env or credential file.
    require(git(repo, 'rev-parse', 'HEAD').decode().strip() == revision, 'Source HEAD mismatch')
    require(not git(repo, 'status', '--porcelain', '--untracked-files=all').strip(), 'Clean source required')
    require(not git(repo, 'ls-files', '--others', '--ignored', '--exclude-standard').strip(),
            'Ignored files present; use a fresh clean source checkout')
    return git(repo, 'archive', '--format=tar', revision)


def checked_members(tar):
    members = tar.getmembers()
    for member in members:
        path = Path(member.name)
        require(not path.is_absolute() and '..' not in path.parts and (member.isfile() or member.isdir()),
                'Unsafe source archive member')
        require(not any(p == '.env' or (p.startswith('.env.') and not p.endswith(('example', 'sample', 'template')))
                        or p.endswith(('.pem', '.key', '.p12', '.pfx')) for p in path.parts),
                'Credential-like tracked source refused')
    return members


def archive_tree_hash(archive):
    digest = hashlib.sha256()
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        for member in sorted(checked_members(tar), key=lambda m: Path(m.name).parts):
            if member.isfile():
                digest.update(member.name.encode() + b'\0')
                # tarfile's data filter strips group/other write bits and retains tracked executable mode.
                digest.update(str(member.mode & 0o755).encode() + b'\0')
                digest.update(hashlib.sha256(tar.extractfile(member).read()).digest())
    return digest.hexdigest()


def export_path(directory):
    directory = Path(directory)
    require('..' not in directory.parts, 'Source export traversal refused')
    directory = directory.absolute()
    require(not any(p.is_symlink() for p in (directory, *directory.parents)),
            'Source export symlink refused')
    private_path(directory.parent, True)
    return directory


def export_directories(directory):
    directory = export_path(directory)
    root = directory.lstat()
    require(stat.S_ISDIR(root.st_mode) and root.st_uid == os.getuid(), 'Foreign source export root')
    directories = [(directory, root)]

    def inaccessible(_error):
        raise Refused('Source export cannot be inspected')

    for parent, names, files in os.walk(directory, followlinks=False, onerror=inaccessible):
        for name in names + files:
            path = Path(parent) / name
            info = path.lstat()
            require(info.st_uid == os.getuid() and
                    (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)),
                    'Source export link, special file or foreign owner refused')
            if stat.S_ISDIR(info.st_mode):
                directories.append((path, info))
    return directories


def normalize_export_directories(directory):
    # Validate the whole public tree before chmod; custody and tracked files stay private/unchanged.
    for path, before in export_directories(directory):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            current = os.fstat(fd)
            require((current.st_dev, current.st_ino) == (before.st_dev, before.st_ino),
                    'Source export directory changed during normalization')
            os.fchmod(fd, 0o755)
        finally:
            os.close(fd)


def unpack_archive(archive, destination):
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        checked_members(tar)
        destination = export_path(destination)
        destination.mkdir(mode=0o700)
        tar.extractall(destination, filter='data')
    normalize_export_directories(destination)


def clone_export(archive, source, destination):
    expected = archive_tree_hash(archive)
    source = export_path(source)
    export_directories(source)
    destination = export_path(destination)
    require(not destination.is_relative_to(source), 'Clone destination overlaps source')
    require(tree_hash(source) == expected, 'Clone source differs from clean Git archive')
    require(not destination.exists(), 'Clone destination already exists')
    # APFS copies share storage while later writes remain independent. Never copy runtime fixtures.
    run(['/bin/cp', '-cRp', str(source), str(destination)], timeout=300)
    export_directories(destination)
    require(tree_hash(destination) == expected, 'APFS clone bytes/modes differ from Git archive')
    normalize_export_directories(destination)


def tree_hash(directory):
    digest = hashlib.sha256()
    for path in sorted(directory.rglob('*')):
        require(not path.is_symlink(), 'Source/config symlink refused')
        if path.is_file():
            digest.update(str(path.relative_to(directory)).encode() + b'\0')
            digest.update(str(path.stat().st_mode & 0o777).encode() + b'\0')
            digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def prepare(args):
    qa_task = getattr(args, 'hostinger_qa_task', None)
    qa_option = qa.selection(qa_task) if qa_task is not None else None
    selected_profile = getattr(args, 'profile', 'standard')
    require(selected_profile in ('standard', 'tactical'), 'Unknown local fixture profile')
    selected_pause = startup_paused({'startupPaused': getattr(args, 'startup_paused', False)})
    selected_observation = getattr(args, 'engine_observation', False)
    require(type(selected_observation) is bool, 'Engine observation requires an explicit boolean selection')
    session = os.environ.get('OPENSAMGUK_TASK_OWNER_SESSION', '')
    require(re.fullmatch('[a-f0-9-]{36}', session), 'Set writer session before prepare')
    require(re.fullmatch('[a-f0-9]{40}', args.docker_sha), 'Exact Docker SHA required')
    require(git(ROOT, 'rev-parse', 'origin/main').decode().strip() == args.docker_sha,
            'Docker SHA must match fetched origin/main')
    require(git(args.source, 'rev-parse', 'origin/main').decode().strip() == args.app_sha,
            'App SHA must match fetched origin/main')
    archive = source_archive(args.source, args.app_sha)
    observation_pins = (observation.source_pins(lambda path: git(args.source, 'show', args.app_sha + ':' + path))
                        if selected_observation else None)
    nginx = git(ROOT, 'show', args.docker_sha + ':infra/nginx/nginx.conf')
    if qa_option is not None:
        require(sha(git(ROOT, 'show', args.docker_sha + ':tools/localhost-acceptance/hostinger_qa.py')) ==
                qa_option['policySha256'], 'Canonical Hostinger QA source required')
    directory = Path(args.custody).absolute()
    map_args = [getattr(args, key, None) for key in ('topdown_bundle', 'topdown_bake_id', 'topdown_manifest_sha256')]
    map_record = None
    if any(value is not None for value in map_args):
        require(all(value is not None for value in map_args), 'All three explicit topdown inputs are required')
        require(not topdown.overlap(Path(map_args[0]), directory), 'Topdown source overlaps custody')
        pins = topdown.source_pins(lambda path: git(args.source, 'show', args.app_sha + ':' + path))
        map_record = topdown.validate(*map_args, pins)
    require(not directory.exists() and not directory.is_symlink(), 'Custody already exists')
    require(not any(p.is_symlink() for p in directory.parents), 'Symlink parent refused')
    directory.mkdir(mode=0o700)
    nonce = secrets.token_hex(8)
    record = {'schema': 1, 'nonce': nonce, 'project': 'osglha' + nonce, 'serverId': 'lha' + nonce,
              'session': session, 'custody': str(directory), 'origin': ORIGIN, 'worldId': 160, 'generation': 0,
              'appSha': args.app_sha, 'dockerSha': args.docker_sha, 'nginxSha256': sha(nginx),
              'templateSha256': sha((ROOT / 'docker-compose.localhost-acceptance.yml').read_bytes()),
              'status': 'PREPARED', 'images': {}}
    if qa_option is not None:
        record.update(hostingerQA=qa_option, origin=qa.ORIGIN)
        record['project'] = qa.project(record)
        nginx = qa.nginx(record, nginx)
        record['nginxSha256'] = sha(nginx)
        write_json(directory / 'hostinger-qa.json', {'nonce': nonce, 'selection': qa_option})
    if selected_profile == 'tactical':
        record['profile'] = selected_profile
        record['battleRouting'] = battle_route_binding(record)
    if selected_pause:
        record['startupPaused'] = True
    if selected_observation:
        record['engineObservation'] = {'schema': 1, 'sourcePins': observation_pins, 'binding': None}
    if map_record:
        record['topdown'] = map_record
    write_json(directory / 'contract.json', record)
    assert_owned(record, inventory(record), empty=True)
    port_free(record)
    if args.clone_source_custody:
        previous, previous_record = load(args.clone_source_custody)
        require(previous_record['appSha'] == record['appSha'], 'Clone source SHA mismatch')
        clone_export(archive, previous / 'source', directory / 'source')
        record['sourceExport'] = 'apfs-clone-of-git-archive'
    else:
        unpack_archive(archive, directory / 'source')
        record['sourceExport'] = 'git-archive'
    record['sourceTreeSha256'] = tree_hash(directory / 'source')
    if map_record:
        topdown.copy_bundle(Path(args.topdown_bundle), directory, map_record)
    (directory / 'certs').mkdir(mode=0o700)
    (directory / 'battle-ws').mkdir(mode=0o700)
    if selected_profile == 'tactical':
        private_write(directory / 'battle-ws' / ROUTE_FILE, battle_route_bytes(record))
    private_write(directory / 'nginx.conf', nginx)
    # Only keys generated here are read, never an existing env/key/certificate.
    key = directory / 'issuer.pem'
    run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', str(key)])
    key.chmod(0o600)
    private = run(['openssl', 'pkcs8', '-topk8', '-nocrypt', '-in', str(key), '-outform', 'DER'])
    public = run(['openssl', 'pkey', '-in', str(key), '-pubout', '-outform', 'DER'])
    key.unlink()
    run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
         '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
         '-keyout', str(directory / 'certs/opensamguk.key'), '-out', str(directory / 'certs/opensamguk.crt')])
    for path in (directory / 'certs').iterdir():
        path.chmod(0o600)
    fixtures = {'DB_PASSWORD': secrets.token_urlsafe(32), 'INTERNAL_TOKEN': secrets.token_urlsafe(32),
                'DEPLOYER_TOKEN': secrets.token_urlsafe(32), 'JWT_PRIVATE_KEY': base64.b64encode(private).decode(),
                'JWT_PUBLIC_KEY': base64.b64encode(public).decode(), 'ADMIN_USERNAME': 'admin' + nonce[:8],
                'ADMIN_PASSWORD': secrets.token_urlsafe(24), 'USER_USERNAME': 'user' + nonce[:8],
                'USER_PASSWORD': secrets.token_urlsafe(24)}
    fixtures = profile_fixtures(record, fixtures)
    write_json(directory / 'runtime.json', fixtures)
    write_json(directory / 'fixture.json', {
        'admin': {'username': fixtures['ADMIN_USERNAME'], 'password': fixtures['ADMIN_PASSWORD']},
        'user': {'username': fixtures['USER_USERNAME'], 'password': fixtures['USER_PASSWORD'], 'name': '견문' + nonce[:6]}})
    write_json(directory / 'compose.json', model_for(record, fixtures))
    record['configSha256'] = sha((directory / 'compose.json').read_bytes())
    record['certsSha256'] = tree_hash(directory / 'certs')
    write_json(directory / 'contract.json', record, replace=True)
    print(str(directory))


def verify_custody_files(directory, record, *, legacy_route=False):
    if qa.selected(record):
        require(json.loads(private_path(directory / 'hostinger-qa.json').read_bytes()) ==
                {'nonce': record['nonce'], 'selection': record['hostingerQA']}, 'Fresh QA selection receipt differs')
        require(sha(git(ROOT, 'show', record['dockerSha'] + ':tools/localhost-acceptance/hostinger_qa.py')) ==
                record['hostingerQA']['policySha256'], 'Canonical QA policy source differs')
    else:
        require(not (directory / 'hostinger-qa.json').exists(), 'Existing QA custody cannot change selection')
    nginx_file_identity(directory / 'nginx.conf')
    require(sha(private_path(directory / 'nginx.conf').read_bytes()) == record.get('runtimeNginxSha256', record['nginxSha256']) and
            sha(qa.nginx(record, git(ROOT, 'show', record['dockerSha'] + ':infra/nginx/nginx.conf'))) == record['nginxSha256'],
            'Canonical nginx mismatch')
    require(('runtimeNginxSha256' not in record and 'runtimeNginxFileIdentity' not in record) or
            'runtimeVerifierHarnessSha256' in record, 'Unbound runtime nginx override')
    require(sha((ROOT / 'docker-compose.localhost-acceptance.yml').read_bytes()) == record['templateSha256'],
            'Harness template changed; prepare a fresh stack')
    require(tree_hash(directory / 'source') == record['sourceTreeSha256'], 'Source bytes/modes changed')
    option = observation.selected(record)
    if option is not None:
        require(option['sourcePins'] == observation.source_pins(lambda path: topdown.read_file(directory / 'source' / path)),
                'Engine observation source pins changed')
    if record.get('topdown'):
        selected = record['topdown']
        pins = topdown.source_pins(lambda path: topdown.read_file(directory / 'source' / path))
        require(selected['sourcePins'] == pins, 'Topdown source pins changed')
        root = directory / 'topdown'
        require(stat.S_IMODE(topdown.path_checked(root, True).stat().st_mode) == 0o755 and
                {p.name for p in root.iterdir()} == {selected['bakeId']}, 'Topdown root changed')
        topdown.validate(root / selected['bakeId'], selected['bakeId'], selected['manifestSha256'], pins, True)
    else:
        require(not (directory / 'topdown').exists(), 'Unselected topdown files')
    require(tree_hash(directory / 'certs') == record['certsSha256'], 'TLS changed')
    verify_battle_route(directory, record, legacy=legacy_route)
    require(sha(private_path(directory / 'compose.json').read_bytes()) == record['configSha256'], 'Compose changed')
    fixtures = json.loads(private_path(directory / 'runtime.json').read_bytes())
    model = json.loads((directory / 'compose.json').read_bytes())
    return fixtures, model


def verify_files(directory, record, *, legacy_route=False):
    fixtures, model = verify_custody_files(directory, record, legacy_route=legacy_route)
    require(model == model_for(record, fixtures), 'Compose differs from owned inputs')
    return model



def inspect_image(reference):
    return json.loads(run(['docker', 'image', 'inspect', '--format', IMAGE_FORMAT, reference]))


def image_metadata(record, service, image):
    return {**labels(record), 'org.opencontainers.image.revision': record['appSha'],
            'org.opensamguk.local.source-tree': record['sourceTreeSha256'],
            'org.opensamguk.local.dockerfile': sha((Path(record['custody']) / 'source/docker' / (service + '.Dockerfile')).read_bytes()),
            'org.opensamguk.local.build-args': sha(json.dumps(build_args(record, service), sort_keys=True).encode())}


def check_image(record, service, image):
    receipt = record['images'].get(service)
    require(receipt is not None and image.get('Id') == receipt['imageId'] and
            receipt['dockerfileSha256'] == image_metadata(record, service, image)['org.opensamguk.local.dockerfile'] and
            receipt['buildArgs'] == build_args(record, service), 'Image receipt mismatch')
    actual = image.get('Config', {}).get('Labels') or {}
    require(all(actual.get(k) == v for k, v in image_metadata(record, service, image).items()), 'Image label mismatch')
    require(image_ref(record, service) in image.get('RepoTags', []), 'Image tag mismatch')


def verify_images(record):
    require(set(record.get('supportImages', {})) == set(SUPPORT_IMAGES), 'Support image receipts required')
    for image, expected_id in record['supportImages'].items():
        require(inspect_image(image)['Id'] == expected_id,
                'Support image changed')
    require(set(record['images']) == set(SERVICES), 'All six source images required')
    for svc in SERVICES:
        check_image(record, svc, inspect_image(image_ref(record, svc)))


@contextlib.contextmanager
def qa_builder(directory, record):
    if not qa.selected(record):
        yield None
        return
    name = 'opensamguk-qa-build-' + record['nonce']
    container = 'buildx_buildkit_' + name + '0'
    existing = run(['docker', 'buildx', 'ls', '--format', '{{.Name}}']).decode().split()
    require(name not in existing and not run(['docker', 'ps', '-aq', '--filter', 'name=^/' + container + '$']).strip(),
            'QA builder already exists; preserved')
    qa.admission(record, 'build')
    created = False
    try:
        run(['docker', 'buildx', 'create', '--name', name, '--driver', 'docker-container',
             '--driver-opt', 'cgroup-parent=' + qa.CGROUP, '--driver-opt', 'memory=2g',
             '--driver-opt', 'memory-swap=2g', '--driver-opt', 'cpu-period=100000',
             '--driver-opt', 'cpu-quota=100000'], timeout=60)
        created = True
        run(['docker', 'buildx', 'inspect', '--bootstrap', name], timeout=180,
            log_path=directory / ('qa-builder-' + secrets.token_hex(4) + '.log'))
        cap = json.loads(run(['docker', 'inspect', '--format',
            '{"Name":{{json .Name}},"Memory":{{.HostConfig.Memory}},"MemorySwap":{{.HostConfig.MemorySwap}},'
            '"CgroupParent":{{json .HostConfig.CgroupParent}},"CpuQuota":{{.HostConfig.CpuQuota}},'
            '"CpuPeriod":{{.HostConfig.CpuPeriod}}}', container]))
        require(cap == {'Name': '/' + container, 'Memory': qa.BUILD_MEMORY, 'MemorySwap': qa.BUILD_MEMORY,
                        'CgroupParent': qa.CGROUP, 'CpuQuota': 100000, 'CpuPeriod': 100000},
                'QA builder actual cgroup/caps differ')
        yield name
    finally:
        if created:
            run(['docker', 'buildx', 'rm', '--force', name], timeout=180)
            require(not run(['docker', 'ps', '-aq', '--filter', 'name=^/' + container + '$']).strip(),
                    'QA builder cleanup incomplete')


def build(args):
    directory, record = load(args.custody)
    require(record['status'] in ('PREPARED', 'BUILDING'), 'Stack already built/started')
    verify_files(directory, record)
    with heavy(args.meta, record, 'build'), qa_builder(directory, record) as builder:
        assert_owned(record, inventory(record), empty=True)
        record['status'] = 'BUILDING'
        write_json(directory / 'contract.json', record, replace=True)
        record.setdefault('supportImages', {})
        for ref in SUPPORT_IMAGES:
            found = run(['docker', 'image', 'ls', '-q', '--filter', 'reference=' + ref])
            if not found.strip():
                print('Preparing support image ' + ref, flush=True)
                run(['docker', 'pull', ref], timeout=600,
                    log_path=directory / (ref.replace(':', '-') + '.pull.log'))
            image_id = inspect_image(ref)['Id']
            require(ref not in record['supportImages'] or record['supportImages'][ref] == image_id,
                    'Support image receipt changed')
            record['supportImages'][ref] = image_id
            write_json(directory / 'contract.json', record, replace=True)
        for svc in SERVICES:
            if svc in record['images']:
                check_image(record, svc, inspect_image(image_ref(record, svc)))
                continue
            resource_gate(directory, 'build', record) if qa.selected(record) else resource_gate(directory, 'build')
            verify_files(directory, record)
            existing = run(['docker', 'image', 'ls', '-q', '--filter', 'reference=' + image_ref(record, svc)])
            require(not existing.strip(), 'Unrecorded image already exists; preserved')
            command = ['docker', 'build', '--progress=plain', '-f', str(directory / 'source/docker' / (svc + '.Dockerfile')),
                       '-t', image_ref(record, svc)]
            if builder:
                command = ['docker', 'buildx', 'build', '--builder', builder, '--load', *command[2:]]
            for k, v in build_args(record, svc).items():
                command += ['--build-arg', k + '=' + v]
            for k, v in image_metadata(record, svc, {}).items():
                command += ['--label', k + '=' + v]
            command += [str(directory / 'source')]
            print('Building ' + svc, flush=True)
            # Build output contains no fixture values; keep it private and never echo errors.
            run(command, timeout=3600, log_path=directory / (svc + '.build.log'))
            image = inspect_image(image_ref(record, svc))
            record['images'][svc] = {'imageId': image['Id'], 'dockerfileSha256': image_metadata(record, svc, {})['org.opensamguk.local.dockerfile'],
                                     'buildArgs': build_args(record, svc)}
            check_image(record, svc, image)
            write_json(directory / 'contract.json', record, replace=True)
        verify_images(record)
        record['status'] = 'BUILT'
        write_json(directory / 'contract.json', record, replace=True)
    print('Six images built and verified')


def compose(directory, record, *args, timeout=60, log_path=None):
    return run(['docker', 'compose', '--project-name', record['project'], '--env-file', '/dev/null',
                '--project-directory', str(directory), '-f', str(directory / 'compose.json'), *args], timeout=timeout, log_path=log_path)


def verify_mounts(actual, service, model):
    expected = []
    for mount in service.get('volumes', []):
        kind = mount['type']
        require(kind in ('bind', 'volume'), 'Unexpected declared mount type')
        source = mount['source'] if kind == 'bind' else model['volumes'][mount['source']]['name']
        expected.append((kind, source, mount['target'], not mount.get('read_only', False)))
    require(len(expected) == len(set(expected)), 'Duplicate declared mount')
    aliases = {'/host_mnt' + source: source for kind, source, _, _ in expected if kind == 'bind'}
    if any(m.get('Type') == 'bind' and m.get('Source') in aliases for m in actual):
        require(sys.platform == 'darwin', 'Desktop mount alias requires macOS')
        # run() independently proves the active endpoint is a local Unix socket.
        daemon = json.loads(run(['docker', 'info', '--format',
            '{"OperatingSystem":{{json .OperatingSystem}},"OSType":{{json .OSType}},"ID":{{json .ID}}}']))
        require(daemon.get('OperatingSystem') == 'Docker Desktop' and daemon.get('OSType') == 'linux'
                and bool(daemon.get('ID')), 'Desktop mount alias requires current local Desktop daemon')
    observed = []
    for mount in actual:
        kind = mount.get('Type')
        require(kind in ('bind', 'volume') and type(mount.get('RW')) is bool,
                'Invalid runtime mount')
        source = mount.get('Source') if kind == 'bind' else mount.get('Name')
        if kind == 'bind':
            source = aliases.get(source, source)
        observed.append((kind, source, mount.get('Destination'), mount['RW']))
    require(len(observed) == len(expected) and len(set(observed)) == len(observed)
            and set(observed) == set(expected), 'Runtime mounts differ from declared model')


def verify_running(record, resources, model, *, bootstrap=False):
    assert_owned(record, resources)
    expected = set(observation.BOOTSTRAP) if bootstrap else set(model['services'])
    require(not bootstrap or observation.selected(record) is not None, 'Unselected bootstrap refused')
    require(len(resources['container']) == len(expected), 'Incomplete stack')
    seen = set()
    for row in resources['container']:
        svc = row['Config']['Labels'].get('com.docker.compose.service')
        require(svc in expected and svc not in seen, 'Unexpected or duplicate container')
        seen.add(svc)
        require(row['State']['Running'] and row['State'].get('Health', {}).get('Status') == 'healthy',
                'Service not healthy')
        expected_image = (record['images'][svc]['imageId'] if svc in SERVICES else
                          record.get('supportImages', {}).get(model['services'][svc]['image']))
        require(expected_image and row['Image'] == expected_image, 'Running image differs from receipt')
        networks = row['NetworkSettings']['Networks']
        require(set(networks) == {record['project'] + '_local'}, 'Foreign runtime network')
        ports = row['HostConfig'].get('PortBindings') or {}
        require(ports == ({'443/tcp': [{'HostIp': '127.0.0.1', 'HostPort': str(qa.port(record))}]} if svc == 'nginx' else {}),
                'Runtime port binding differs')
        if qa.selected(record):
            qa.runtime_cap(row, svc)
        verify_mounts(row.get('Mounts', []), model['services'][svc], model)
    for row in resources['network']:
        require(row.get('Driver') == 'bridge', 'Foreign runtime network driver')
        own_ids = {r['Id'] for r in resources['container']}
        require(set(row.get('Containers', {})) <= own_ids, 'Foreign network member; preserved')
    if not bootstrap:
        verify_battle_route_runtime(record, resources)
    if observation.selected(record) is not None:
        verify_observation_network(record, resources)


def verify_observation_network(record, resources):
    services = {r['Config']['Labels'].get('com.docker.compose.service') for r in resources['container']}
    require('game-engine' in services, 'Owned observation engine required')
    for endpoint in ('game-engine', 'game-api'):
        found = 0
        alias = 's' + record['serverId'] + '-' + endpoint
        for row in resources['container']:
            service = row['Config']['Labels'].get('com.docker.compose.service')
            aliases = row['NetworkSettings']['Networks'][record['project'] + '_local'].get('Aliases') or []
            if service == endpoint:
                found += 1
                require(len(aliases) == 3 and set(aliases) == {row['Name'].lstrip('/'), endpoint, alias},
                        'Owned observation endpoint aliases differ')
            else:
                require(not {endpoint, alias} & set(aliases), 'Observation endpoint belongs to another service')
        require(found == (1 if endpoint in services else 0), 'Unique owned observation endpoint required')


def verify_battle_route_runtime(record, resources):
    if profile(record) != 'tactical':
        return
    alias = 's' + record['serverId'] + '-game-api'
    found = 0
    for row in resources['container']:
        service = row['Config']['Labels'].get('com.docker.compose.service')
        aliases = row['NetworkSettings']['Networks'][record['project'] + '_local'].get('Aliases') or []
        if service == 'game-api':
            found += 1
            require(len(aliases) == 3 and set(aliases) == {row['Name'].lstrip('/'), 'game-api', alias},
                    'Owned game API runtime aliases differ')
        else:
            require(alias not in aliases, 'Owned game API alias belongs to another endpoint')
    require(found == 1, 'Unique owned game API endpoint required')


def registry_repair_model(record, fixtures, model):
    canonical = model_for(record, fixtures)
    legacy = json.loads(json.dumps(canonical))
    changed_services = []
    for name, service in legacy['services'].items():
        env = service.get('environment', {})
        if 'SERVER_REGISTRY_JSON' in env:
            rows = json.loads(env['SERVER_REGISTRY_JSON'])
            require(len(rows) == 1 and rows[0]['id'] == record['serverId'], 'Unexpected registry membership')
            rows[0]['deployProject'] = record['project']
            env['SERVER_REGISTRY_JSON'] = json.dumps(rows, separators=(',', ':'))
            changed_services.append(name)
    require(set(changed_services) == {'gateway-api', 'web-gateway', 'web-game'}, 'Unexpected registry consumers')
    require(model == legacy, 'Repair permits only the known registry deployment-coordinate defect')
    return canonical


def runtime_caps(model, resources):
    total = 0
    for row in resources['container']:
        svc = row['Config']['Labels']['com.docker.compose.service']
        limit = model['services'][svc]['mem_limit']
        require(re.fullmatch(r'[1-9][0-9]*[mg]', limit), 'Unknown runtime memory limit')
        expected = int(limit[:-1]) * {'m': 1024**2, 'g': GIB}[limit[-1]]
        actual = int(run(['docker', 'inspect', '--format', '{{.HostConfig.Memory}}', row['Id']]))
        require(actual == expected, 'Runtime memory cap differs')
        total += actual
    require(total == 6016 * 1024**2, 'Runtime memory budget differs')
    return total


def repair_registry(args):
    directory, record = load(args.custody)
    require(record['status'] == 'RUNNING', 'Registry repair requires the unpassed running stack')
    proof = json.loads(private_path(directory / 'pre-repair-c56171e-verification.json').read_bytes())
    require(proof.get('verifierHead') == 'c56171ee5d583672235fea8fece5b3ab2b38b217' and
            proof.get('oldPublicContract') == record and proof.get('gatewaySeed') == {'count': 0, 'initialized': False},
            'Original verifier receipt mismatch')
    fixtures, model = verify_custody_files(directory, record)
    canonical = registry_repair_model(record, fixtures, model)
    verify_images(record)
    require(not (directory / 'registry-repair.json').exists(), 'Registry repair already attempted; no automatic retry')
    with heavy(args.meta, record, 'gateway-repair'):
        resources = inventory(record)
        verify_running(record, resources, model)
        caps = runtime_caps(model, resources)
        query = """BEGIN READ ONLY; SELECT json_build_object(
            'count',(SELECT count(*) FROM game_server),
            'initialized',(SELECT initialized FROM game_server_registry_seed_state WHERE id=1)); COMMIT;"""
        require(json.loads(sql(directory, record, 'gateway-postgres', query)) == {'count': 0, 'initialized': False},
                'Registry already initialized; no repair')
        before = {name: sha(private_path(directory / name).read_bytes()) for name in ('runtime.json', 'fixture.json')}
        old_compose = private_path(directory / 'compose.json').read_bytes()
        old_record = private_path(directory / 'contract.json').read_bytes()
        private_write(directory / 'registry-repair-original-compose.json', old_compose)
        private_write(directory / 'registry-repair-original-contract.json', old_record)
        audit = {'status': 'PREPARED', 'oldConfigSha256': record['configSha256'],
                 'oldRegistrySha256': sha(model['services']['gateway-api']['environment']['SERVER_REGISTRY_JSON'].encode()),
                 'newRegistrySha256': sha(canonical['services']['gateway-api']['environment']['SERVER_REGISTRY_JSON'].encode()),
                 'unchangedPrivateFileHashes': before, 'runtimeCapsBytes': caps,
                 'replacedServiceMemoryBytes': 768 * 1024**2, 'hostFreeBefore': shutil.disk_usage(directory).free,
                 'originalContainers': {r['Config']['Labels']['com.docker.compose.service']: r['Id'] for r in resources['container']},
                 'originalNetworks': [r['Id'] for r in resources['network']],
                 'originalVolumes': [r['Name'] for r in resources['volume']]}
        write_json(directory / 'registry-repair.json', audit)
        write_json(directory / 'compose.json', canonical, replace=True)
        record['configSha256'] = sha((directory / 'compose.json').read_bytes())
        write_json(directory / 'contract.json', record, replace=True)
        verify_files(directory, record)
        require(all(sha(private_path(directory / name).read_bytes()) == digest for name, digest in before.items()),
                'Private fixture changed; repair stopped')
        audit.update(status='CONFIG_REPAIRED', newConfigSha256=record['configSha256'])
        write_json(directory / 'registry-repair.json', audit, replace=True)
        compose(directory, record, 'up', '-d', '--no-build', '--pull', 'never', '--no-deps',
                '--wait', '--wait-timeout', '180', 'gateway-api', timeout=240,
                log_path=directory / 'registry-repair-gateway-startup.log')
        after = inventory(record)
        verify_running(record, after, canonical)
        runtime_caps(canonical, after)
        require(all(r['Id'] == audit['originalContainers'][r['Config']['Labels']['com.docker.compose.service']]
                    for r in after['container'] if r['Config']['Labels']['com.docker.compose.service'] != 'gateway-api') and
                sorted(r['Id'] for r in after['network']) == sorted(audit['originalNetworks']) and
                sorted(r['Name'] for r in after['volume']) == sorted(audit['originalVolumes']),
                'A resource outside gateway replacement changed')
        audit.update(status='GATEWAY_RECREATED', hostFreeAfter=shutil.disk_usage(directory).free)
        write_json(directory / 'registry-repair.json', audit, replace=True)
    smoke(args)
    audit['status'] = 'SMOKE_PASSED'
    write_json(directory / 'registry-repair.json', audit, replace=True)


def startup_disk_check(directory, stage, initial_free=None):
    require(stage in ('afterObservationBootstrapFreeBytes', 'afterStartupFreeBytes', 'beforeSmokePassedFreeBytes'),
            'Unknown disk observation')
    path = directory / 'startup-disk.json'
    report = ({'startupFreeBytes': initial_free} if initial_free is not None else
              json.loads(private_path(path).read_bytes()))
    report[stage] = shutil.disk_usage(directory).free
    report['consumedBytes'] = report['startupFreeBytes'] - report[stage]
    write_json(path, report, replace=path.exists())
    require(report[stage] >= 3 * GIB, 'Startup reserve below 3 GiB; resources preserved')


def up(args):
    directory, record = load(args.custody)
    require(record['status'] == 'BUILT', 'Build six images first; do not reuse a started project')
    model = verify_files(directory, record)
    verify_images(record)
    with heavy(args.meta, record, 'startup'):
        assert_owned(record, inventory(record), empty=True)
        port_free(record)
        # config output contains credentials and stays in process memory.
        normalized = json.loads(compose(directory, record, 'config', '--format', 'json'))
        require(normalized['name'] == record['project'] and set(normalized['services']) == set(model['services']),
                'Compose normalization changed identity')
        if qa.selected(record):
            qa.normalized(normalized, model, record)
        initial_free = shutil.disk_usage(directory).free
        write_json(directory / 'startup-disk.json', {'startupFreeBytes': initial_free})
        record['status'] = 'STARTING'
        write_json(directory / 'contract.json', record, replace=True)
        bootstrap_ids = None
        if observation.selected(record) is not None:
            require(record['engineObservation']['binding'] is None, 'Fresh observation bootstrap is already bound')
            compose(directory, record, 'up', '-d', '--no-build', '--pull', 'never', '--wait', '--wait-timeout', '600',
                    *observation.BOOTSTRAP, timeout=660, log_path=directory / 'observation-bootstrap.log')
            startup_disk_check(directory, 'afterObservationBootstrapFreeBytes', initial_free)
            resources = inventory(record)
            verify_running(record, resources, model, bootstrap=True)
            bootstrap_ids = observation_resource_ids(resources)
            world = observation_metadata(directory, record)
            status = observation_status(directory, record, 'game-engine', 'http://127.0.0.1:8082')
            option = observation.bind(record, world, status, time.time(), observation.seed_tick(model))
            verify_files(directory, record)
            current = inventory(record)
            verify_running(record, current, model, bootstrap=True)
            require(observation_resource_ids(current) == bootstrap_ids, 'Bootstrap resources changed before binding')
            record['engineObservation'] = option
            fixtures = json.loads(private_path(directory / 'runtime.json').read_bytes())
            model = model_for(record, fixtures)
            write_json(directory / 'compose.json', model, replace=True)
            record['configSha256'] = sha((directory / 'compose.json').read_bytes())
            write_json(directory / 'contract.json', record, replace=True)
            verify_files(directory, record)
        compose(directory, record, 'up', '-d', '--no-build', '--pull', 'never', '--wait', '--wait-timeout', '600', timeout=660, log_path=directory / 'startup.log')
        startup_disk_check(directory, 'afterStartupFreeBytes', initial_free)
        resources = inventory(record)
        verify_running(record, resources, model)
        if bootstrap_ids is not None:
            require(observation_resource_ids(resources, bootstrap_only=True) == bootstrap_ids,
                    'Bootstrap resources changed during full startup')
        record['status'] = 'RUNNING'
        write_json(directory / 'contract.json', record, replace=True)
    smoke(args)


def resume_capacity():
    # No new workload is admitted: retain VM capacity/load checks without reserving startup memory twice.
    info = json.loads(run(['docker', 'info', '--format',
        '{"NCPU":{{json .NCPU}},"MemTotal":{{json .MemTotal}}}'], timeout=30))
    require(info['NCPU'] >= 2 and info['MemTotal'] >= 6 * GIB, 'Docker needs 2 CPUs and 6 GiB memory')
    require(os.getloadavg()[1] <= 400, 'Host load5 exceeds the managed QA limit of 400')


def resume_startup(args):
    directory, record = load(args.custody)
    require(record['status'] in ('STARTING', 'RUNNING'), 'Resume requires an unpassed started stack')
    model = verify_files(directory, record)
    verify_images(record)
    resources = inventory(record)
    verify_running(record, resources, model)
    runtime_caps(model, resources)
    resume_capacity()
    verifier_head = git(ROOT, 'rev-parse', 'HEAD').decode().strip()
    require(re.fullmatch('[a-f0-9]{40}', verifier_head), 'Invalid runtime verifier head')
    require(not git(ROOT, 'status', '--porcelain', '--untracked-files=all').strip(), 'Runtime verifier must be clean')
    # Retain the failed start contract before the first recovery transition.
    write_json(directory / ('pre-resume-' + secrets.token_hex(8) + '.json'), record)
    record['runtimeVerifierHead'] = verifier_head
    record['runtimeVerifierPath'] = str(ROOT)
    record['status'] = 'RUNNING'
    write_json(directory / 'contract.json', record, replace=True)
    smoke(args)


def route_resource_ids(resources):
    return {'containers': sorted((row['Id'], row['Image']) for row in resources['container']),
            'networks': sorted(row['Id'] for row in resources['network']),
            'volumes': sorted(row['Name'] for row in resources['volume'])}


def wait_tactical_route(directory, record):
    context = ssl.create_default_context(cafile=str(directory / 'certs/opensamguk.crt'))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
    if qa.selected(record):
        opener.add_handler(ObservationNoRedirect())
    deadline = time.monotonic() + 30
    while True:
        statuses = []
        for prefix in ('/api/battle-ws', '/ws/battles'):
            for sid in (record['serverId'], 'foreign'):
                try:
                    with opener.open(qa.origin(record) + prefix + '/' + sid + '/160/probe', timeout=3) as response:
                        statuses.append(response.status)
                except urllib.error.HTTPError as error:
                    statuses.append(error.code)
        require(statuses[1::2] == [404, 404] and all(value in (403, 404) for value in statuses[::2]),
                'Unexpected reloaded route boundary')
        if statuses == [403, 404, 403, 404]:
            return
        require(time.monotonic() < deadline, 'Tactical route reload did not become ready')
        time.sleep(1)


def restore_route_failure(directory, record, model, before, original, old_nginx, new_nginx, inode, reload_attempted):
    resources = inventory(record)
    verify_running(record, resources, model)
    require(route_resource_ids(resources) == before, 'Changed resources prevent original route restoration')
    require(private_path(directory / ROUTE_ORIGINAL).read_bytes() == original and
            private_path(directory / ROUTE_ORIGINAL_NGINX).read_bytes() == old_nginx,
            'Original route backup changed; restoration refused')
    current = private_path(directory / 'nginx.conf').read_bytes()
    require(current in (old_nginx, new_nginx), 'Foreign nginx bytes prevent restoration')
    route = private_path(directory / 'battle-ws', True)
    files = list(route.iterdir())
    require(not files or {path.name for path in files} == {ROUTE_FILE}, 'Foreign route files prevent restoration')
    if files:
        path = private_path(route / ROUTE_FILE)
        require(path.stat().st_nlink == 1 and path.read_bytes() == battle_route_bytes(record),
                'Foreign route bytes prevent restoration')
    current_contract = json.loads(private_path(directory / 'contract.json').read_bytes())
    require(current_contract in (json.loads(original), record), 'Changed contract prevents restoration')
    write_bound_nginx(directory / 'nginx.conf', current, old_nginx, inode)
    if files:
        (route / ROUTE_FILE).unlink()
    private_write(directory / 'contract.json', original, replace=True)
    if reload_attempted:
        original_record = json.loads(original)
        compose(directory, original_record, 'exec', '-T', 'nginx', 'nginx', '-t',
                log_path=directory / 'tactical-route-restore-nginx-test.log')
        compose(directory, original_record, 'exec', '-T', 'nginx', 'nginx', '-s', 'reload',
                log_path=directory / 'tactical-route-restore-nginx-reload.log')
    current = inventory(record)
    verify_running(record, current, model)
    require(route_resource_ids(current) == before, 'Restored route resource identities changed')


def battle_boundary_checks(record):
    checks = []
    for prefix in ('/api/battle-ws', '/ws/battles'):
        checks.extend([(prefix + '/' + record['serverId'] + '/160/probe',
                        {403 if profile(record) == 'tactical' else 404}),
                       (prefix + '/foreign/160/probe', {404}),
                       (prefix + '/' + record['serverId'] + '/0/probe', {404}),
                       (prefix + '/' + record['serverId'] + '/160/bad.dot', {404})])
    return checks


def repair_tactical_route(args):
    directory, record = load(args.custody)
    require(args.authorize_project == record['project'], 'Explicit owned route repair approval required')
    require(record['status'] == 'RUNNING' and record['dockerSha'] == LEGACY_TACTICAL_DOCKER and
            profile(record) == 'tactical' and 'battleRouting' not in record and
            not any(key.startswith('runtimeVerifier') for key in record), 'Only original unpassed d35 tactical route repair is allowed')
    verifier = route_verifier_identity(args.verifier_sha)
    for path in ('docker-compose.localhost-acceptance.yml',):
        require(git(ROOT, 'show', record['dockerSha'] + ':' + path) ==
                git(ROOT, 'show', args.verifier_sha + ':' + path), 'Route repair cannot change Compose')
    old_nginx, new_nginx = route_nginx_transition(record, args.verifier_sha)
    failure = json.loads(private_path(directory / 'h-execution.json').read_bytes())
    require(failure.get('status') == 'FAILED_OR_REFUSED' and failure.get('exceptionType') == 'Refused' and
            failure.get('fixedFailureCode') == 'Boundary smoke failed at /api/battle-ws/' + record['serverId'] + '/160/probe',
            'Original tactical boundary failure is required')
    attempt = directory / 'tactical-route-execution.json'
    require(not any(path.exists() or path.is_symlink() for path in
                    (attempt, directory / ROUTE_ORIGINAL, directory / ROUTE_ORIGINAL_NGINX, directory / ROUTE_PROOF)),
            'Route repair already attempted; original state preserved')
    with heavy(args.meta, record, 'route-repair'):
        require(not (Path(args.meta) / '.locks/gui-run').exists(), 'GUI operation active')
        model = verify_files(directory, record, legacy_route=True)
        verify_images(record)
        resources = inventory(record)
        verify_running(record, resources, model)
        runtime_caps(model, resources)
        before = route_resource_ids(resources)
        original = private_path(directory / 'contract.json').read_bytes()
        require(json.loads(original) == record, 'Contract changed during route repair admission')
        inode = nginx_file_identity(directory / 'nginx.conf')
        config = {'runtimeNginxSha256': sha(new_nginx), 'runtimeNginxFileIdentity': inode}
        audit = {'status': 'APPLYING', 'buildDockerSha': record['dockerSha'], **verifier,
                 'originalContractFile': ROUTE_ORIGINAL, 'originalContractSha256': sha(original),
                 'resourceIdsBefore': before}
        write_json(attempt, audit)
        reload_attempted = False
        try:
            private_write(directory / ROUTE_ORIGINAL, original)
            private_write(directory / ROUTE_ORIGINAL_NGINX, old_nginx)
            record.update({**verifier, **config})
            record['battleRouting'] = battle_route_binding(record)
            write_json(directory / ROUTE_PROOF, {'schema': 1, 'originalContractSha256': sha(original),
                       **verifier, **config, 'battleRouting': record['battleRouting']})
            private_write(directory / 'battle-ws' / ROUTE_FILE, battle_route_bytes(record))
            write_bound_nginx(directory / 'nginx.conf', old_nginx, new_nginx, inode)
            write_json(directory / 'contract.json', record, replace=True)
            verify_files(directory, record)
            compose(directory, record, 'exec', '-T', 'nginx', 'nginx', '-t',
                    log_path=directory / 'tactical-route-nginx-test.log')
            reload_attempted = True
            compose(directory, record, 'exec', '-T', 'nginx', 'nginx', '-s', 'reload',
                    log_path=directory / 'tactical-route-nginx-reload.log')
            wait_tactical_route(directory, record)
            current = inventory(record)
            verify_running(record, current, model)
            require(route_resource_ids(current) == before, 'Route repair changed resource identities')
            audit['status'] = 'RELOADED'
            write_json(attempt, audit, replace=True)
            smoke(args, finalize=False)
            current = inventory(record)
            verify_running(record, current, model)
            require(route_resource_ids(current) == before, 'Post-smoke resource identities changed')
            record['status'] = 'SMOKE_PASSED'
            write_json(directory / 'contract.json', record, replace=True)
            audit['status'] = 'SMOKE_PASSED'
            write_json(attempt, audit, replace=True)
        except BaseException:
            audit['status'] = 'FAILED_OR_REFUSED'
            try:
                restore_route_failure(directory, record, model, before, original, old_nginx, new_nginx, inode, reload_attempted)
                audit['restoration'] = 'ORIGINAL_FAILURE_CONFIG_RESTORED'
            except BaseException:
                audit['restoration'] = 'REFUSED_OR_FAILED_REQUIRES_OPERATOR'
            write_json(attempt, audit, replace=True)
            raise
    print('Owned tactical route repaired; original failure and six build image pins retained; USER remains separate')


def sql(directory, record, service, query):
    db = 'game' if service == 'game-postgres' else 'gateway'
    return compose(directory, record, 'exec', '-T', service, 'psql', '-X', '-q', '-A', '-t', '-v', 'ON_ERROR_STOP=1',
                   '-U', 'lha', '-d', db, '-c', query).decode().strip()


def observation_resource_ids(resources, *, bootstrap_only=False):
    containers = resources['container']
    if bootstrap_only:
        containers = [r for r in containers if r['Config']['Labels']['com.docker.compose.service'] in observation.BOOTSTRAP]
    return {'container': sorted(r['Id'] for r in containers), 'network': sorted(r['Id'] for r in resources['network']),
            'volume': sorted(r['Name'] for r in resources['volume'] if
                             r['Name'].endswith(('_game-pgdata', '_game-redisdata')))}


def observation_metadata(directory, record):
    require(type(record['worldId']) is int, 'Observation world must be an integer')
    # Only identity/timing metadata is projected, never the complete meta/env or account tables.
    query = f"""BEGIN READ ONLY;
        SELECT json_build_object('worldCount',(SELECT count(*) FROM world_state),
          'worldId',w.id,'tickSeconds',w.tick_seconds,'serverId',w.meta->>'serverId',
          'serverIdAlias',w.meta->>'server_id',
          'games',(SELECT json_agg(json_build_object('worldId',g.world_id,'serverId',g.server_id))
                   FROM ng_games g WHERE g.world_id=w.id))
        FROM world_state w WHERE w.id={record['worldId']}; COMMIT;"""
    return observation.decode(sql(directory, record, 'game-postgres', query))


def observation_status(directory, record, service, origin):
    require((service, origin) in (('game-engine', 'http://127.0.0.1:8082'), ('game-api', observation.ORIGIN)),
            'Observation probe endpoint differs')
    raw = compose(directory, record, 'exec', '-T', service, 'curl', '--silent', '--show-error',
                  '--max-time', '1', '--noproxy', '*', '--write-out', '\nSTATUS:%{http_code}',
                  origin + '/admin/turn-daemon/status')
    body, separator, status = raw.rpartition(b'\nSTATUS:')
    require(separator and status == b'200', 'Observation status HTTP probe failed')
    return observation.decode(body)


def observation_smoke(directory, record, model, opener):
    option = observation.selected(record)
    if option is None:
        return
    binding = option['binding']
    require(binding is not None, 'Collector is not bound to generated metadata')
    require(observation.metadata(observation_metadata(directory, record), record, observation.seed_tick(model)) == binding,
            'Generated observation binding changed')
    observation.validate_status(observation_status(directory, record, 'game-api', observation.ORIGIN), binding, time.time())
    # The public response need not claim RUNNING: PAUSED/STALLED are valid observed states.
    try:
        with opener.open(qa.origin(record) + '/api/server-basic-info/' + record['serverId'], timeout=5) as response:
            require(response.status == 200, 'Public collector HTTP probe failed')
            payload = observation.decode(response.read(65537))
        observation.validate_public(payload, binding, time.time())
    except urllib.error.URLError:
        raise Refused('Public collector HTTP probe failed') from None


def validate_tactical_readiness(payload, record, now=None):
    pins = ('dbFingerprint', 'nativeFenceSha256', 'ruleSha256', 'catalogSha256', 'combatSha256', 'spaceSha256')
    require(isinstance(payload, dict) and set(payload) == set(pins) | {
        'schemaVersion', 'status', 'worldId', 'moraleEncoding', 'checkedAt', 'reasons'},
        'Tactical readiness response schema differs')
    require(type(payload['schemaVersion']) is int and payload['schemaVersion'] == 1 and
            type(payload['worldId']) is int and payload['worldId'] == record['worldId'] and
            payload['status'] == 'READY' and payload['reasons'] == [] and
            payload['moraleEncoding'] == 'CAMPAIGN_NATIVE_D177_V1', 'Tactical pipeline is not ready')
    require(all(isinstance(payload[key], str) and re.fullmatch('[a-f0-9]{64}', payload[key]) for key in pins),
            'Tactical readiness pin is missing or invalid')
    try:
        stamp = datetime.datetime.fromisoformat(payload['checkedAt'].replace('Z', '+00:00'))
    except (AttributeError, TypeError, ValueError):
        raise Refused('Tactical readiness time is invalid') from None
    require(stamp.tzinfo is not None and stamp.utcoffset() == datetime.timedelta(0),
            'Tactical readiness time must be UTC')
    age = (time.time() if now is None else now) - stamp.timestamp()
    require(0 <= age <= 5, 'Tactical readiness observation is not fresh')


def tactical_smoke(directory, record):
    # Probe inside the owned API container; no new public gateway route or credential is needed.
    raw = compose(directory, record, 'exec', '-T', 'game-api', 'curl', '--silent', '--show-error',
                  '--max-time', '3', '--noproxy', '*', '--write-out', '\nSTATUS:%{http_code}',
                  f'http://127.0.0.1:8081/internal/battles/pipeline-readiness?worldId={record["worldId"]}')
    body, separator, status = raw.rpartition(b'\nSTATUS:')
    require(separator and status == b'200' and len(body) <= 16384, 'Tactical readiness HTTP probe failed')
    def unique_fields(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'Tactical readiness response has duplicate fields')
            result[key] = value
        return result
    try:
        payload = json.loads(body, object_pairs_hook=unique_fields)
    except (ValueError, UnicodeDecodeError):
        raise Refused('Tactical readiness response is invalid') from None
    validate_tactical_readiness(payload, record)


def validate_startup_pause_status(payload, record):
    require(isinstance(payload, dict) and payload.get('state') == 'paused' and
            payload.get('running') is False and all(payload.get(key) is True for key in
            ('paused', 'loopAlive', 'serviceMaterialized', 'recoveryReady', 'autoStartEnabled')) and
            payload.get('recoveryMode') == 'READY', 'Engine startup pause is not ready')
    clock = payload.get('clock')
    require(isinstance(clock, dict) and type(clock.get('worldId')) is int and
            clock['worldId'] == record['worldId'], 'Startup pause world differs')
    started, completed = payload.get('lastTickStartedAt'), payload.get('lastTickCompletedAt')
    if started is None and completed is None:
        return
    try:
        start = datetime.datetime.fromisoformat(started.replace('Z', '+00:00'))
        end = datetime.datetime.fromisoformat(completed.replace('Z', '+00:00'))
        require(start.tzinfo is not None and end.tzinfo is not None and end >= start,
                'Startup pause has an unfinished tick')
    except (AttributeError, TypeError, ValueError):
        raise Refused('Startup pause tick observation is invalid') from None


def startup_pause_smoke(directory, record):
    if not startup_paused(record):
        return
    raw = compose(directory, record, 'exec', '-T', 'game-engine', 'curl', '--silent', '--show-error',
                  '--max-time', '3', '--noproxy', '*', '--write-out', '\nSTATUS:%{http_code}',
                  'http://127.0.0.1:8082/admin/turn-daemon/status')
    body, separator, status = raw.rpartition(b'\nSTATUS:')
    require(separator and status == b'200' and len(body) <= 16384, 'Startup pause HTTP probe failed')
    def unique_fields(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'Startup pause status has duplicate fields')
            result[key] = value
        return result
    try:
        payload = json.loads(body, object_pairs_hook=unique_fields)
    except (ValueError, UnicodeDecodeError):
        raise Refused('Startup pause status is invalid') from None
    validate_startup_pause_status(payload, record)


def smoke(args, *, finalize=True):
    directory, record = load(args.custody)
    with qa.lock('browser.lock') if qa.selected(record) else contextlib.nullcontext():
        return smoke_locked(args, finalize=finalize)


def smoke_locked(args, *, finalize=True):
    directory, record = load(args.custody)
    model = verify_files(directory, record)
    verify_images(record)
    verify_running(record, inventory(record), model)
    compose(directory, record, 'exec', '-T', 'nginx', 'nginx', '-t',
            log_path=directory / ('nginx-test-' + secrets.token_hex(4) + '.log'))
    context = ssl.create_default_context(cafile=str(directory / 'certs/opensamguk.crt'))
    handlers = [urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context)]
    if observation.selected(record) is not None or qa.selected(record):
        handlers.append(ObservationNoRedirect())
    opener = urllib.request.build_opener(*handlers)
    checks = [('/health', {200}), ('/api/gateway/auth/me', {401}), *battle_boundary_checks(record),
              ('/d_pic/.ops/private', {404}), ('/game/', {404}), ('/', {200})]
    for path, expected in checks:
        try:
            with opener.open(qa.origin(record) + path, timeout=30) as response:
                status = response.status
        except urllib.error.HTTPError as e:
            status = e.code
        require(status in expected, 'Boundary smoke failed at ' + path)
    require(sql(directory, record, 'game-postgres', 'SELECT string_agg(id::text,\',\' ORDER BY id) FROM world_state;') == '160',
            'Seed world identity mismatch')
    # Registry JSON input is checked byte-for-byte during prepare/validate. Actual publication is verified by ID.
    sid = record['serverId']
    actual = sql(directory, record, 'gateway-postgres',
                 f"SELECT count(*) FROM game_server s JOIN game_server_publication p USING(server_id) WHERE s.server_id='{sid}' AND s.generation=0 AND p.state='PUBLIC' AND p.revision=1;")
    require(actual == '1', 'Registry identity mismatch')
    if profile(record) == 'tactical':
        tactical_smoke(directory, record)
    topdown.smoke(record, lambda path: compose(directory, record, 'exec', '-T', 'game-api',
        'curl', '-fsS', '--max-time', '15', 'http://localhost:8081' + path))
    startup_pause_smoke(directory, record)
    observation_smoke(directory, record, model, opener)
    startup_disk_check(directory, 'beforeSmokePassedFreeBytes')
    if finalize:
        record['status'] = 'SMOKE_PASSED'
        write_json(directory / 'contract.json', record, replace=True)
    print('nginx, healthy services, seed identity and unauthenticated boundaries passed; USER stories remain separate')



def snapshot(args):
    require(re.fullmatch(r'[1-9][0-9]{0,9}', str(args.general_id)), 'Positive general ID required')
    request_id = args.request_id
    if request_id is not None:
        require(re.fullmatch(r'[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}', request_id), 'UUID request ID required')
    directory, record = load(args.custody, read_only=True)
    require(sha(private_path(directory / 'compose.json').read_bytes()) == record['configSha256'], 'Compose changed')
    model = json.loads((directory / 'compose.json').read_bytes())
    validate_model(model, record)
    verify_running(record, inventory(record), model)
    gid = int(args.general_id)
    extra = ""
    if request_id is not None:
        extra = f""", 'reservation', (SELECT row_to_json(r) FROM (
            SELECT turn_idx AS slot, action_code AS action, reservation_revision AS revision
            FROM general_turn WHERE world_id=160 AND general_id={gid} AND request_id='{request_id}') r),
          'logCount', (SELECT count(*) FROM log_entry WHERE world_id=160 AND general_id={gid}
              AND meta->'refs'->>'requestId'='{request_id}'),
          'appliedCount', (SELECT count(*) FROM command_result WHERE world_id=160
              AND request_id='{request_id}' AND terminal_status='APPLIED' AND ok=true),
          'terminal', (SELECT row_to_json(t) FROM (
            SELECT terminal_status AS status, ok, committed_world_version AS version FROM command_result
            WHERE world_id=160 AND request_id='{request_id}' ORDER BY result_seq DESC LIMIT 1) t)"""
    query = f"""BEGIN READ ONLY;
      SELECT json_build_object('generalId',g.id,'cityId',g.city_id,'userId',g.user_id,
        'nationId',g.nation_id,'npcState',g.npc_state,'experience',g.experience,'dedication',g.dedication,
        'turnTime',g.turn_time,'personal',json_build_object('requestId',g.meta->'personalLastTurn'->>'requestId',
          'inputId',g.meta->'personalLastTurn'->>'inputId'),
        'world',(SELECT json_build_object('year',current_year,'month',current_month,'phase',current_phase,
          'lastTurnTime',meta->>'lastTurnTime','tickSeconds',tick_seconds,
          'worldVersion',world_version,'writerEpoch',writer_epoch) FROM world_state WHERE id=160)
        {extra}) FROM general g WHERE g.world_id=160 AND g.id={gid};
      COMMIT;"""
    raw = sql(directory, record, 'game-postgres', query)
    # psql transaction tags are suppressed with -q; JSON is the only public stdout.
    result = json.loads(raw)
    require(isinstance(result, dict) and result.get('generalId') == gid, 'Persisted actor missing')
    print(json.dumps(result))


def down(args):
    directory, record = load(args.custody)
    # Cleanup does not require healthy services or all six successful builds.
    verify_files(directory, record)
    with heavy(args.meta, record, 'cleanup'):
        resources = inventory(record)
        assert_owned(record, resources)
        own_ids = {r['Id'] for r in resources['container']}
        for row in resources['network']:
            require(set(row.get('Containers', {})) <= own_ids, 'Foreign network member; no cleanup')
        # Reject volumes attached to any container outside the exact owned inventory.
        for volume in resources['volume']:
            consumers = set(run(['docker', 'ps', '-aq', '--filter', 'volume=' + volume['Name']]).decode().split())
            require(all(any(r['Id'].startswith(c) for r in resources['container']) for c in consumers),
                    'Foreign volume consumer; no cleanup')
        for svc in record['images']:
            check_image(record, svc, inspect_image(image_ref(record, svc)))
        # Delete inspected IDs/names explicitly. Compose down could also act on unknown orphans.
        if own_ids:
            run(['docker', 'container', 'rm', '-f', *sorted(own_ids)])
        for row in resources['network']:
            run(['docker', 'network', 'rm', row['Id']])
        for row in resources['volume']:
            run(['docker', 'volume', 'rm', row['Name']])
        for svc in record['images']:
            run(['docker', 'image', 'rm', image_ref(record, svc)])
        record['status'] = 'REMOVED'
        write_json(directory / 'contract.json', record, replace=True)
    # Keep private custody/source and the original failure for independent diagnosis.
    print('Owned resources removed; private custody retained')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('prepare', allow_abbrev=False)
    p.add_argument('--source', required=True, type=Path)
    p.add_argument('--app-sha', required=True)
    p.add_argument('--docker-sha', required=True)
    p.add_argument('--custody', required=True, type=Path)
    p.add_argument('--hostinger-qa-task', help='Fresh-only fixed localhost:18443/cgroup policy; exact t_<8hex> task ID')
    p.add_argument('--profile', choices=('standard', 'tactical'), default='standard',
                   help='Explicit opt-in for a new fixture; never modifies an existing custody')
    p.add_argument('--startup-paused', action='store_true',
                   help='Hold scheduled ticks from engine startup; normal resume releases the hold')
    p.add_argument('--engine-observation', action='store_true',
                   help='New stack only: bind the API collector to generated engine metadata before starting API')
    p.add_argument('--clone-source-custody', type=Path,
                   help='Optional owned prior custody; clone public source only after exact Git archive comparison')
    p.add_argument('--topdown-bundle', type=Path, help='Existing approved full bake directory; new custody only')
    p.add_argument('--topdown-bake-id', help='Explicit approved 64-hex bake identity')
    p.add_argument('--topdown-manifest-sha256', help='Explicit approved manifest byte SHA256')
    p = sub.add_parser('snapshot')
    p.add_argument('--custody', required=True, type=Path)
    p.add_argument('--general-id', required=True)
    p.add_argument('--request-id')
    for command in ('build', 'up', 'smoke', 'resume-startup', 'validate', 'down', 'repair-registry', 'repair-tactical-route'):
        p = sub.add_parser(command)
        p.add_argument('--custody', required=True, type=Path)
        if command in ('build', 'up', 'down', 'repair-registry', 'repair-tactical-route'):
            p.add_argument('--meta', required=True, type=Path)
        if command == 'repair-tactical-route':
            p.add_argument('--verifier-sha', required=True, help='Exact separately reviewed clean verifier revision')
            p.add_argument('--authorize-project', required=True, help='Exact owned project, after explicit operation approval')
    args = parser.parse_args()
    try:
        if args.command == 'validate':
            directory, record = load(args.custody)
            verify_files(directory, record)
            assert_owned(record, inventory(record))
            print('Owned source/config validated')
        else:
            globals()[args.command.replace('-', '_')](args)
    except (Refused, qa.Refused, OSError, ValueError, KeyError, TypeError, EOFError) as e:
        # Never print child exceptions, config values, tokens or arbitrary untrusted filenames.
        print('REFUSED: ' + str(e) if isinstance(e, (Refused, qa.Refused, topdown.Refused, observation.Refused)) else 'REFUSED: invalid input or unavailable dependency; custody preserved')
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
