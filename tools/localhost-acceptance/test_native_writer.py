"""Synthetic source/files/proofs and mocked runtime only. No Docker, PG, HTTP or credentials."""
import base64
import copy
from contextlib import ExitStack, nullcontext, redirect_stderr, redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

spec = importlib.util.spec_from_file_location('native_harness', Path(__file__).with_name('harness.py'))
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)
n = h.native_writer


class NativeWriterTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()
        self.directory.chmod(0o700)
        self.record = {'schema': 1, 'nonce': '0123456789abcdef', 'session': '01a15100-e55a-7551-b704-52c7a0571fdf',
                       'project': 'osglha0123456789abcdef', 'serverId': 'lha0123456789abcdef',
                       'origin': h.ORIGIN, 'worldId': 160, 'generation': 0, 'custody': str(self.directory),
                       'appSha': 'a' * 40, 'dockerSha': 'b' * 40, 'status': 'BUILT', 'images': {}}
        self.fixtures = {key: 'synthetic-fixture' for key in ('DB_PASSWORD', 'JWT_PRIVATE_KEY', 'JWT_PUBLIC_KEY',
                         'INTERNAL_TOKEN', 'DEPLOYER_TOKEN', 'ADMIN_USERNAME', 'ADMIN_PASSWORD')}
        self.source = {path: '\n'.join(markers).encode() for path, markers in n.SOURCE.items()}
        self.helper = Path(n.__file__).read_bytes()
        self.option = n.selection(self.source.__getitem__, lambda path: self.helper)
        self.proof = {'worldCount': 1, 'worldId': 160, 'writerEpoch': 1, 'grantEpoch': 1, 'previousEpoch': 0,
                      'originEpoch': 0, 'grantId': '11111111-1111-4111-8111-111111111111',
                      'requestId': '11111111-1111-4111-8111-111111111111', 'leaseAlive': True, 'handoverValid': True}

    def selected_record(self, bound=False):
        record = copy.deepcopy(self.record)
        record['nativeWriter'] = copy.deepcopy(self.option)
        if bound: record['nativeWriter']['proof'] = copy.deepcopy(self.proof)
        return record

    def config(self):
        h.private_write(self.directory / n.FILE, n.CONFIG)
        (self.directory / n.FILE).chmod(0o644)

    def test_off_does_not_read_native_source_tables_or_require_a_schema(self):
        with patch.object(n, 'source_pins', side_effect=AssertionError('native source read in OFF')), \
             patch.object(h, 'sql', side_effect=AssertionError('native table may not exist')), \
             patch.object(h, 'compose', side_effect=AssertionError('runtime called in OFF')):
            self.assertIsNone(n.selected(self.record))
            self.assertEqual(({}, []), n.settings(self.record))
            h.model_for(self.record, self.fixtures)
            h.native_writer_smoke(self.directory, self.record)
            n.verify_custody(self.directory, self.record,
                             lambda path: self.fail('OFF read app source'), lambda path: self.fail('OFF read verifier'))

    def test_exact_engine_only_file_projection_composes_with_existing_profiles(self):
        for tactical in (False, True):
            for observed in (False, True):
                record = copy.deepcopy(self.record)
                record['startupPaused'] = True
                fixtures = dict(self.fixtures)
                if tactical:
                    record['profile'] = 'tactical'
                    fixtures[h.TACTICAL_KEY] = base64.b64encode(b'k' * 32).decode()
                if observed:
                    record['engineObservation'] = {'schema': 1, 'sourcePins': {path: 'c' * 64 for path in h.observation.SOURCE},
                        'binding': {'publicServerId': record['serverId'], 'nativeServerId': 'generated-world-sid',
                                    'worldId': 160, 'tickSeconds': 120}}
                baseline = h.model_for(record, fixtures)
                record['nativeWriter'] = self.option
                model = h.model_for(record, fixtures)
                engine = model['services']['game-engine']
                self.assertEqual('file:/app/native-writer.properties', engine['environment'].pop(n.LOCATION))
                self.assertEqual([{'type': 'bind', 'source': str(self.directory) + '/' + n.FILE,
                                  'target': n.TARGET, 'read_only': True, 'bind': {'create_host_path': False}}],
                                 engine.pop('volumes'))
                self.assertNotIn('SPRING_APPLICATION_JSON', engine['environment'])
                self.assertEqual(baseline, model)
        self.assertEqual(b'opensamguk.native-writer.enabled=true\n', n.CONFIG)

    def test_nonboolean_selection_unknown_record_keys_and_bad_world_refuse(self):
        for option in (None, False, True, 'true', {}, {**self.option, 'schema': True},
                       {**self.option, 'sourcePins': {}}, {**self.option, 'configSha256': '0' * 64},
                       {**self.option, 'extra': True}):
            with self.subTest(option=option), self.assertRaises(n.Refused):
                h.model_for({**self.record, 'nativeWriter': option}, self.fixtures)
        for alias in ('native_writer', 'nativeWriterEnabled', 'NATIVE_WRITER', 'native-writer'):
            with self.subTest(alias=alias), self.assertRaises(n.Refused): n.selected({**self.record, alias: False})
        for key, value in (('worldId', True), ('worldId', 1), ('generation', 1)):
            record = self.selected_record()
            record[key] = value
            with self.assertRaises(n.Refused): h.model_for(record, self.fixtures)

    def test_other_services_and_config_aliases_cannot_receive_native_property(self):
        record = self.selected_record()
        model = h.model_for(record, self.fixtures)
        for service in model['services']:
            for key, value in ((n.LOCATION, 'file:/foreign'), ('SPRING_CONFIG_LOCATION', 'file:/foreign'),
                               ('OPENSAMGUK_NATIVE_WRITER_ENABLED', 'true'), ('opensamguk.native-writer.enabled', 'true'),
                               ('SPRING_APPLICATION_JSON', '{"opensamguk":{"native-writer":{"enabled":true}}}'),
                               ('JAVA_TOOL_OPTIONS', '-Dopensamguk.native-writer.enabled=true')):
                changed = copy.deepcopy(model)
                changed['services'][service].setdefault('environment', {})[key] = value
                with self.subTest(service=service, key=key), self.assertRaises((n.Refused, h.Refused, h.observation.Refused)):
                    h.validate_model(changed, record)

    def test_config_mount_missing_foreign_writable_extra_and_disabled_record_refuse(self):
        record = self.selected_record()
        model = h.model_for(record, self.fixtures)
        for mutate in (lambda m: m['services']['game-engine'].pop('volumes'),
                       lambda m: m['services']['game-engine']['volumes'][0].update(read_only=False),
                       lambda m: m['services']['game-engine']['volumes'][0].update(source='/tmp/foreign'),
                       lambda m: m['services']['game-engine']['volumes'][0].update(target='/app/application.properties'),
                       lambda m: m['services']['game-engine']['volumes'][0]['bind'].update(create_host_path=True),
                       lambda m: m['services']['game-engine']['volumes'].append(copy.deepcopy(m['services']['game-engine']['volumes'][0])),
                       lambda m: m['services']['game-api'].update(volumes=copy.deepcopy(m['services']['game-engine']['volumes']))):
            changed = copy.deepcopy(model); mutate(changed)
            with self.assertRaises((h.Refused, n.Refused)): h.validate_model(changed, record)
        with self.assertRaises((h.Refused, n.Refused)): h.validate_model(model, self.record)
        with self.assertRaises(n.Refused): h.validate_model(h.model_for(self.record, self.fixtures), record)

    def test_config_bytes_modes_links_owner_and_old_custody_verifier_refuse(self):
        record = self.selected_record()
        self.config()
        def verify(): n.verify_custody(self.directory, record, self.source.__getitem__, lambda path: self.helper)
        verify()
        path = self.directory / n.FILE
        for mode in (0o600, 0o666, 0o755):
            path.chmod(mode)
            with self.subTest(mode=mode), self.assertRaises(n.Refused): verify()
        path.chmod(0o644)
        for data in (b'opensamguk.native-writer.enabled=false\n', n.CONFIG + b'server.port=9999\n', b''):
            path.write_bytes(data)
            with self.assertRaises(n.Refused): verify()
        path.write_bytes(n.CONFIG)
        with patch.object(n.os, 'getuid', return_value=os.getuid() + 1), self.assertRaises(n.Refused): verify()
        linked = self.directory / 'extra-link'; os.link(path, linked)
        with self.assertRaises(n.Refused): verify()
        linked.unlink(); path.unlink()
        other = self.directory / 'public-file'; other.write_bytes(n.CONFIG); path.symlink_to(other)
        with self.assertRaises(n.Refused): verify()
        path.unlink(); path.write_bytes(n.CONFIG); path.chmod(0o644)
        with self.assertRaises(n.Refused):
            n.verify_custody(self.directory, record, self.source.__getitem__, lambda path: b'old Docker without native capability')
        with self.assertRaises(n.Refused): n.verify_custody(self.directory, self.record, None, None)

    def test_old_app_and_old_docker_cannot_create_selection(self):
        with self.assertRaises(n.Refused): n.selection(lambda path: b'old app', lambda path: self.helper)
        with self.assertRaises(n.Refused): n.selection(self.source.__getitem__, lambda path: b'old Docker')
        for path in self.source:
            bad = {**self.source, path: b'missing native contract'}
            with self.subTest(path=path), self.assertRaises(n.Refused): n.source_pins(bad.__getitem__)

    def test_runtime_native_bind_must_match_its_readonly_single_file_declaration(self):
        record = self.selected_record(); model = h.model_for(record, self.fixtures)
        engine = model['services']['game-engine']
        mount = {'Type': 'bind', 'Source': record['custody'] + '/' + n.FILE, 'Destination': n.TARGET, 'RW': False}
        h.verify_mounts([mount], engine, model)
        for changed in ([], [mount, mount], [{**mount, 'RW': True}], [{**mount, 'Source': '/tmp/foreign'}],
                        [{**mount, 'Destination': '/app/application.properties'}]):
            with self.subTest(changed=changed), self.assertRaises(h.Refused): h.verify_mounts(changed, engine, model)

    def test_source_drift_is_rejected_even_when_required_markers_remain(self):
        record = self.selected_record(); self.config()
        changed = dict(self.source)
        changed[next(iter(changed))] += b'\nchanged source'
        with self.assertRaisesRegex(n.Refused, 'source pins changed'):
            n.verify_custody(self.directory, record, changed.__getitem__, lambda path: self.helper)

    def test_query_is_fixed_world_readonly_and_never_issues_a_grant(self):
        record = self.selected_record()
        with patch.object(h, 'sql', return_value=json.dumps(self.proof)) as sql:
            self.assertEqual(self.proof, h.native_writer_proof(self.directory, record))
        query = sql.call_args.args[-1]
        self.assertEqual('game-postgres', sql.call_args.args[-2])
        self.assertIn('BEGIN READ ONLY', query); self.assertIn('WHERE w.id=160', query)
        self.assertIn('native_writer_lease_alive(w.id,g.grant_id,g.epoch)', query)
        self.assertIn('native_writer_binding_valid(w.id,h.origin_epoch,g.epoch,g.grant_id)', query)
        for word in ('UPDATE ', 'INSERT ', 'DELETE ', 'set_config', 'pg_try_advisory_lock', 'password', 'SELECT *'):
            self.assertNotIn(word, query)
        with patch.object(h, 'sql') as sql, self.assertRaises(n.Refused): h.native_writer_proof(self.directory, self.record)
        sql.assert_not_called()

    def test_grant_requires_exact_world_epoch_uuid_live_lease_and_complete_chain(self):
        n.validate_proof(self.proof, self.record)
        for key, value in (('worldCount', 0), ('worldCount', 2), ('worldCount', True), ('worldId', 1),
                           ('writerEpoch', 0), ('writerEpoch', True), ('grantEpoch', 2), ('previousEpoch', -1),
                           ('originEpoch', 1), ('originEpoch', True), ('grantId', 'invalid'),
                           ('requestId', '22222222-2222-4222-8222-222222222222'), ('leaseAlive', False),
                           ('leaseAlive', 'true'), ('handoverValid', False), ('handoverValid', None)):
            with self.subTest(key=key, value=value), self.assertRaises(n.Refused):
                n.validate_proof({**self.proof, key: value}, self.record)
        with self.assertRaises(n.Refused): n.validate_proof({**self.proof, 'running': True}, self.record)

    def test_initial_binding_only_in_fresh_starting_and_rechecks_never_adopt_a_new_grant(self):
        record = self.selected_record()
        with self.assertRaises(n.Refused): n.verify_proof(self.proof, record, initial=True)
        record['status'] = 'STARTING'
        record['nativeWriter']['proof'] = n.verify_proof(self.proof, record, initial=True)
        n.verify_proof(self.proof, record)
        with self.assertRaises(n.Refused): n.verify_proof(self.proof, record, initial=True)
        changed = {**self.proof, 'writerEpoch': 2, 'grantEpoch': 2, 'previousEpoch': 1,
                   'grantId': '22222222-2222-4222-8222-222222222222', 'requestId': '22222222-2222-4222-8222-222222222222'}
        n.validate_proof(changed, record)
        with self.assertRaisesRegex(n.Refused, 'owned grant changed'): n.verify_proof(changed, record)
        self.assertEqual(self.proof, record['nativeWriter']['proof'])

    def test_duplicate_empty_oversize_proofs_fail_without_echoing_values(self):
        for raw in (b'{"leaseAlive":true,"leaseAlive":false}', b'', b'x' * 8193, b'\xff', b'not JSON'):
            with self.assertRaises(n.Refused): n.decode(raw)

    def resources(self, services):
        rows = []
        for service in services:
            name = self.record['project'] + '-' + service + '-1'
            rows.append({'Id': 'id-' + service, 'Name': name, 'Config': {'Labels': {'com.docker.compose.service': service}},
                         'NetworkSettings': {'Networks': {self.record['project'] + '_local': {
                             'Aliases': [name, service, 's' + self.record['serverId'] + '-' + service]}}}})
        return {'container': rows, 'network': [{'Id': 'owned-network'}],
                'volume': [{'Name': self.record['project'] + '_game-pgdata'}, {'Name': self.record['project'] + '_game-redisdata'}]}

    def startup(self, proofs=None, observed=False, free=None):
        record = self.selected_record()
        if observed:
            record['engineObservation'] = {'schema': 1, 'sourcePins': {path: 'c' * 64 for path in h.observation.SOURCE}, 'binding': None}
        model = h.model_for(record, self.fixtures)
        bootstrap = self.resources(h.observation.BOOTSTRAP)
        full = self.resources((*h.observation.BOOTSTRAP, 'game-api', 'gateway-api'))
        args = SimpleNamespace(custody=self.directory, meta=self.directory)
        h.write_json(self.directory / 'runtime.json', self.fixtures)
        self.config()
        calls = []
        def compose(directory, current, *argv, **kwargs):
            calls.append((argv, copy.deepcopy(current)))
            return json.dumps(model).encode() if argv[0] == 'config' else b''
        stack = ExitStack(); self.addCleanup(stack.close)
        for name, kwargs in {
            'load': {'return_value': (self.directory, record)}, 'verify_files': {'return_value': model},
            'verify_images': {}, 'heavy': {'return_value': nullcontext()}, 'port_free': {}, 'verify_running': {}, 'smoke': {},
            'inventory': {'side_effect': [{'container': [], 'network': [], 'volume': []}, bootstrap, bootstrap, full]},
            'compose': {'side_effect': compose},
            'sql': {'side_effect': [json.dumps(p) for p in (proofs if proofs is not None else [self.proof, self.proof])]},
        }.items(): stack.enter_context(patch.object(h, name, **kwargs))
        stack.enter_context(patch.object(h.shutil, 'disk_usage', side_effect=[SimpleNamespace(free=x) for x in
                            (free if free is not None else [8 * h.GIB, 7 * h.GIB, 6 * h.GIB])]))
        if observed:
            world = {'worldCount': 1, 'worldId': 160, 'tickSeconds': 120, 'serverId': 'generated-world-sid',
                     'serverIdAlias': None, 'games': [{'worldId': 160, 'serverId': 'generated-world-sid'}]}
            stack.enter_context(patch.object(h, 'observation_metadata', return_value=world))
            stack.enter_context(patch.object(h, 'observation_status', return_value={'paused': True,
                'serverTime': '2026-10-19T00:00:00Z', 'clock': {'worldId': 160, 'serverId': 'generated-world-sid', 'tickSeconds': 120}}))
            stack.enter_context(patch.object(h.time, 'time', return_value=1792368000.0))
        else:
            stack.enter_context(patch.object(h, 'observation_metadata', side_effect=AssertionError('unselected observation metadata')))
            stack.enter_context(patch.object(h, 'observation_status', side_effect=AssertionError('unselected observation HTTP')))
        return args, record, calls

    def test_native_bootstrap_uses_real_disk_guard_and_proves_grant_before_api(self):
        args, record, calls = self.startup()
        with patch.object(h, 'startup_disk_check', wraps=h.startup_disk_check) as disk: h.up(args)
        self.assertEqual(3, len(calls))
        self.assertEqual(h.observation.BOOTSTRAP, calls[1][0][-3:])
        self.assertIsNone(calls[1][1]['nativeWriter']['proof'])
        self.assertEqual(self.proof, calls[2][1]['nativeWriter']['proof'])
        self.assertEqual(self.proof, record['nativeWriter']['proof'])
        self.assertEqual('RUNNING', record['status'])
        self.assertEqual(2, h.sql.call_count)
        self.assertEqual(['afterObservationBootstrapFreeBytes', 'afterStartupFreeBytes'], [c.args[1] for c in disk.call_args_list])
        engine = json.loads((self.directory / 'compose.json').read_bytes())['services']['game-engine']
        self.assertEqual('file:' + n.TARGET, engine['environment'][n.LOCATION])
        self.assertNotIn('SPRING_APPLICATION_JSON', engine['environment'])

    def test_native_and_collector_bootstrap_keep_separate_proofs(self):
        args, record, calls = self.startup(observed=True)
        h.up(args)
        self.assertEqual(self.proof, record['nativeWriter']['proof'])
        self.assertEqual({'publicServerId', 'nativeServerId', 'worldId', 'tickSeconds'}, set(record['engineObservation']['binding']))
        self.assertEqual(3, len(calls))
        model = json.loads((self.directory / 'compose.json').read_bytes())
        self.assertIn('SPRING_APPLICATION_JSON', model['services']['game-api']['environment'])
        self.assertNotIn('SPRING_APPLICATION_JSON', model['services']['game-engine']['environment'])

    def test_missing_lease_and_handover_stop_before_api_with_starting_preserved(self):
        args, record, calls = self.startup(proofs=[{**self.proof, 'handoverValid': False}])
        with self.assertRaises(n.Refused): h.up(args)
        self.assertEqual(2, len(calls))
        self.assertEqual('STARTING', record['status'])
        self.assertIsNone(record['nativeWriter']['proof'])
        h.smoke.assert_not_called()
        self.assertFalse((self.directory / 'compose.json').exists())

    def test_missing_native_schema_never_becomes_a_legacy_fallback_for_opt_in(self):
        args, record, calls = self.startup()
        with patch.object(h, 'sql', side_effect=h.Refused('native schema unavailable')):
            with self.assertRaises(h.Refused): h.up(args)
        self.assertEqual(2, len(calls)); self.assertEqual('STARTING', record['status'])
        self.assertIsNone(record['nativeWriter']['proof']); h.smoke.assert_not_called()

    def test_lease_loss_during_full_startup_cannot_publish_running(self):
        args, record, calls = self.startup(proofs=[self.proof, {**self.proof, 'leaseAlive': False}])
        with self.assertRaises(n.Refused): h.up(args)
        self.assertEqual(3, len(calls))
        self.assertEqual('STARTING', record['status'])
        self.assertEqual(self.proof, record['nativeWriter']['proof'])
        h.smoke.assert_not_called()

    def test_native_bootstrap_below_3gib_does_not_query_a_grant(self):
        args, record, calls = self.startup(free=[8 * h.GIB, 3 * h.GIB - 1])
        with self.assertRaisesRegex(h.Refused, 'Startup reserve below 3 GiB'): h.up(args)
        self.assertEqual('STARTING', record['status'])
        self.assertEqual(2, len(calls))
        h.sql.assert_not_called(); h.smoke.assert_not_called()

    def test_smoke_requires_actual_live_proof_not_current_running_labels(self):
        record = self.selected_record(bound=True)
        with patch.object(h, 'sql', return_value=json.dumps(self.proof)): h.native_writer_smoke(self.directory, record)
        for proof in ({**self.proof, 'leaseAlive': False}, {**self.proof, 'handoverValid': False},
                      {'observationState': 'CURRENT', 'state': 'RUNNING'}):
            with patch.object(h, 'sql', return_value=json.dumps(proof)), self.assertRaises(n.Refused):
                h.native_writer_smoke(self.directory, record)

    def test_full_smoke_cannot_mark_pass_when_live_native_query_fails(self):
        for alive in (False, True):
            record = self.selected_record(bound=True); record['status'] = 'RUNNING'
            model = h.model_for(record, self.fixtures)
            opener = MagicMock()
            def response(url, **kwargs):
                ws = '/api/battle-ws/' in url or '/ws/battles/' in url
                result = MagicMock()
                result.__enter__.return_value.status = (401 if '/auth/me' in url else
                    404 if ws or '/d_pic/' in url or url.endswith('/game/') else 200)
                return result
            opener.open.side_effect = response
            with self.subTest(alive=alive), patch.object(h, 'load', return_value=(self.directory, record)), \
                 patch.object(h, 'verify_files', return_value=model), patch.object(h, 'verify_images'), \
                 patch.object(h, 'verify_running'), patch.object(h, 'inventory', return_value={}), \
                 patch.object(h, 'compose'), patch.object(h.ssl, 'create_default_context'), \
                 patch.object(h.urllib.request, 'build_opener', return_value=opener), \
                 patch.object(h, 'startup_disk_check'), patch.object(h, 'write_json') as write, \
                 patch.object(h, 'sql', side_effect=['160', '1', json.dumps({**self.proof, 'leaseAlive': alive})]), \
                 redirect_stdout(io.StringIO()):
                if alive:
                    h.smoke(SimpleNamespace(custody=self.directory))
                    self.assertEqual('SMOKE_PASSED', record['status'])
                else:
                    with self.assertRaises(n.Refused): h.smoke(SimpleNamespace(custody=self.directory))
                    write.assert_not_called(); self.assertEqual('RUNNING', record['status'])

    def test_cli_only_prepare_selects_native_and_rejects_nonboolean_or_later_commands(self):
        argv = ['harness.py', 'prepare', '--source', '/app', '--app-sha', 'a' * 40,
                '--docker-sha', 'b' * 40, '--custody', '/not-created']
        for flag in ([], ['--native-writer']):
            with patch.object(h.sys, 'argv', argv + flag), patch.object(h, 'prepare') as prepare:
                self.assertEqual(0, h.main()); self.assertIs(bool(flag), prepare.call_args.args[0].native_writer)
        for command in ('up', 'build', 'smoke', 'resume-startup', 'validate'):
            with patch.object(h.sys, 'argv', ['harness.py', command, '--custody', '/old', '--native-writer']), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit): h.main()
        with patch.object(h, 'source_archive') as source:
            with self.assertRaises(h.Refused): h.prepare(SimpleNamespace(native_writer='true'))
            source.assert_not_called()

    def test_prepare_creates_private_custody_public_one_property_file_and_existing_nonce_refuses(self):
        custody = self.directory / 'fresh'
        args = SimpleNamespace(source=self.directory / 'app', app_sha='a' * 40, docker_sha='b' * 40,
                               custody=custody, clone_source_custody=None, native_writer=True)
        def git(repo, *argv):
            if argv[0] == 'rev-parse': return (args.app_sha if repo == args.source else args.docker_sha).encode()
            path = argv[1].split(':', 1)[1]
            if repo == args.source: return self.source[path]
            if path == n.HELPER: return self.helper
            return b'public nginx'
        def unpack(archive, directory):
            directory.mkdir(mode=0o755)
            for path, data in self.source.items():
                destination = directory / path; destination.parent.mkdir(parents=True, exist_ok=True); destination.write_bytes(data)
        def openssl(argv, **kwargs):
            self.assertEqual('openssl', argv[0])
            if argv[1] == 'genpkey': Path(argv[argv.index('-out') + 1]).write_bytes(b'synthetic test bytes')
            if argv[1] == 'req':
                for flag in ('-keyout', '-out'): Path(argv[argv.index(flag) + 1]).write_bytes(b'synthetic test bytes')
            return b'synthetic test bytes'
        with patch.dict(os.environ, {'OPENSAMGUK_TASK_OWNER_SESSION': self.record['session']}), \
             patch.object(h, 'git', side_effect=git), patch.object(h, 'source_archive', return_value=b'public archive'), \
             patch.object(h, 'unpack_archive', side_effect=unpack), patch.object(h, 'inventory', return_value={}), \
             patch.object(h, 'assert_owned'), patch.object(h, 'port_free'), patch.object(h, 'run', side_effect=openssl), \
             patch.object(h, 'sql', side_effect=AssertionError('prepare must not query DB')), redirect_stdout(io.StringIO()):
            h.prepare(args)
            original = (custody / 'contract.json').read_bytes()
            record = json.loads(original)
            self.assertEqual(self.option, record['nativeWriter'])
            h.verify_files(custody, record)
            self.assertEqual(n.CONFIG, (custody / n.FILE).read_bytes())
            self.assertEqual(0o644, (custody / n.FILE).stat().st_mode & 0o777)
            self.assertEqual(0o700, custody.stat().st_mode & 0o777)
            with self.assertRaisesRegex(h.Refused, 'Custody already exists'): h.prepare(args)
            self.assertEqual(original, (custody / 'contract.json').read_bytes())
            record['dockerSha'] = 'c' * 40
            def old_git(repo, *argv):
                if argv[0] == 'show' and argv[1] == 'c' * 40 + ':' + n.HELPER: raise h.Refused('old revision has no native helper')
                return git(repo, *argv)
            with patch.object(h, 'git', side_effect=old_git), self.assertRaises(h.Refused): h.verify_files(custody, record)


if __name__ == '__main__':
    unittest.main()
