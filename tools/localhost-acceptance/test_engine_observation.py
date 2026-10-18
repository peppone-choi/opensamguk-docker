"""Pure mocked startup and public contract tests. Never contact Docker, HTTP or a database."""
import copy
from contextlib import ExitStack, nullcontext, redirect_stderr, redirect_stdout
import datetime
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

spec = importlib.util.spec_from_file_location('observation_harness', Path(__file__).with_name('harness.py'))
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)
o = h.observation


class EngineObservationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.directory = Path(temp.name).resolve()
        self.directory.chmod(0o700)
        self.record = {'nonce': '0123456789abcdef', 'session': '01a15100-e55a-7551-b704-52c7a0571fdf',
                       'project': 'osglha0123456789abcdef', 'serverId': 'lha0123456789abcdef',
                       'origin': h.ORIGIN, 'worldId': 160, 'generation': 0, 'custody': str(self.directory),
                       'appSha': 'a' * 40, 'dockerSha': 'b' * 40, 'status': 'BUILT', 'images': {}}
        self.fixtures = {key: 'synthetic-fixture' for key in ('DB_PASSWORD', 'JWT_PRIVATE_KEY', 'JWT_PUBLIC_KEY',
                         'INTERNAL_TOKEN', 'DEPLOYER_TOKEN', 'ADMIN_USERNAME', 'ADMIN_PASSWORD')}
        self.source = {path: '\n'.join(markers).encode() for path, markers in o.SOURCE.items()}
        self.option = {'schema': 1, 'sourcePins': o.source_pins(self.source.__getitem__), 'binding': None}
        self.record['engineObservation'] = copy.deepcopy(self.option)
        self.now = datetime.datetime(2026, 10, 19, tzinfo=datetime.timezone.utc).timestamp()
        self.world = {'worldCount': 1, 'worldId': 160, 'tickSeconds': 120, 'serverId': 'native-generated-42',
                      'serverIdAlias': None, 'games': [{'worldId': 160, 'serverId': 'native-generated-42'}]}
        self.status = {'paused': False, 'serverTime': '2026-10-19T00:00:00Z',
                       'clock': {'worldId': 160, 'serverId': 'native-generated-42', 'tickSeconds': 120}}
        self.bound = o.bind(self.record, self.world, self.status, self.now, 120)

    def bound_record(self):
        return {**self.record, 'engineObservation': copy.deepcopy(self.bound)}

    def public(self):
        return {'game': {'status': 'OPEN', 'turnTerm': 2, 'serverTime': '2026-10-19T00:00:00Z',
                         'turnLoop': {'state': 'STALLED', 'paused': False, 'observationState': 'CURRENT',
                                      'sourceObservedAt': '2026-10-19T00:00:00Z',
                                      'receivedAt': '2026-10-19T00:00:00Z'}}}

    def test_default_and_pending_leave_existing_model_exactly_unchanged(self):
        off = dict(self.record)
        del off['engineObservation']
        self.assertEqual(h.model_for(off, self.fixtures), h.model_for(self.record, self.fixtures))
        self.assertEqual({}, o.environment(off))
        self.assertEqual({}, o.environment(self.record))

    def test_bound_adds_only_exact_api_properties_using_native_not_public_sid(self):
        for tactical in (False, True):
            for paused in (False, True):
                record = {**self.record, 'profile': 'tactical' if tactical else 'standard', 'startupPaused': paused}
                if tactical:
                    import base64
                    fixtures = {**self.fixtures, h.TACTICAL_KEY: base64.b64encode(b'k' * 32).decode()}
                else:
                    fixtures = self.fixtures
                baseline = h.model_for(record, fixtures)
                record['engineObservation'] = self.bound
                model = h.model_for(record, fixtures)
                settings = json.loads(model['services']['game-api']['environment'].pop('SPRING_APPLICATION_JSON'))
                self.assertEqual({'turn-daemon-observation': {'enabled': True, 'origin': o.ORIGIN,
                    'server-id': self.world['serverId'], 'world-id': 160, 'tick-seconds': 120, **o.TIMING}}, settings)
                self.assertNotEqual(record['serverId'], settings['turn-daemon-observation']['server-id'])
                self.assertEqual(baseline, model)
        self.assertLess(o.TIMING['deadline-millis'], o.TIMING['poll-millis'])
        self.assertGreaterEqual(o.TIMING['max-age-millis'], o.TIMING['poll-millis'] + o.TIMING['deadline-millis'])

    def test_selection_types_and_public_world_tick_native_pin_tampering_refuse(self):
        bad_options = [None, False, True, {}, {**self.option, 'schema': True}, {**self.option, 'extra': True},
                       {**self.option, 'sourcePins': {}}, {**self.option, 'binding': {}}]
        for option in bad_options:
            with self.subTest(option=option), self.assertRaises(o.Refused):
                h.model_for({**self.record, 'engineObservation': option}, self.fixtures)
        for field, value in [('worldId', True), ('worldId', 1), ('publicServerId', 'foreign'),
                             ('nativeServerId', ''), ('nativeServerId', "x'; UPDATE world_state"),
                             ('tickSeconds', 0), ('tickSeconds', True), ('tickSeconds', 121)]:
            record = self.bound_record()
            record['engineObservation']['binding'][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(o.Refused):
                h.model_for(record, self.fixtures)

    def test_env_aliases_service_leaks_process_world_database_and_network_refuse(self):
        record = self.bound_record()
        model = h.model_for(record, self.fixtures)
        for service in model['services']:
            for alias in ('TURN_DAEMON_OBSERVATION_ENABLED', 'turn-daemon-observation.origin', 'SPRING_APPLICATION_JSON'):
                changed = copy.deepcopy(model)
                changed['services'][service].setdefault('environment', {})[alias] = 'foreign'
                with self.subTest(service=service, alias=alias), self.assertRaises((h.Refused, o.Refused)):
                    h.validate_model(changed, record)
        for service in ('game-api', 'game-engine'):
            for field, value in [('SERVER_ID', 'foreign'), ('OPENSAMGUK_WORLD_ID', '1'),
                                 ('SERVER_GENERATION', '1'), ('GAME_DATABASE_URL', 'jdbc:postgresql://foreign/game')]:
                changed = copy.deepcopy(model)
                changed['services'][service]['environment'][field] = value
                with self.subTest(field=field), self.assertRaises((h.Refused, o.Refused)):
                    h.validate_model(changed, record)
        for mutate in (lambda m: m['services']['game-engine']['networks']['local']['aliases'].append('foreign'),
                       lambda m: m['services']['game-engine']['depends_on'].update({'gateway-api': {'condition': 'service_healthy'}}),
                       lambda m: m['services']['game-engine']['environment'].update(RESET_TURNTERM='0')):
            changed = copy.deepcopy(model)
            mutate(changed)
            with self.assertRaises((h.Refused, o.Refused)): h.validate_model(changed, record)
        off = dict(record)
        del off['engineObservation']
        with self.assertRaises(o.Refused): h.validate_model(model, off)
        with self.assertRaises(o.Refused): h.validate_model(h.model_for(self.record, self.fixtures), record)

    def test_source_pins_cover_whole_files_and_missing_contract_refuses(self):
        changed = dict(self.source)
        path = next(iter(changed))
        changed[path] += b'\nchanged public source'
        self.assertNotEqual(self.option['sourcePins'], o.source_pins(changed.__getitem__))
        for path in self.source:
            bad = {**self.source, path: b'incompatible contract'}
            with self.subTest(path=path), self.assertRaises(o.Refused): o.source_pins(bad.__getitem__)

    def test_metadata_requires_one_process_world_and_one_matching_native_game(self):
        self.assertEqual(self.world['serverId'], self.bound['binding']['nativeServerId'])
        for field, value in [('worldCount', 0), ('worldCount', 2), ('worldCount', True), ('worldId', 1),
                             ('tickSeconds', 0), ('tickSeconds', 121), ('tickSeconds', True), ('serverId', None),
                             ('serverIdAlias', 'foreign'), ('games', []), ('games', self.world['games'] * 2),
                             ('games', [{'worldId': 1, 'serverId': self.world['serverId']}]),
                             ('games', [{'worldId': 160, 'serverId': 'foreign'}])]:
            with self.subTest(field=field, value=value), self.assertRaises(o.Refused):
                o.bind(self.record, {**self.world, field: value}, self.status, self.now, 120)
        with self.assertRaises(o.Refused): o.bind(self.bound_record(), self.world, self.status, self.now, 120)

    def test_status_foreign_public_sid_wrongworld_tick_missing_stale_future_refuse(self):
        for clock in ({**self.status['clock'], 'serverId': self.record['serverId']},
                      {**self.status['clock'], 'worldId': 1}, {**self.status['clock'], 'worldId': True},
                      {**self.status['clock'], 'tickSeconds': 121}, None):
            with self.subTest(clock=clock), self.assertRaises(o.Refused):
                o.bind(self.record, self.world, {**self.status, 'clock': clock}, self.now, 120)
        for delta in (-0.001, 5.001):
            with self.assertRaises(o.Refused):
                o.bind(self.record, self.world, self.status, self.now + delta, 120)
        o.bind(self.record, self.world, self.status, self.now + 5, 120)
        for field, value in [('paused', None), ('paused', 'false'), ('serverTime', None), ('serverTime', '2026-10-19T00:00:00')]:
            with self.subTest(field=field), self.assertRaises(o.Refused):
                o.bind(self.record, self.world, {**self.status, field: value}, self.now, 120)

    def test_public_current_does_not_invent_running_and_unknown_stale_invalid_refuse(self):
        payload = self.public()
        for state, paused in [('RUNNING', False), ('WAITING', False), ('CATCHING_UP', False), ('PAUSED', True), ('STALLED', False)]:
            payload['game']['turnLoop'].update(state=state, paused=paused)
            o.validate_public(payload, self.bound['binding'], self.now)
        for field, value in [('observationState', 'MISSING'), ('observationState', 'EXPIRED'), ('observationState', 'INVALID'),
                             ('state', 'UNKNOWN'), ('state', 'RUNNING'), ('paused', None),
                             ('sourceObservedAt', '2026-10-18T23:59:54Z'), ('receivedAt', '2026-10-19T00:00:01Z')]:
            changed = copy.deepcopy(payload)
            # Last valid state is STALLED/false. RUNNING is tested as an inconsistent paused state.
            if field == 'state' and value == 'RUNNING': changed['game']['turnLoop']['paused'] = True
            changed['game']['turnLoop'][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(o.Refused):
                o.validate_public(changed, self.bound['binding'], self.now)

    def test_json_duplicate_oversize_and_non_json_refuse(self):
        for raw in (b'{"clock":{},"clock":{}}', b'not JSON', b'x' * 65537, b'\xff'):
            with self.subTest(raw=raw[:20]), self.assertRaises(o.Refused): o.decode(raw)

    def test_metadata_query_is_readonly_and_projects_no_env_accounts_or_full_meta(self):
        with patch.object(h, 'sql', return_value=json.dumps(self.world)) as sql:
            self.assertEqual(self.world, h.observation_metadata(self.directory, self.record))
        query = sql.call_args.args[-1]
        self.assertIn('BEGIN READ ONLY', query)
        self.assertIn('WHERE w.id=160', query)
        self.assertIn('WHERE g.world_id=w.id', query)
        self.assertNotIn('SELECT *', query)
        for word in ('password', 'config', 'env', 'UPDATE', 'general_owner'): self.assertNotIn(word, query)

    def test_status_probe_has_exact_internal_get_no_tokens_redirect_or_public_port(self):
        with self.assertRaisesRegex(h.Refused, 'redirect refused'):
            h.ObservationNoRedirect().redirect_request(None, None, 302, '', {}, 'https://foreign.invalid')
        for service, origin in (('game-engine', 'http://127.0.0.1:8082'), ('game-api', o.ORIGIN)):
            with patch.object(h, 'compose', return_value=json.dumps(self.status).encode() + b'\nSTATUS:200') as compose:
                self.assertEqual(self.status, h.observation_status(self.directory, self.record, service, origin))
            argv = compose.call_args.args[2:]
            self.assertIn(service, argv)
            self.assertEqual(origin + '/admin/turn-daemon/status', argv[-1])
            for forbidden in ('-L', '-H', '--header', '--insecure', '-k', '-X'): self.assertNotIn(forbidden, argv)
        for raw in (b'{}\nSTATUS:302', b'{}\nSTATUS:401', b'{}', b'{"paused":true,"paused":false}\nSTATUS:200'):
            with patch.object(h, 'compose', return_value=raw), self.assertRaises((h.Refused, o.Refused)):
                h.observation_status(self.directory, self.record, 'game-api', o.ORIGIN)
        with patch.object(h, 'compose') as compose, self.assertRaises(h.Refused):
            h.observation_status(self.directory, self.record, 'game-api', 'http://foreign:8082')
        compose.assert_not_called()

    def resources(self, services):
        rows = []
        for service in services:
            name = self.record['project'] + '-' + service + '-1'
            rows.append({'Id': 'id-' + service, 'Name': name, 'Config': {'Labels': {'com.docker.compose.service': service}},
                         'NetworkSettings': {'Networks': {self.record['project'] + '_local': {
                             'Aliases': [name, service, 's' + self.record['serverId'] + '-' + service]}}}})
        return {'container': rows, 'network': [{'Id': 'owned-network'}],
                'volume': [{'Name': self.record['project'] + '_game-pgdata'}, {'Name': self.record['project'] + '_game-redisdata'}]}

    def test_runtime_engine_api_aliases_are_unique_even_without_tactical_profile(self):
        resources = self.resources(o.BOOTSTRAP)
        h.verify_observation_network(self.record, resources)
        resources = self.resources((*o.BOOTSTRAP, 'game-api'))
        h.verify_observation_network(self.record, resources)
        for endpoint in ('game-engine', 'game-api'):
            for wrong in ('foreign', endpoint, 's' + self.record['serverId'] + '-' + endpoint):
                bad = copy.deepcopy(resources)
                bad['container'][0]['NetworkSettings']['Networks'][self.record['project'] + '_local']['Aliases'].append(wrong)
                if wrong == 'foreign':
                    row = next(r for r in bad['container'] if r['Config']['Labels']['com.docker.compose.service'] == endpoint)
                    row['NetworkSettings']['Networks'][self.record['project'] + '_local']['Aliases'].pop()
                with self.subTest(endpoint=endpoint, wrong=wrong), self.assertRaises(h.Refused):
                    h.verify_observation_network(self.record, bad)

    def startup(self, invalid=False, changed_resources=False, disk_free=None):
        model = h.model_for(self.record, self.fixtures)
        bootstrap = self.resources(o.BOOTSTRAP)
        full = self.resources((*o.BOOTSTRAP, 'game-api', 'gateway-api'))
        if changed_resources: full['container'][0]['Id'] += '-changed'
        args = SimpleNamespace(custody=self.directory, meta=self.directory)
        h.write_json(self.directory / 'runtime.json', self.fixtures)
        calls = []
        def compose(directory, record, *argv, **kwargs):
            calls.append((argv, copy.deepcopy(record)))
            if argv[0] == 'config': return json.dumps(model).encode()
            return b''
        stack = ExitStack()
        self.addCleanup(stack.close)
        for name, kwargs in {
            'load': {'return_value': (self.directory, self.record)}, 'verify_files': {'return_value': model},
            'verify_images': {}, 'heavy': {'return_value': nullcontext()},
            'inventory': {'side_effect': [{'container': [], 'network': [], 'volume': []}, bootstrap, bootstrap, full]},
            'port_free': {}, 'verify_running': {}, 'smoke': {},
            'observation_metadata': {'return_value': self.world},
            'observation_status': {'return_value': {**self.status, 'clock': None} if invalid else self.status},
            'compose': {'side_effect': compose},
        }.items(): stack.enter_context(patch.object(h, name, **kwargs))
        # Keep the real stage allowlist, reserve check and report writes in every startup test.
        free = disk_free if disk_free is not None else [8 * h.GIB, 7 * h.GIB, 6 * h.GIB]
        stack.enter_context(patch.object(h.shutil, 'disk_usage', side_effect=[SimpleNamespace(free=n) for n in free]))
        stack.enter_context(patch.object(h.time, 'time', return_value=self.now))
        return args, calls

    def test_startup_binds_before_any_api_start_and_preserves_bootstrap_ids(self):
        args, calls = self.startup()
        with patch.object(h, 'startup_disk_check', wraps=h.startup_disk_check) as check:
            h.up(args)
        self.assertEqual(['afterObservationBootstrapFreeBytes', 'afterStartupFreeBytes'],
                         [call.args[1] for call in check.call_args_list])
        report = json.loads((self.directory / 'startup-disk.json').read_bytes())
        self.assertEqual(8 * h.GIB, report['startupFreeBytes'])
        self.assertEqual(6 * h.GIB, report['afterStartupFreeBytes'])
        self.assertEqual(2 * h.GIB, report['consumedBytes'])
        self.assertEqual(3, len(calls))
        self.assertEqual(o.BOOTSTRAP, calls[1][0][-3:])
        self.assertIsNone(calls[1][1]['engineObservation']['binding'])
        self.assertEqual(self.bound['binding'], calls[2][1]['engineObservation']['binding'])
        self.assertNotIn('game-api', calls[1][0])
        for argv, _ in calls[1:]:
            self.assertIn('--no-build', argv)
            self.assertEqual('never', argv[argv.index('--pull') + 1])
        model = json.loads((self.directory / 'compose.json').read_bytes())
        self.assertEqual(o.environment(self.record), {k: v for k, v in model['services']['game-api']['environment'].items() if o.reserved(k)})
        self.assertEqual(h.sha((self.directory / 'compose.json').read_bytes()), self.record['configSha256'])
        self.assertEqual('RUNNING', self.record['status'])
        self.assertEqual(0o600, (self.directory / 'compose.json').stat().st_mode & 0o777)

    def test_bootstrap_disk_below_3gib_preserves_failure_and_never_reads_metadata_or_starts_api(self):
        args, calls = self.startup(disk_free=[8 * h.GIB, 3 * h.GIB - 1])
        with self.assertRaisesRegex(h.Refused, 'Startup reserve below 3 GiB'): h.up(args)
        self.assertEqual(2, len(calls))
        self.assertEqual(o.BOOTSTRAP, calls[1][0][-3:])
        self.assertEqual('STARTING', self.record['status'])
        self.assertIsNone(self.record['engineObservation']['binding'])
        h.observation_metadata.assert_not_called()
        h.observation_status.assert_not_called()
        h.smoke.assert_not_called()
        self.assertFalse((self.directory / 'compose.json').exists())
        report = json.loads((self.directory / 'startup-disk.json').read_bytes())
        self.assertEqual(3 * h.GIB - 1, report['afterObservationBootstrapFreeBytes'])
        self.assertEqual(5 * h.GIB + 1, report['consumedBytes'])
        self.assertEqual(0o600, (self.directory / 'startup-disk.json').stat().st_mode & 0o777)

    def test_bootstrap_and_full_startup_accept_exact_3gib_reserve(self):
        args, calls = self.startup(disk_free=[8 * h.GIB, 3 * h.GIB, 3 * h.GIB])
        h.up(args)
        self.assertEqual(3, len(calls))
        self.assertEqual('RUNNING', self.record['status'])

    def test_unknown_disk_stage_refuses_before_measurement_or_report_mutation(self):
        path = self.directory / 'startup-disk.json'
        h.write_json(path, {'startupFreeBytes': 8 * h.GIB})
        original = path.read_bytes()
        for stage in ('afterObservationBootstrap', 'afterStartupFreeByte', '', None):
            with self.subTest(stage=stage), patch.object(h.shutil, 'disk_usage') as disk:
                with self.assertRaisesRegex(h.Refused, 'Unknown disk observation'):
                    h.startup_disk_check(self.directory, stage, 8 * h.GIB)
                disk.assert_not_called()
                self.assertEqual(original, path.read_bytes())

    def test_invalid_bootstrap_never_starts_api_or_publishes_running(self):
        args, calls = self.startup(invalid=True)
        with self.assertRaises(o.Refused): h.up(args)
        self.assertEqual(2, len(calls))
        self.assertEqual('STARTING', self.record['status'])
        self.assertIsNone(self.record['engineObservation']['binding'])
        h.smoke.assert_not_called()

    def test_full_startup_resource_replacement_cannot_publish_running(self):
        args, _ = self.startup(changed_resources=True)
        with self.assertRaisesRegex(h.Refused, 'Bootstrap resources changed'): h.up(args)
        self.assertEqual('STARTING', self.record['status'])
        h.smoke.assert_not_called()

    def test_smoke_requires_internal_and_public_current_observation_and_changed_metadata_refuses(self):
        record = self.bound_record()
        opener = MagicMock()
        response = opener.open.return_value.__enter__.return_value
        response.status = 200
        response.read.return_value = json.dumps(self.public()).encode()
        model = h.model_for(record, self.fixtures)
        with patch.object(h, 'observation_metadata', return_value=self.world), \
             patch.object(h, 'observation_status', return_value=self.status) as status, \
             patch.object(h.time, 'time', return_value=self.now):
            h.observation_smoke(self.directory, record, model, opener)
        self.assertEqual(('game-api', o.ORIGIN), status.call_args.args[-2:])
        self.assertEqual(h.ORIGIN + '/api/server-basic-info/' + record['serverId'], opener.open.call_args.args[0])
        for field, value in [('serverId', 'different-native'), ('worldId', 1)]:
            with patch.object(h, 'observation_metadata', return_value={**self.world, field: value}), \
                 patch.object(h, 'observation_status') as status, self.assertRaises((h.Refused, o.Refused)):
                h.observation_smoke(self.directory, record, model, opener)
            status.assert_not_called()
        off = dict(record)
        del off['engineObservation']
        with patch.object(h, 'compose', side_effect=AssertionError('default performed runtime I/O')):
            h.observation_smoke(self.directory, off, model, opener)

    def test_prepare_cli_explicit_boolean_and_unknown_flag_refuse_before_dependencies(self):
        argv = ['harness.py', 'prepare', '--source', '/app', '--app-sha', 'a' * 40,
                '--docker-sha', 'b' * 40, '--custody', '/not-created']
        for flag in ([], ['--engine-observation']):
            with patch.object(h.sys, 'argv', argv + flag), patch.object(h, 'prepare') as prepare:
                self.assertEqual(0, h.main())
                self.assertIs(bool(flag), prepare.call_args.args[0].engine_observation)
        with patch.object(h.sys, 'argv', argv + ['--engine-observ']), redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit): h.main()
        with patch.object(h, 'source_archive') as source, patch.object(h, 'run') as run:
            with self.assertRaises(h.Refused): h.prepare(SimpleNamespace(engine_observation='true'))
            source.assert_not_called(); run.assert_not_called()

    def test_smoke_never_publishes_pass_for_unknown_and_installs_redirect_guard_only_when_selected(self):
        for enabled, current in ((False, False), (True, False), (True, True)):
            record = self.bound_record()
            if not enabled: del record['engineObservation']
            record['status'] = 'RUNNING'
            model = h.model_for(record, self.fixtures)
            payload = self.public()
            if not current: payload['game']['turnLoop'].update(state='UNKNOWN', observationState='MISSING', paused=None)
            opener = MagicMock()
            def response(url, **kwargs):
                ws = '/api/battle-ws/' in url or '/ws/battles/' in url
                status = 401 if '/auth/me' in url else 404 if ws or '/d_pic/' in url or url.endswith('/game/') else 200
                result = MagicMock()
                result.__enter__.return_value.status = status
                result.__enter__.return_value.read.return_value = json.dumps(payload).encode()
                return result
            opener.open.side_effect = response
            with self.subTest(enabled=enabled, current=current), \
                 patch.object(h, 'load', return_value=(self.directory, record)), \
                 patch.object(h, 'verify_files', return_value=model), patch.object(h, 'verify_images'), \
                 patch.object(h, 'verify_running'), patch.object(h, 'inventory', return_value={}), patch.object(h, 'compose'), \
                 patch.object(h.ssl, 'create_default_context'), \
                 patch.object(h.urllib.request, 'build_opener', return_value=opener) as build, \
                 patch.object(h, 'sql', side_effect=['160', '1']), patch.object(h, 'startup_disk_check'), \
                 patch.object(h, 'observation_metadata', return_value=self.world), \
                 patch.object(h, 'observation_status', return_value=self.status), \
                 patch.object(h.time, 'time', return_value=self.now), patch.object(h, 'write_json') as write, \
                 redirect_stdout(io.StringIO()):
                if enabled and not current:
                    with self.assertRaises(o.Refused): h.smoke(SimpleNamespace(custody=self.directory))
                    write.assert_not_called()
                    self.assertEqual('RUNNING', record['status'])
                else:
                    h.smoke(SimpleNamespace(custody=self.directory))
                    self.assertEqual('SMOKE_PASSED', record['status'])
                self.assertEqual(enabled, any(isinstance(handler, h.ObservationNoRedirect) for handler in build.call_args.args))

    def test_prepare_records_source_pins_but_does_not_enable_unbound_collector(self):
        custody = self.directory / 'fresh'
        args = SimpleNamespace(source=self.directory / 'app', app_sha='a' * 40, docker_sha='b' * 40,
                               custody=custody, clone_source_custody=None, engine_observation=True)
        def git(repo, *argv):
            if argv[0] == 'rev-parse': return (args.app_sha if repo == args.source else args.docker_sha).encode()
            if repo == args.source: return self.source[argv[1].split(':', 1)[1]]
            return b'public nginx'
        def unpack(archive, directory):
            directory.mkdir(mode=0o755)
            for path, data in self.source.items():
                destination = directory / path
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(data)
        def openssl(argv, **kwargs):
            self.assertEqual('openssl', argv[0])
            if argv[1] == 'genpkey': Path(argv[argv.index('-out') + 1]).write_bytes(b'synthetic bytes')
            if argv[1] == 'req':
                for flag in ('-keyout', '-out'): Path(argv[argv.index(flag) + 1]).write_bytes(b'synthetic bytes')
            return b'synthetic bytes'
        with patch.dict(os.environ, {'OPENSAMGUK_TASK_OWNER_SESSION': self.record['session']}), \
             patch.object(h, 'git', side_effect=git), patch.object(h, 'source_archive', return_value=b'public archive'), \
             patch.object(h, 'unpack_archive', side_effect=unpack), patch.object(h, 'inventory', return_value={}), \
             patch.object(h, 'assert_owned'), patch.object(h, 'port_free'), patch.object(h, 'run', side_effect=openssl), \
             redirect_stdout(io.StringIO()):
            h.prepare(args)
            record = json.loads((custody / 'contract.json').read_bytes())
            self.assertEqual(self.option, record['engineObservation'])
            model = h.verify_files(custody, record)
            self.assertNotIn('SPRING_APPLICATION_JSON', model['services']['game-api']['environment'])
            source_path = custody / 'source' / next(iter(self.source))
            source_path.write_bytes(source_path.read_bytes() + b'\nsource drift')
            # Even an updated generic tree hash cannot detach this opt-in from its original contract pins.
            record['sourceTreeSha256'] = h.tree_hash(custody / 'source')
            with self.assertRaisesRegex(h.Refused, 'source pins changed'): h.verify_files(custody, record)
        self.assertEqual(0o600, (custody / 'contract.json').stat().st_mode & 0o777)

    def test_bootstrap_verifier_excludes_any_early_api_even_when_health_is_green(self):
        model = h.model_for(self.record, self.fixtures)
        resources = self.resources((*o.BOOTSTRAP, 'game-api'))
        with patch.object(h, 'assert_owned'), self.assertRaisesRegex(h.Refused, 'Incomplete stack'):
            h.verify_running(self.record, resources, model, bootstrap=True)
        off = dict(self.record)
        del off['engineObservation']
        with patch.object(h, 'assert_owned'), self.assertRaisesRegex(h.Refused, 'Unselected bootstrap'):
            h.verify_running(off, self.resources(o.BOOTSTRAP), model, bootstrap=True)


if __name__ == '__main__':
    unittest.main()
