"""Synthetic public fixtures and mocked RPCs only; no Docker, keys or runtime writes."""
import base64
from contextlib import redirect_stderr, redirect_stdout
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

SPEC = importlib.util.spec_from_file_location('startup_pause_harness', Path(__file__).with_name('harness.py'))
h = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(h)


class StartupPauseTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.record = {'nonce': '0123456789abcdef', 'session': '01a14994-f8a1-7282-9f45-f9d3c5390cee',
                       'project': 'osglha0123456789abcdef', 'serverId': 'lha0123456789abcdef',
                       'origin': h.ORIGIN, 'worldId': 160, 'generation': 0, 'custody': '/public-custody',
                       'appSha': 'a' * 40, 'dockerSha': 'b' * 40, 'images': {}}
        self.fixtures = {key: 'synthetic-fixture' for key in ('DB_PASSWORD', 'JWT_PRIVATE_KEY', 'JWT_PUBLIC_KEY',
                         'INTERNAL_TOKEN', 'DEPLOYER_TOKEN', 'ADMIN_USERNAME', 'ADMIN_PASSWORD')}

    def selected(self, tactical=False, mapped=False):
        record, fixtures = copy.deepcopy(self.record), dict(self.fixtures)
        if tactical:
            record['profile'] = 'tactical'
            fixtures[h.TACTICAL_KEY] = base64.b64encode(b'k' * 32).decode()
        if mapped:
            record['topdown'] = {'bakeId': 'd' * 64, 'manifestSha256': 'e' * 64, 'sourcePins': {}}
        return record, fixtures

    def payload(self):
        return dict(state='paused', running=False, paused=True, loopAlive=True, serviceMaterialized=True,
                    recoveryMode='READY', recoveryReady=True, autoStartEnabled=True,
                    clock={'worldId': 160}, lastTickStartedAt=None, lastTickCompletedAt=None)

    def test_default_model_bytes_match_exact_d0a4_for_all_existing_combinations(self):
        # Captured from unmodified d0a4 with these same deterministic synthetic fixtures.
        hashes = {(False, False): '32faf0a4fc268d7317cc9b1587d62daeea51dd13cc2710902d87cb10ecb025ef',
                  (False, True): '23c6a76743d23b4ddc6d8b38703944c2293ba6752c7bec57ba08b60cbdc0d5f7',
                  (True, False): 'e4645db1abbf0b2be5c59f06cc1b54546d12182cdd0e2e3a8e4b4182ee187e33',
                  (True, True): '5804cccf482bb9b3f8c71c9e3727437107d0091d1c59dfff7656116180b8b504'}
        for (tactical, mapped), expected in hashes.items():
            with self.subTest(tactical=tactical, mapped=mapped):
                record, fixtures = self.selected(tactical, mapped)
                model = h.model_for(record, fixtures)
                self.assertEqual(expected, h.sha((json.dumps(model, indent=2) + '\n').encode()))
                self.assertEqual(model, h.model_for({**record, 'startupPaused': False}, fixtures))
                self.assertNotIn('startupPaused', record)

    def test_opt_in_changes_only_exact_engine_environment_and_keeps_map_and_tactical(self):
        self.assertEqual('OPENSAMGUK_DAEMON_STARTUP_PAUSED', h.STARTUP_PAUSE_ENV)
        for tactical in (False, True):
            for mapped in (False, True):
                record, fixtures = self.selected(tactical, mapped)
                baseline = h.model_for(record, fixtures)
                selected = h.model_for({**record, 'startupPaused': True}, fixtures)
                self.assertEqual('true', selected['services']['game-engine']['environment'].pop(h.STARTUP_PAUSE_ENV))
                self.assertEqual(baseline, selected)

    def test_record_types_unknown_aliases_and_false_contract_environment_mismatch_refuse(self):
        for value in ('true', 'false', 1, 0, None, [], {}):
            with self.subTest(value=value), self.assertRaises(h.Refused):
                h.model_for({**self.record, 'startupPaused': value}, self.fixtures)
        for alias in ('startup_paused', 'engineStartupPaused', 'startupPause', 'STARTUP_PAUSED', 'startupPausedExtra'):
            with self.subTest(alias=alias), self.assertRaises(h.Refused):
                h.model_for({**self.record, alias: True}, self.fixtures)
        record = {**self.record, 'startupPaused': True}
        selected = h.model_for(record, self.fixtures)
        for false_record in (self.record, {**self.record, 'startupPaused': False}):
            with self.assertRaises(h.Refused): h.validate_model(selected, false_record)
        with self.assertRaises(h.Refused): h.validate_model(h.model_for(self.record, self.fixtures), record)

    def test_flag_removal_wrong_values_unknown_keys_and_all_other_service_leaks_refuse(self):
        record = {**self.record, 'startupPaused': True}
        selected = h.model_for(record, self.fixtures)
        for value in (False, True, 'false', 'TRUE', '1', '', None):
            bad = copy.deepcopy(selected)
            bad['services']['game-engine']['environment'][h.STARTUP_PAUSE_ENV] = value
            with self.subTest(value=value), self.assertRaises(h.Refused): h.validate_model(bad, record)
        for service in selected['services']:
            if service == 'game-engine': continue
            bad = copy.deepcopy(selected)
            bad['services'][service].setdefault('environment', {})[h.STARTUP_PAUSE_ENV] = 'true'
            with self.subTest(service=service), self.assertRaises(h.Refused): h.validate_model(bad, record)
        for alias in ('TURN_DAEMON_STARTUP_PAUSED', 'OPENSAMGUK_DAEMON_STARTUP_PAUSE', 'opensamguk.daemon.startup-paused'):
            bad = copy.deepcopy(selected)
            bad['services']['game-engine']['environment'][alias] = 'true'
            with self.subTest(alias=alias), self.assertRaises(h.Refused): h.validate_model(bad, record)

    def test_prepare_opt_in_records_boolean_and_default_omits_contract_field(self):
        records = []
        for enabled in (False, True):
            custody = self.root / ('selected' if enabled else 'default')
            args = SimpleNamespace(source=self.root / 'app', app_sha='a' * 40, docker_sha='b' * 40,
                                   custody=custody, clone_source_custody=None, startup_paused=enabled)
            def git(repo, *argv):
                if argv[0] == 'rev-parse': return (args.app_sha if repo == args.source else args.docker_sha).encode()
                return b'public nginx'
            def unpack(archive, directory):
                directory.mkdir(mode=0o755)
                (directory / 'public.txt').write_bytes(b'public source')
            def synthetic_openssl(argv, **kwargs):
                self.assertEqual('openssl', argv[0])
                if argv[1] == 'genpkey': Path(argv[argv.index('-out') + 1]).write_bytes(b'synthetic test bytes')
                if argv[1] == 'req':
                    for flag in ('-keyout', '-out'): Path(argv[argv.index(flag) + 1]).write_bytes(b'synthetic test bytes')
                return b'synthetic test bytes'
            with patch.dict(os.environ, {'OPENSAMGUK_TASK_OWNER_SESSION': self.record['session']}), \
                 patch.object(h, 'git', side_effect=git), patch.object(h, 'source_archive', return_value=b'archive'), \
                 patch.object(h, 'unpack_archive', side_effect=unpack), patch.object(h, 'inventory', return_value={}), \
                 patch.object(h, 'assert_owned'), patch.object(h, 'port_free'), patch.object(h, 'run', side_effect=synthetic_openssl), \
                 patch.object(h.secrets, 'token_hex', return_value='0123456789abcdef'), \
                 patch.object(h.secrets, 'token_urlsafe', return_value='synthetic-fixture'), redirect_stdout(io.StringIO()):
                h.prepare(args)
                record = json.loads((custody / 'contract.json').read_bytes())
                model = h.verify_files(custody, record)
            records.append(record)
            self.assertEqual(enabled, record.get('startupPaused', False))
            self.assertEqual({'OPENSAMGUK_DAEMON_STARTUP_PAUSED': 'true'} if enabled else {},
                             {k: v for k, v in model['services']['game-engine']['environment'].items() if h.startup_pause_key(k)})
            self.assertEqual(0o600, (custody / 'contract.json').stat().st_mode & 0o777)
        self.assertNotIn('startupPaused', records[0])
        records[1].pop('startupPaused')
        # Fresh paths/config/certs have their own identities; optional record selection is the sole new field.
        self.assertEqual(set(records[0]), set(records[1]))

    def test_cli_flag_is_explicit_and_unknown_flag_or_nonboolean_input_fails_early(self):
        argv = ['harness.py', 'prepare', '--source', '/app', '--app-sha', 'a' * 40,
                '--docker-sha', 'b' * 40, '--custody', '/not-created']
        for flag in ([], ['--startup-paused']):
            with patch.object(h.sys, 'argv', argv + flag), patch.object(h, 'prepare') as prepare:
                self.assertEqual(0, h.main())
                self.assertIs(bool(flag), prepare.call_args.args[0].startup_paused)
        with patch.object(h.sys, 'argv', argv + ['--startup-pause']), redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit): h.main()
        with patch.object(h, 'source_archive') as source, patch.object(h, 'run') as run:
            with self.assertRaises(h.Refused): h.prepare(SimpleNamespace(startup_paused='true'))
            source.assert_not_called(); run.assert_not_called()

    def test_status_requires_real_paused_ready_materialized_loop_and_exact_world(self):
        h.validate_startup_pause_status(self.payload(), self.record)
        for key, value in [('paused', False), ('running', True), ('state', 'running'), ('loopAlive', False),
                           ('serviceMaterialized', False), ('recoveryReady', False), ('recoveryMode', 'FLUSH_RETRY'),
                           ('autoStartEnabled', False), ('paused', 1), ('clock', None),
                           ('clock', {'worldId': 1}), ('clock', {'worldId': '160'})]:
            bad = self.payload(); bad[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(h.Refused):
                h.validate_startup_pause_status(bad, self.record)

    def test_status_refuses_tick_in_flight_missing_or_invalid_completion(self):
        started = '2026-10-18T10:00:00Z'
        for start, end in [(started, None), (None, started), (started, '2026-10-18T09:59:59Z'),
                           (started, 'invalid'), (started, '2026-10-18T10:00:01')]:
            payload = {**self.payload(), 'lastTickStartedAt': start, 'lastTickCompletedAt': end}
            with self.subTest(start=start, end=end), self.assertRaises(h.Refused):
                h.validate_startup_pause_status(payload, self.record)
        h.validate_startup_pause_status({**self.payload(), 'lastTickStartedAt': started,
                                       'lastTickCompletedAt': '2026-10-18T10:00:01Z'}, self.record)

    def test_probe_is_owned_engine_get_only_and_default_performs_no_rpc(self):
        record = {**self.record, 'startupPaused': True}
        with patch.object(h, 'compose', return_value=json.dumps(self.payload()).encode() + b'\nSTATUS:200') as rpc:
            h.startup_pause_smoke(self.root, record)
            args = rpc.call_args.args
            self.assertEqual(('exec', '-T', 'game-engine', 'curl'), args[2:6])
            self.assertEqual('http://127.0.0.1:8082/admin/turn-daemon/status', args[-1])
            self.assertNotIn('POST', args)
            rpc.reset_mock(); h.startup_pause_smoke(self.root, self.record); rpc.assert_not_called()

    def test_probe_rejects_redirect_errors_invalid_oversize_and_duplicate_status(self):
        record = {**self.record, 'startupPaused': True}
        good = json.dumps(self.payload()).encode()
        cases = [good + b'\nSTATUS:301', good + b'\nSTATUS:401', good, b'invalid\nSTATUS:200',
                 b' ' * 16385 + b'\nSTATUS:200', b'{"paused":false,' + good[1:] + b'\nSTATUS:200']
        for raw in cases:
            with patch.object(h, 'compose', return_value=raw), self.assertRaises(h.Refused):
                h.startup_pause_smoke(self.root, record)

    def test_full_smoke_preserves_tactical_map_checks_and_cannot_pass_unpaused(self):
        base, fixtures = self.selected(tactical=True, mapped=True)
        base.update(startupPaused=True, status='RUNNING')
        model = h.model_for(base, fixtures)
        for paused in (True, False):
            record = copy.deepcopy(base)
            payload = self.payload(); payload['paused'] = paused
            opener = MagicMock()
            statuses = (200, 401, 403, 404, 404, 404, 200)
            responses = [MagicMock() for _ in statuses]
            for response, status in zip(responses, statuses): response.__enter__.return_value.status = status
            opener.open.side_effect = responses
            def rpc(directory, rec, *args, **kwargs):
                return b'' if args[2] == 'nginx' else json.dumps(payload).encode() + b'\nSTATUS:200'
            with patch.object(h, 'load', return_value=(self.root, record)), patch.object(h, 'verify_files', return_value=model), \
                 patch.object(h, 'verify_images'), patch.object(h, 'inventory'), patch.object(h, 'verify_running'), \
                 patch.object(h, 'compose', side_effect=rpc), patch.object(h.ssl, 'create_default_context'), \
                 patch.object(h.urllib.request, 'build_opener', return_value=opener), patch.object(h, 'sql', side_effect=['160', '1']), \
                 patch.object(h, 'tactical_smoke') as tactical, patch.object(h.topdown, 'smoke') as mapped, \
                 patch.object(h, 'startup_disk_check'), patch.object(h, 'write_json') as written, redirect_stdout(io.StringIO()):
                if paused:
                    h.smoke(SimpleNamespace(custody=self.root)); self.assertEqual('SMOKE_PASSED', record['status'])
                else:
                    with self.assertRaises(h.Refused): h.smoke(SimpleNamespace(custody=self.root))
                    self.assertEqual('RUNNING', record['status']); written.assert_not_called()
                tactical.assert_called_once(); mapped.assert_called_once()


if __name__ == '__main__':
    unittest.main()
