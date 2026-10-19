"""Combined startup/tactical/map fixtures. Every runtime operation uses the stateful fake CLI."""
import copy
import unittest

import recovery as r
import test_topdown_recovery as mapped
import test_runtime_binding as routed
from storage import read, write, digest


class StartupRecoveryTests(unittest.TestCase):
    def setUp(self):
        mapped.SelectedRecoveryTests.setUp(self)
        routed.RuntimeBindingTests.reviewed_route_fixture(self)

    git = routed.RuntimeBindingTests.git

    backup = mapped.SelectedRecoveryTests.backup
    def version(self):
        self.version_sources = dict(self.map.sources)
        return routed.RuntimeBindingTests.version(self)

    def test_combined_A_B_A_keeps_pause_profile_private_map_and_environment_without_resume(self):
        self.backup(); version = self.version()
        self.assertIs(read(version)['startupPaused'], True)
        self.assertEqual(read(version)['profile'], 'tactical')
        b, a = self.root / 'B', self.root / 'A-return'
        self.engine.restore(self.bundle, b, version)
        self.engine.observe(b); self.engine.stop_target(b)
        self.engine.rollback(self.bundle, b, a)
        self.engine.observe(a); self.engine.stop_target(a)
        self.assertTrue(self.engine.resume(self.bundle)['fullFlowObserved'])
        original = read(self.source / 'runtime.json')
        for target in (b, a):
            record = read(target / 'target.json')['record']
            self.assertIs(record['startupPaused'], True)
            self.assertEqual(record['profile'], 'tactical')
            self.assertEqual(record['topdown'], self.record['topdown'])
            self.assertEqual(read(target / 'runtime/runtime.json'), original)
            model = read(target / 'compose.json')
            for svc in self.model['services']:
                self.assertEqual(model['services'][svc].get('environment'), self.model['services'][svc].get('environment'))
            self.assertEqual(model['services']['game-engine']['environment'][r.fresh.STARTUP_PAUSE_ENV], 'true')
            self.assertTrue(model['services']['game-api']['volumes'][0]['read_only'])
            r.selected_tree(target / 'runtime', record, True)
            for name in ('manifest.json', *self.map.files):
                archived = self.bundle / 'custody/topdown' / self.map.bake_id / name
                restored = target / 'runtime/topdown' / self.map.bake_id / name
                self.assertEqual(archived.read_bytes(), restored.read_bytes())
                self.assertEqual(archived.stat().st_mode & 0o777, 0o600)
                self.assertEqual(restored.stat().st_mode & 0o777, 0o644)
        self.assertTrue(any('/admin/turn-daemon/status' in ' '.join(call) for call in self.io.calls))
        self.assertTrue(any('/internal/battles/pipeline-readiness?' in ' '.join(call) for call in self.io.calls))
        self.assertFalse(any('/admin/turn-daemon/resume' in ' '.join(call) for call in self.io.calls))

    def test_missing_false_alias_or_leaked_startup_environment_refuses_before_stop(self):
        for change in ('missing', 'false', 'alias', 'other-service'):
            with self.subTest(change=change):
                model = copy.deepcopy(self.model)
                env = model['services']['game-engine']['environment']
                if change == 'missing': env.pop(r.fresh.STARTUP_PAUSE_ENV)
                elif change == 'false': env[r.fresh.STARTUP_PAUSE_ENV] = 'false'
                elif change == 'alias': env['TURN_DAEMON_STARTUP_PAUSED'] = env.pop(r.fresh.STARTUP_PAUSE_ENV)
                else: model['services']['game-api']['environment'][r.fresh.STARTUP_PAUSE_ENV] = 'true'
                write(self.source / 'compose.json', model, replace=True)
                contract = dict(self.record, configSha256=digest(self.source / 'compose.json'))
                write(self.source / 'contract.json', contract, replace=True)
                with self.assertRaises(Exception): self.backup()
                self.assertFalse(any(c[1:2] == ['kill'] for c in self.io.calls))
        write(self.source / 'compose.json', self.model, replace=True)
        write(self.source / 'contract.json', self.record, replace=True)

    def test_version_and_target_cannot_drop_or_change_startup_and_tactical_profile(self):
        self.backup(); version = self.version(); original = read(version)
        for key, value in (('startupPaused', False), ('profile', 'standard')):
            changed = copy.deepcopy(original); changed[key] = value
            write(version, changed, replace=True)
            with self.assertRaisesRegex(Exception, 'VERSION_PROFILE_BINDING'):
                self.engine.restore(self.bundle, self.root / 'bad', version)
            self.assertFalse((self.root / 'bad').exists())
        write(version, original, replace=True)
        target = self.root / 'B'; self.engine.restore(self.bundle, target, version)
        original = read(target / 'target.json')
        for key, value in (('startupPaused', False), ('profile', 'standard')):
            changed = copy.deepcopy(original); changed['record'][key] = value
            write(target / 'target.json', changed, replace=True)
            with self.assertRaisesRegex(Exception, 'TARGET_PROFILE_BINDING'): self.engine.target(target)
        write(target / 'target.json', original, replace=True)

    def test_restore_never_marks_started_if_initial_pause_smoke_fails(self):
        self.backup(); version = self.version(); target = self.root / 'B'
        self.io.startup_pause_ok = False
        with self.assertRaisesRegex(Exception, 'Engine startup pause is not ready'):
            self.engine.restore(self.bundle, target, version)
        self.assertEqual(read(target / 'target.json')['phase'], 'DATA_VERIFIED')
        self.assertIsNone(read(target / 'target.json')['observation'])

    def test_observe_rechecks_pause_and_tactical_readiness_before_USER_acceptance(self):
        self.backup(); version = self.version(); target = self.root / 'B'
        self.engine.restore(self.bundle, target, version)
        self.io.startup_pause_ok = False
        with self.assertRaisesRegex(Exception, 'Engine startup pause is not ready'): self.engine.observe(target)
        self.io.startup_pause_ok = True; self.io.tactical_ready = False
        with self.assertRaisesRegex(Exception, 'Tactical pipeline is not ready'): self.engine.observe(target)
        self.assertEqual(read(target / 'target.json')['phase'], 'RUNNING_NOT_ACCEPTED')
        self.assertIsNone(read(target / 'target.json')['observation'])
