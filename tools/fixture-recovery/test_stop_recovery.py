"""Normal-stop provenance with fake Docker only, including failure cleanup."""
import copy
import json
import tarfile
import unittest

import recovery as r
from storage import Refused, read, write
import test_recovery as base
from test_recovery import RID, image_id


class NormalStopTests(unittest.TestCase):
    setUp = base.RecoveryTests.setUp
    backup = base.RecoveryTests.backup
    version = base.RecoveryTests.version

    def row(self, service, project=None):
        project = project or self.record['project']
        return next(row for row in self.io.containers.values()
                    if row['Config']['Labels']['com.docker.compose.service'] == service
                    and row['Config']['Labels'][r.fresh.PROJECT_LABEL] == project)

    def stop_journal(self):
        path = self.root / 'manual-stop.json'
        return {}, path

    def assert_no_backup(self):
        self.assertFalse((self.bundle / 'manifest.json').exists())
        self.assertFalse(any(c[1:3] == ['image', 'save'] for c in self.io.calls))
        self.assertFalse(any(c[1:2] == ['run'] for c in self.io.calls))

    def test_own_TERM_143_records_bound_proof_and_full_backup(self):
        def outcome(service, row):
            if service not in r.DATA:
                row['ExitCode'] = 143
        self.io.stop_hook = outcome
        self.backup()
        proof = read(self.bundle / 'stop-proof.json')
        self.assertEqual(set(proof['stopAttempts']), set(r.STOP))
        for service, attempt in proof['stopAttempts'].items():
            self.assertEqual(attempt['status'], 'PROVEN')
            self.assertEqual(attempt['before']['Id'], self.row(service)['Id'])
            self.assertEqual(attempt['before']['Image'], self.row(service)['Image'])
            self.assertEqual(attempt['before']['StartedAt'], attempt['after']['StartedAt'])
            self.assertEqual(attempt['command'], ['docker', 'kill', '--signal=SIGTERM', self.row(service)['Id']])
            self.assertEqual(attempt['after']['ExitCode'], 0 if service in r.DATA else 143)
        self.assertEqual((self.bundle / 'stop-proof.json').stat().st_mode & 0o777, 0o600)
        self.assertNotIn('FAKE PRIVATE SENTINEL', json.dumps(proof))
        self.assertNotIn('FAKE-', json.dumps(proof))

    def test_own_INT_130_is_allowed_but_other_signal_exit_is_not(self):
        self.io.signal = 'SIGINT'
        self.io.stop_hook = lambda svc, row: row.update(ExitCode=130) if svc not in r.DATA else None
        self.backup()
        self.assertEqual(read(self.bundle / 'stop-proof.json')['stopAttempts']['game-engine']['after']['ExitCode'], 130)

    def test_app_137_never_completes_and_original_returns(self):
        self.io.stop_hook = lambda svc, row: row.update(ExitCode=137) if svc == 'game-engine' else None
        with self.assertRaises(Refused):
            self.backup()
        self.assert_no_backup()
        self.assertTrue(all(c['State']['Running'] for c in self.io.containers.values()))
        self.assertEqual(read(self.bundle / 'journal.json')['phase'], 'ORIGINAL_RESUMED')

    def test_app_OOM_even_with_zero_exit_never_completes(self):
        self.io.stop_hook = lambda svc, row: row['State'].update(OOMKilled=True) if svc == 'game-api' else None
        with self.assertRaises(Refused):
            self.backup()
        self.assert_no_backup()

    def test_app_engine_error_even_with_zero_exit_never_completes(self):
        self.io.stop_hook = lambda svc, row: row['State'].update(Error='synthetic failure') if svc == 'game-engine' else None
        with self.assertRaises(Refused):
            self.backup()
        self.assert_no_backup()
        journal = read(self.bundle / 'journal.json')
        self.assertNotIn('synthetic failure', json.dumps(journal))

    def test_TERM_does_not_authorize_130_or_arbitrary_failure(self):
        for code in (1, 130, 139):
            with self.subTest(code=code):
                journal, path = self.stop_journal()
                self.io.stop_hook = lambda svc, row: row.update(ExitCode=code)
                with self.assertRaises(Refused):
                    self.engine.stop(self.record, self.model, journal, path, services=('nginx',))
                # Fresh synthetic state, without touching a real container.
                path.unlink()
                self.row('nginx')['State'].update(Running=True, Pid=42)

    def test_data_143_still_refused(self):
        self.io.stop_hook = lambda svc, row: row.update(ExitCode=143) if svc == 'game-postgres' else None
        with self.assertRaisesRegex(Refused, 'UNCLEAN_DATA_STOP'):
            self.backup()
        self.assert_no_backup()

    def test_143_without_own_signal_is_refused(self):
        row = self.row('game-engine')
        row['State'].update(Running=False, Pid=0, FinishedAt=self.io.timestamp())
        row['ExitCode'] = 143
        journal, path = self.stop_journal()
        with self.assertRaises(Refused):
            self.engine.stop(self.record, self.model, journal, path, services=('game-engine',))
        self.assertFalse(any(c[1:2] == ['kill'] for c in self.io.calls))

    def test_changed_StartedAt_after_signal_is_refused(self):
        self.io.stop_hook = lambda svc, row: row['State'].update(StartedAt=self.io.timestamp()) if svc == 'game-engine' else None
        with self.assertRaises(Refused):
            self.backup()
        self.assert_no_backup()
        self.assertEqual(read(self.bundle / 'journal.json')['phase'], 'RESUME_REQUIRED')

    def test_changed_image_after_signal_is_refused(self):
        self.io.stop_hook = lambda svc, row: row.update(Image=image_id('external')) if svc == 'game-engine' else None
        with self.assertRaises(Refused):
            self.backup()
        self.assert_no_backup()

    def test_stale_zero_missing_future_or_offset_FinishedAt_is_checked(self):
        for stamp in ('0001-01-01T00:00:00Z', '', '2026-10-19T00:00:02.123456789Z',
                      '2099-01-01T00:00:00Z', '2026-10-19T00:00:00.123456789+09:00'):
            with self.subTest(stamp=stamp):
                journal, path = self.stop_journal()
                self.io.stop_hook = lambda svc, row: row['State'].update(FinishedAt=stamp)
                with self.assertRaises(Refused):
                    self.engine.stop(self.record, self.model, journal, path, services=('nginx',))
                path.unlink()
                self.row('nginx')['State'].update(Running=True, Pid=42)

    def test_daemon_change_during_signal_is_refused(self):
        def outcome(svc, row):
            if svc == 'game-engine':
                self.io.daemon_id = 'different-daemon'
        self.io.stop_hook = outcome
        with self.assertRaises(Refused):
            self.backup()
        self.assert_no_backup()

    def test_suspended_error_or_restarting_before_signal_is_refused(self):
        for state in ({'Restarting': True}, {'Pid': 0}, {'OOMKilled': True}, {'Error': 'bad'},
                      {'Paused': True}, {'Dead': True}):
            with self.subTest(state=state):
                row = self.row('game-engine')
                original = copy.deepcopy(row['State'])
                row['State'].update(state)
                journal, path = self.stop_journal()
                with self.assertRaises(Refused):
                    self.engine.stop(self.record, self.model, journal, path, services=('game-engine',))
                self.assertFalse(any(c[1:2] == ['kill'] for c in self.io.calls))
                if path.exists(): path.unlink()
                row['State'] = original

    def test_restart_after_proven_stop_invalidates_repeat_and_backup(self):
        journal, path = self.stop_journal()
        self.engine.stop(self.record, self.model, journal, path, services=('game-engine',))
        row = self.row('game-engine')
        row['State'].update(StartedAt=self.io.timestamp(), FinishedAt=self.io.timestamp())
        count = len([c for c in self.io.calls if c[1:2] == ['kill']])
        with self.assertRaises(Refused):
            self.engine.stop(self.record, self.model, journal, path, services=('game-engine',))
        self.assertEqual(len([c for c in self.io.calls if c[1:2] == ['kill']]), count)

    def test_external_restart_during_archive_prevents_manifest(self):
        original_stream = self.io.stream
        def stream(args, path, incoming=False):
            result = original_stream(args, path, incoming=incoming)
            if args[1:3] == ['image', 'save']:
                self.row('game-engine')['State']['StartedAt'] = self.io.timestamp()
            return result
        self.io.stream = stream
        with self.assertRaises(Refused):
            self.backup()
        self.assertFalse((self.bundle / 'manifest.json').exists())

    def test_partial_target_failure_stops_remaining_and_allows_original_return_without_pass(self):
        self.backup()
        target = self.root / 'partial'
        self.engine.restore(self.bundle, target, self.version())
        self.engine.observe(target)
        def outcome(svc, row):
            if svc == 'game-api':
                row['ExitCode'] = 137
        self.io.stop_hook = outcome
        with self.assertRaises(Refused):
            self.engine.stop_target(target)
        project = read(target / 'target.json')['record']['project']
        self.assertTrue(all(not self.row(s, project)['State']['Running'] for s in r.STOP))
        self.assertEqual(read(target / 'target.json')['phase'], 'STOP_FAILED_PRESERVED')
        with self.assertRaises(Refused):
            self.engine.rollback(self.bundle, target, self.root / 'forbidden')
        with self.assertRaises(Refused):
            self.engine.stop_target(target)
        result = self.engine.resume(self.bundle)
        self.assertEqual(result['phase'], 'ORIGINAL_RESUMED')
        self.assertFalse(result['fullFlowObserved'])
        self.assertTrue(target.exists())

    def test_signal_child_failure_remains_unproven_even_if_externally_stopped(self):
        self.io.stop_errors.add('game-engine')
        journal, path = self.stop_journal()
        with self.assertRaises(Refused):
            self.engine.stop(self.record, self.model, journal, path, services=('game-engine',))
        row = self.row('game-engine')
        row['State'].update(Running=False, Pid=0, FinishedAt=self.io.timestamp())
        row['ExitCode'] = 143
        self.io.stop_errors.clear()
        with self.assertRaises(Refused):
            self.engine.stop(self.record, self.model, journal, path, services=('game-engine',))
        self.assertEqual(read(path)['stopAttempts']['game-engine']['status'], 'FAILED')

    def test_after_state_cannot_be_restarting_live_dead_or_paused(self):
        for state in ({'Restarting': True}, {'Pid': 17}, {'Paused': True}, {'Dead': True}):
            with self.subTest(state=state):
                journal, path = self.stop_journal()
                self.io.stop_hook = lambda svc, row: row['State'].update(state)
                with self.assertRaises(Refused):
                    self.engine.stop(self.record, self.model, journal, path, services=('nginx',))
                path.unlink()
                self.row('nginx')['State'].update(Running=True, Pid=42, Restarting=False, Paused=False, Dead=False)

    def test_non_boolean_flags_and_boolean_integers_are_not_valid_proof(self):
        journal, path = self.stop_journal()
        self.engine.stop(self.record, self.model, journal, path, services=('nginx',))
        original = copy.deepcopy(journal['stopAttempts']['nginx'])
        for field, value in (('OOMKilled', 0), ('Pid', False), ('ExitCode', False), ('RestartCount', False)):
            with self.subTest(field=field):
                attempt = copy.deepcopy(original)
                attempt['after'][field] = value
                with self.assertRaises(Refused):
                    r.validate_stop(attempt, 'nginx', self.record, self.model)


    def test_nanosecond_boundary_and_timezone_offsets_are_preserved(self):
        self.assertEqual(r.timestamp_ns('2026-10-19T09:00:00.123456789+09:00'),
                         r.timestamp_ns('2026-10-19T00:00:00.123456789Z'))
        self.assertEqual(r.timestamp_ns('2026-10-19T00:00:00.123456790Z') -
                         r.timestamp_ns('2026-10-19T00:00:00.123456789Z'), 1)
        self.assertEqual(r.timestamp_ns('2026-10-19T00:00:00Z'),
                         r.timestamp_ns('2026-10-19T00:00:00.000000000Z'))
        with self.assertRaises(Refused):
            r.timestamp_ns('2026-10-19T00:00:00.1234567890Z')

    def test_live_owned_instance_change_immediately_before_signal_is_refused(self):
        original = self.io.run
        engine = self.row('game-engine')
        def run(args, **kwargs):
            result = original(args, **kwargs)
            if args[1:2] == ['info']:
                engine['State']['StartedAt'] = self.io.timestamp()
            return result
        self.io.run = run
        journal, path = self.stop_journal()
        with self.assertRaises(Refused):
            self.engine.stop(self.record, self.model, journal, path, services=('game-engine',))
        self.assertFalse(any(c[1:2] == ['kill'] for c in self.io.calls))

    def test_daemon_clock_regression_is_not_proof(self):
        self.io.stop_hook = lambda svc, row: setattr(self.io, 'clock', 2)
        journal, path = self.stop_journal()
        with self.assertRaises(Refused):
            self.engine.stop(self.record, self.model, journal, path, services=('nginx',))

    def test_kill_failure_continues_remaining_owned_target_services(self):
        self.backup()
        target = self.root / 'partial'
        self.engine.restore(self.bundle, target)
        self.io.stop_errors.add('game-api')
        with self.assertRaises(Refused):
            self.engine.stop_target(target)
        project = read(target / 'target.json')['record']['project']
        self.assertTrue(self.row('game-api', project)['State']['Running'])
        self.assertTrue(all(not self.row(s, project)['State']['Running'] for s in r.STOP if s != 'game-api'))
        with self.assertRaisesRegex(Refused, 'TARGET_STILL_RUNNING'):
            self.engine.resume(self.bundle)
        self.assertEqual(read(target / 'stop.json')['stopAttempts']['game-api']['status'], 'FAILED')

    def test_partial_restore_cleanup_cannot_be_full_target_stop(self):
        self.backup()
        self.io.corrupt_restore = True
        target = self.root / 'partial'
        with self.assertRaises(tarfile.TarError):
            self.engine.restore(self.bundle, target)
        self.engine.stop_target(target)
        self.assertEqual(read(target / 'target.json')['phase'], 'STOPPED_PARTIAL_PRESERVED')
        self.assertFalse(self.engine.resume(self.bundle)['fullFlowObserved'])


    def test_proven_repeat_is_idempotent_but_proof_removal_is_not(self):
        self.backup()
        target = self.root / 'target'
        self.engine.restore(self.bundle, target)
        self.engine.stop_target(target)
        count = len([c for c in self.io.calls if c[1:2] == ['kill']])
        self.engine.stop_target(target)
        self.assertEqual(len([c for c in self.io.calls if c[1:2] == ['kill']]), count)
        j = read(target / 'stop.json')
        del j['stopAttempts']['game-engine']
        write(target / 'stop.json', j, replace=True)
        with self.assertRaises(Refused):
            self.engine.stop_target(target)
        self.assertFalse(self.engine.resume(self.bundle)['fullFlowObserved'])

    def test_rollback_requires_current_B_stop_proof_even_if_phase_claims_success(self):
        self.backup()
        target = self.root / 'B'
        self.engine.restore(self.bundle, target, self.version())
        self.engine.observe(target)
        self.engine.stop_target(target)
        self.row('game-engine', read(target / 'target.json')['record']['project'])['ExitCode'] = 137
        with self.assertRaises(Refused):
            self.engine.rollback(self.bundle, target, self.root / 'bad-A')
        self.assertFalse((self.root / 'bad-A').exists())

    def test_externally_restarted_original_is_not_adopted_before_any_start(self):
        self.backup()
        row = self.row('game-engine')
        row['State'].update(Running=True, Pid=42, StartedAt=self.io.timestamp())
        with self.assertRaisesRegex(Refused, 'ORIGINAL_RUN_CHANGED'):
            self.engine.resume(self.bundle)
        self.assertFalse(any(c[1:2] == ['start'] for c in self.io.calls))


    def test_all_targets_need_clean_stop_before_fullflow_true(self):
        self.backup()
        b = self.root / 'B'; a = self.root / 'A'
        self.engine.restore(self.bundle, b, self.version())
        self.engine.observe(b); self.engine.stop_target(b)
        self.engine.rollback(self.bundle, b, a); self.engine.observe(a)
        self.io.stop_hook = lambda svc, row: row.update(ExitCode=137) if svc == 'game-engine' else None
        with self.assertRaises(Refused):
            self.engine.stop_target(a)
        self.assertFalse(self.engine.resume(self.bundle)['fullFlowObserved'])


if __name__ == '__main__':
    unittest.main()
