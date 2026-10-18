"""Output isolation regressions. All custody, bundles and CLI calls are synthetic."""
from argparse import Namespace
import contextlib
import io
import os
from pathlib import Path
import unittest
from unittest.mock import patch

import recovery as r
import storage
import test_recovery as fixtures


class OutputPathTests(unittest.TestCase):
    setUp = fixtures.RecoveryTests.setUp
    backup = fixtures.RecoveryTests.backup

    def args(self, action='restore', **changes):
        values = dict(action=action, source_custody=self.source, bundle=self.bundle,
                      logs=self.root/'logs', target=self.root/'target',
                      output=self.root/'version.json', source=self.root/'B-source',
                      from_target=self.root/'prior-target')
        values.update(changes)
        return Namespace(**values)

    def token(self):
        return {'sourceContractSha256': storage.digest(self.source/'contract.json')}

    def snapshot(self):
        roots = [self.source] + ([self.bundle] if self.bundle.exists() else [])
        return {str(p): (p.lstat().st_mode, p.read_bytes() if p.is_file() else None)
                for root in roots for p in (root, *sorted(root.rglob('*')))}

    def refused(self, action):
        before = self.snapshot()
        calls = list(self.io.calls)
        with self.assertRaises(storage.Refused):
            action()
        self.assertEqual(before, self.snapshot())
        self.assertEqual(calls, self.io.calls)

    def test_dotdot_outputs_are_rejected_before_custody_or_bundle_mutation(self):
        self.backup()
        storage.newdir(self.root/'outside')
        cases = [self.args('backup', bundle=self.root/'outside/../source/new-backup'),
                 self.args(target=self.root/'outside/../source/new-target'),
                 self.args('rollback', target=self.root/'outside/../backup/new-target'),
                 self.args(logs=self.root/'outside/../source/new-logs'),
                 self.args(logs=self.root/'outside/../backup/new-logs'),
                 self.args('pin-version', output=self.root/'outside/../source/new-version')]
        for args in cases:
            with self.subTest(action=args.action, output=str(args)):
                self.refused(lambda: r.authorize_inputs(args, self.token()))

    def test_pin_output_refuses_source_bundle_and_B_source_even_without_alias(self):
        self.backup()
        b_source = storage.newdir(self.root/'B-source')
        for parent in (self.source, self.bundle, b_source):
            with self.subTest(parent=parent.name):
                args = self.args('pin-version', output=parent/'new-version.json')
                self.refused(lambda: r.authorize_inputs(args, self.token()))
                self.assertFalse((parent/'new-version.json').exists())

    def test_existing_outputs_are_not_opened_or_overwritten(self):
        self.backup()
        output = self.root/'version.json'
        storage.put(output, b'existing version')
        self.refused(lambda: r.authorize_inputs(self.args('pin-version', output=output), self.token()))
        self.assertEqual(b'existing version', output.read_bytes())

    def test_case_alias_uses_existing_filesystem_identity(self):
        alias = self.source.with_name('SOURCE')
        if alias.exists() and os.path.samefile(alias, self.source):
            self.refused(lambda: storage.isolated_output(alias/'new', [self.source]))
        else:
            # Case-sensitive hosts still exercise the ancestor-identity fallback.
            storage.newdir(alias)
            real_samefile = os.path.samefile
            def samefile(a, b):
                return ((a == alias and b == self.source) or
                        (b == alias and a == self.source) or real_samefile(a, b))
            with patch('storage.os.path.samefile', side_effect=samefile):
                self.refused(lambda: storage.isolated_output(alias/'new', [self.source]))

    def test_symlink_and_dangling_aliases_are_refused_without_following_them(self):
        self.backup()
        alias = self.root/'source-alias'; alias.symlink_to(self.source, target_is_directory=True)
        dangling = self.root/'dangling'; dangling.symlink_to(self.root/'missing')
        for path in (alias/'new', dangling/'new'):
            for field in ('logs', 'target', 'output'):
                with self.subTest(path=path, field=field):
                    action = 'pin-version' if field == 'output' else 'restore'
                    self.refused(lambda: r.authorize_inputs(self.args(action, **{field:path}), self.token()))

    def test_entry_methods_reject_output_before_any_fake_Docker_call(self):
        self.refused(lambda: self.engine.backup(self.source, self.source/'bad-backup', 2, fixtures.RID))
        self.backup()
        self.refused(lambda: self.engine.restore(self.bundle, self.source/'bad-target'))
        self.refused(lambda: self.engine.restore(self.bundle, self.bundle/'bad-target'))
        self.refused(lambda: self.engine.version(self.bundle, 'b'*40, {}, self.source/'bad-version', self.root/'B-source'))
        self.refused(lambda: self.engine.version(self.bundle, 'b'*40, {}, self.bundle/'bad-version', self.root/'B-source'))
        prior = storage.newdir(self.root/'prior-target')
        self.refused(lambda: self.engine.rollback(self.bundle, prior, prior/'bad-rollback'))

    def test_storage_rejects_dotdot_and_symlink_parents_for_all_writes(self):
        storage.newdir(self.root/'outside')
        alias = self.root/'alias'; alias.symlink_to(self.source, target_is_directory=True)
        for parent in (self.root/'outside/../source', alias):
            for create in (lambda p: storage.newdir(p), lambda p: storage.put(p, b'new'),
                           lambda p: storage.write(p, {'new':True})):
                self.refused(lambda: create(parent/'unexpected'))
                self.assertFalse((self.source/'unexpected').exists())

    def test_logs_and_other_outputs_cannot_contain_each_other(self):
        self.backup()
        for args in (self.args(logs=self.root/'target/logs'),
                     self.args('pin-version', output=self.root/'logs'),
                     self.args('pin-version', logs=self.root/'version.json/logs')):
            self.refused(lambda: r.authorize_inputs(args, self.token()))
        prior = storage.newdir(self.root/'prior-target')
        args = self.args('rollback', target=prior/'new')
        self.refused(lambda: r.authorize_inputs(args, self.token()))

    def test_cli_refuses_alias_before_logs_transport_git_or_heavy(self):
        self.backup()
        storage.newdir(self.root/'outside')
        handoff = self.root/'handoff.json'
        storage.write(handoff, dict(self.token(), schema=1, sourceCustody=str(self.source),
            ownerSession=fixtures.SESSION, scope='F_FULL_RECOVERY', windowId='fake-only',
            expiresAt='2099-01-01T00:00:00Z'))
        cases = [('restore', ['--target', str(self.root/'outside/../source/target')]),
                 ('pin-version', ['--app-sha', 'b'*40, '--source', str(self.root/'B-source'),
                                  '--output', str(self.bundle/'new-version.json')])]
        for action, extra in cases:
            logs = self.root/('logs-'+action)
            argv = ['recovery', '--handoff', str(handoff), '--source-custody', str(self.source),
                    '--meta', str(self.root), '--logs', str(logs), action, '--bundle', str(self.bundle), *extra]
            before, calls = self.snapshot(), list(self.io.calls)
            with patch('sys.argv', argv), patch.object(r, 'LocalIO') as transport, \
                    patch.object(r.fresh, 'git') as git, patch.object(r, 'heavy') as heavy:
                with contextlib.redirect_stdout(io.StringIO()) as stdout:
                    self.assertEqual(1, r.main())
                self.assertEqual(before, self.snapshot()); self.assertEqual(calls, self.io.calls)
                self.assertIn('REFUSED_OR_FAILED', stdout.getvalue())
                transport.assert_not_called(); git.assert_not_called(); heavy.assert_not_called()
                self.assertFalse(logs.exists())

    def test_legal_relative_siblings_become_canonical_and_remain_usable(self):
        self.backup()
        previous = Path.cwd()
        try:
            os.chdir(self.root)
            args = self.args(source_custody=Path('source'), bundle=Path('backup'),
                             target=Path('target'), logs=Path('logs'))
            r.authorize_inputs(args, self.token())
            self.assertEqual(args.source_custody, self.source)
            self.assertEqual(args.target, self.root/'target')
            self.assertEqual(args.logs, self.root/'logs')
            self.assertEqual(args.bundle, self.bundle)
        finally:
            os.chdir(previous)


if __name__ == '__main__':
    unittest.main()
