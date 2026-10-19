"""Buildx side-effect fault injection only; no Docker daemon/network is used."""
import importlib.util
import contextlib
import json
from pathlib import Path
import os
import signal
import subprocess
import tempfile
import unittest
from unittest.mock import patch, Mock

spec = importlib.util.spec_from_file_location('builder_test_harness', Path(__file__).with_name('harness.py'))
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)


class BuilderCLI:
    """Model persisted Buildx store separately from actual container/volume state."""
    def __init__(self, harness=h):
        self.h = harness
        self.calls = []
        self.config = self.metadata = self.node = self.name = None
        self.cid = None
        self.volume = None
        self.cap_changes = {}
        self.create_error = self.bootstrap_error = None
        self.before_create = self.after_create = self.after_bootstrap = None
        self.fail_cleanup = self.leave_metadata = self.leave_container = False

    def save_metadata(self, data):
        self.h.write_json(self.metadata, data, replace=self.metadata.exists())

    def row(self):
        return dict({'Id': self.cid, 'Name': '/buildx_buildkit_' + self.node,
            'Memory': self.h.qa.BUILD_MEMORY, 'MemorySwap': self.h.qa.BUILD_MEMORY,
            'CgroupParent': self.h.qa.CGROUP, 'CpuQuota': 100000, 'CpuPeriod': 100000,
            'Mounts': [{'Type': 'volume', 'Name': self.volume['Name'], 'Destination': '/var/lib/buildkit'}]},
            **self.cap_changes)

    def __call__(self, args, **kwargs):
        self.calls.append((args, kwargs))
        if args[:3] == ['docker', 'context', 'inspect']:
            return b'unix:///synthetic/qa.sock\n'
        if args[:3] == ['docker', 'buildx', 'ls']:
            return b''
        if args[:3] == ['docker', 'buildx', 'create']:
            self.config = Path(kwargs['buildx_config'])
            self.name = args[args.index('--name') + 1]
            self.node = args[args.index('--node') + 1]
            self.metadata = self.config / 'instances' / self.name
            self.metadata.parent.mkdir(mode=0o700)
            opts = dict(args[i+1].split('=', 1) for i, a in enumerate(args) if a == '--driver-opt')
            if self.before_create:
                self.before_create()
            data = {'Name': self.name, 'Driver': 'docker-container', 'Dynamic': False,
                    'Nodes': [{'Name': self.node, 'Endpoint': args[-1], 'DriverOpts': opts,
                               'Platforms': None, 'Flags': None, 'Files': None}]}
            self.save_metadata(data)
            if self.after_create:
                self.after_create()
            if self.create_error:
                raise self.create_error
            return self.name.encode()
        if args[:3] == ['docker', 'buildx', 'inspect']:
            assert Path(kwargs['buildx_config']) == self.config
            self.cid = 'c'*64
            self.volume = {'Name': 'buildx_buildkit_' + self.node + '_state', 'Driver': 'local',
                           'CreatedAt': '2026-10-19T03:00:00Z', 'Labels': None, 'Options': None}
            if self.after_bootstrap:
                self.after_bootstrap()
            if self.bootstrap_error:
                raise self.bootstrap_error
            return b''
        if args[:2] == ['docker', 'ps']:
            return self.cid.encode() if self.cid and self.node in args[-1] else b''
        if args[:2] == ['docker', 'inspect']:
            assert args[-1] == self.cid
            return json.dumps(self.row()).encode()
        if args[:3] == ['docker', 'volume', 'ls']:
            return self.volume['Name'].encode() if self.volume else b''
        if args[:3] == ['docker', 'volume', 'inspect']:
            return json.dumps(self.volume).encode()
        if args[:3] == ['docker', 'container', 'rm']:
            assert args[-1] == self.cid and len(args[-1]) == 64
            if self.fail_cleanup:
                raise KeyboardInterrupt()
            if not self.leave_container:
                self.cid = None
            return b''
        if args[:3] == ['docker', 'volume', 'rm']:
            assert '-f' not in args and '--force' not in args
            self.volume = None
            return b''
        if args[:3] == ['docker', 'buildx', 'rm']:
            assert '--keep-daemon' in args and Path(kwargs['buildx_config']) == self.config
            if not self.leave_metadata:
                self.metadata.unlink()
            return b''
        raise AssertionError('Unexpected synthetic CLI call: ' + repr(args))

    def removed(self):
        return [a for a, _ in self.calls if a[:3] in (['docker', 'container', 'rm'],
                ['docker', 'volume', 'rm'], ['docker', 'buildx', 'rm'])]


class BuilderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name).resolve()
        self.directory.chmod(0o700)
        self.record = {'hostingerQA': h.qa.selection('t_26af26d1'), 'origin': h.qa.ORIGIN,
                       'nonce': '0123456789abcdef', 'session': '01234567-0123-0123-0123-0123456789ab',
                       'project': 'opensamguk-qa-t_26af26d1-0123456789abcdef'}
        self.cli = BuilderCLI()
        self.addCleanup(patch.stopall)
        patch.object(h, 'run', side_effect=self.cli).start()
        patch.object(h.qa, 'admission').start()

    def enter(self, body=None):
        with h.qa_builder(self.directory, self.record) as builder:
            self.assertEqual(self.cli.name, builder['name'])
            self.assertEqual(self.cli.config, builder['config'])
            if body:
                body()

    def clean(self):
        self.assertFalse(self.cli.metadata.exists())
        self.assertIsNone(self.cli.cid)
        self.assertIsNone(self.cli.volume)
        self.assertFalse(list(self.directory.rglob('*cleanup-required.json')))

    def required(self):
        self.assertTrue(list(self.directory.rglob('*cleanup-required.json')))

    def test_normal_cleanup_verifies_metadata_container_and_volume_absence(self):
        self.enter()
        self.clean()
        self.assertEqual(['docker', 'container', 'rm', '-f', 'c'*64], self.cli.removed()[0])
        self.assertIn('--keep-daemon', self.cli.removed()[-1])

    def test_build_failure_cleans_before_propagating(self):
        def fail():
            raise RuntimeError('synthetic build failure')
        with self.assertRaisesRegex(RuntimeError, 'synthetic build'):
            self.enter(fail)
        self.clean()

    def partial(self, error):
        self.cli.create_error = error
        with self.assertRaises(type(error)):
            self.enter()
        self.clean()
        self.assertEqual(1, len(self.cli.removed()))
        self.cli.create_error = None
        self.enter()
        self.clean()

    def test_partial_create_timeout_reconciles_and_same_custody_retry_succeeds(self):
        self.partial(h.Refused('synthetic timeout'))

    def test_partial_create_cancel_reconciles_and_same_custody_retry_succeeds(self):
        self.partial(KeyboardInterrupt())

    def test_partial_create_failed_exit_reconciles_and_retry_succeeds(self):
        self.partial(h.Refused('synthetic nonzero exit'))

    def test_partial_create_system_exit_reconciles(self):
        self.partial(SystemExit(2))

    def test_create_failure_before_metadata_confirms_absence_without_removal(self):
        def fail():
            raise h.Refused('before side effect')
        self.cli.before_create = fail
        with self.assertRaisesRegex(h.Refused, 'before side effect'):
            self.enter()
        self.clean()
        self.assertEqual([], self.cli.removed())

    def test_bootstrap_timeout_reconciles_container_and_metadata(self):
        self.cli.bootstrap_error = h.Refused('bootstrap timeout')
        with self.assertRaisesRegex(h.Refused, 'bootstrap timeout'):
            self.enter()
        self.clean()

    def test_bootstrap_cancel_reconciles_container_and_metadata(self):
        self.cli.bootstrap_error = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            self.enter()
        self.clean()

    def test_uncertain_bootstrap_without_visible_container_is_not_false_absence(self):
        def invisible():
            self.cli.cid = self.cli.volume = None
        self.cli.after_bootstrap = invisible
        self.cli.bootstrap_error = KeyboardInterrupt()
        with self.assertRaisesRegex(h.Refused, 'cleanup-required'):
            self.enter()
        self.required()
        self.assertEqual([], self.cli.removed())
        self.cli.calls.clear()
        with self.assertRaisesRegex(h.Refused, 'prior attempt'):
            self.enter()
        self.assertEqual([], self.cli.calls)

    def test_foreign_metadata_after_uncertain_create_is_preserved(self):
        def change():
            data = json.loads(self.cli.metadata.read_bytes())
            data['Nodes'][0]['Endpoint'] = 'unix:///foreign.sock'
            self.cli.save_metadata(data)
        self.cli.after_create = change
        self.cli.create_error = KeyboardInterrupt()
        with self.assertRaisesRegex(h.Refused, 'cleanup-required'):
            self.enter()
        self.required()
        self.assertEqual([], self.cli.removed())
        self.assertTrue(self.cli.metadata.exists())

    def test_external_metadata_change_after_bootstrap_is_preserved(self):
        def change():
            data = json.loads(self.cli.metadata.read_bytes())
            data['Nodes'][0]['Flags'] = ['external-change']
            self.cli.save_metadata(data)
        with self.assertRaisesRegex(h.Refused, 'cleanup-required'):
            self.enter(change)
        self.required()
        self.assertEqual([], self.cli.removed())

    def test_external_container_replacement_is_never_deleted_by_name(self):
        def replace():
            self.cli.cid = 'd'*64
        with self.assertRaisesRegex(h.Refused, 'cleanup-required'):
            self.enter(replace)
        self.required()
        self.assertEqual([], self.cli.removed())

    def test_cap_mismatch_is_refused_not_reported_as_clean(self):
        self.cli.cap_changes['Memory'] = 0
        with self.assertRaisesRegex(h.Refused, 'cleanup-required'):
            self.enter()
        self.required()
        self.assertEqual([], self.cli.removed())

    def test_foreign_container_projection_is_preserved(self):
        self.cli.cap_changes['Name'] = '/foreign'
        with self.assertRaisesRegex(h.Refused, 'cleanup-required'):
            self.enter()
        self.required()
        self.assertEqual([], self.cli.removed())

    def test_cleanup_cancel_is_explicit_not_false_absence(self):
        self.cli.fail_cleanup = True
        with self.assertRaisesRegex(h.Refused, 'cleanup-required'):
            self.enter()
        self.required()
        self.assertIsNotNone(self.cli.cid)
        self.assertTrue(self.cli.metadata.exists())

    def test_cleanup_metadata_still_present_is_not_pass(self):
        self.cli.leave_metadata = True
        with self.assertRaisesRegex(h.Refused, 'cleanup-required'):
            self.enter()
        self.required()

    def test_cleanup_container_still_present_is_not_pass(self):
        self.cli.leave_container = True
        with self.assertRaisesRegex(h.Refused, 'cleanup-required'):
            self.enter()
        self.required()
        self.assertEqual(1, len(self.cli.removed()))

    def test_missing_metadata_with_live_container_is_preserved(self):
        with self.assertRaisesRegex(h.Refused, 'cleanup-required'):
            self.enter(lambda: self.cli.metadata.unlink())
        self.required()
        self.assertEqual([], self.cli.removed())

    def test_foreign_state_volume_is_preserved(self):
        def change():
            self.cli.volume['Labels'] = {'foreign': 'true'}
        self.cli.after_bootstrap = change
        with self.assertRaisesRegex(h.Refused, 'cleanup-required'):
            self.enter()
        self.required()
        self.assertEqual([], self.cli.removed())


class BuilderProcessTests(unittest.TestCase):
    def test_all_six_build_commands_receive_the_private_store(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
            directory = Path(tmp).resolve()
            record = {'status': 'PREPARED', 'hostingerQA': h.qa.selection('t_26af26d1'),
                      'nonce': '0123456789abcdef', 'origin': h.qa.ORIGIN, 'appSha': 'a'*40, 'images': {}}
            builder = {'name': 'synthetic-owned-builder', 'config': directory}
            for name in ('verify_files', 'assert_owned', 'inventory', 'resource_gate', 'check_image', 'verify_images'):
                stack.enter_context(patch.object(h, name))
            stack.enter_context(patch.object(h, 'load', return_value=(directory, record)))
            stack.enter_context(patch.object(h, 'heavy', return_value=contextlib.nullcontext()))
            stack.enter_context(patch.object(h, 'qa_builder', return_value=contextlib.nullcontext(builder)))
            stack.enter_context(patch.object(h, 'inspect_image', return_value={'Id': 'synthetic-image'}))
            stack.enter_context(patch.object(h, 'image_metadata', return_value={'org.opensamguk.local.dockerfile': 'synthetic-hash'}))
            stack.enter_context(patch.object(h, 'build_args', return_value={}))
            run = stack.enter_context(patch.object(h, 'run', return_value=b''))
            args = type('Args', (), {'custody': directory, 'meta': directory})()
            h.build(args)
            builds = [call for call in run.call_args_list if call.args[0][:3] == ['docker', 'buildx', 'build']]
            self.assertEqual(6, len(builds))
            for call in builds:
                self.assertEqual(directory, call.kwargs['buildx_config'])
                self.assertIn(builder['name'], call.args[0])
                self.assertIn('--load', call.args[0])

    def test_private_config_success_returns_output_and_never_kills_unrelated_processes(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp).resolve()
            config.chmod(0o700)
            process = Mock(pid=12345, returncode=0)
            process.communicate.return_value = (b'synthetic builder', b'')
            with patch.object(h.subprocess, 'Popen', return_value=process), patch.object(h.os, 'killpg') as kill, patch.dict(os.environ, DOCKER_HOST='unix:///synthetic/qa.sock', DOCKER_CONTEXT=''):
                self.assertEqual(b'synthetic builder', h.run(['docker', 'buildx', 'create'], buildx_config=config))
                kill.assert_not_called()

    def test_private_config_reaps_plugin_group_before_timeout_or_cancel(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp).resolve()
            config.chmod(0o700)
            for error in (subprocess.TimeoutExpired('synthetic', 1), KeyboardInterrupt(), SystemExit(2)):
                with self.subTest(error=type(error).__name__):
                    process = Mock(pid=12345)
                    process.communicate.side_effect = error
                    events = []
                    process.wait.side_effect = lambda: events.append('wait')
                    with patch.object(h.subprocess, 'Popen', return_value=process) as popen, patch.object(h.os, 'killpg', side_effect=lambda *a: events.append(a)), patch.dict(os.environ, DOCKER_HOST='unix:///synthetic/qa.sock', DOCKER_CONTEXT=''):
                        with self.assertRaises(h.Refused if isinstance(error, subprocess.TimeoutExpired) else type(error)):
                            h.run(['docker', 'buildx', 'create'], timeout=1, buildx_config=config)
                        self.assertTrue(popen.call_args.kwargs['start_new_session'])
                        self.assertEqual(str(config), popen.call_args.kwargs['env']['BUILDX_CONFIG'])
                        self.assertEqual([(12345, signal.SIGKILL), 'wait'], events)
            with self.assertRaisesRegex(h.Refused, 'only for Buildx'):
                h.run(['docker', 'ps'], buildx_config=config)

    def test_effective_endpoint_honors_docker_host_and_context_precedence(self):
        with patch.dict(os.environ, DOCKER_HOST='unix:///synthetic/override.sock', DOCKER_CONTEXT=''), patch.object(h, 'run', side_effect=AssertionError('context not selected')):
            self.assertEqual('unix:///synthetic/override.sock', h.local_docker_endpoint())
        with patch.dict(os.environ, DOCKER_HOST='unix:///ignored.sock', DOCKER_CONTEXT='synthetic'), patch.object(h, 'run', return_value=b'unix:///synthetic/context.sock'):
            self.assertEqual('unix:///synthetic/context.sock', h.local_docker_endpoint())


if __name__ == '__main__':
    unittest.main()
