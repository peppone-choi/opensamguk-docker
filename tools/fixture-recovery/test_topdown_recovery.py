"""Selected public map recovery, entirely synthetic and daemon-free."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import recovery as r
from storage import read, write, put, newdir, digest, seal
import test_recovery as base
from test_recovery import RID

spec = importlib.util.spec_from_file_location('recovery_public_fixture', r.ROOT / 'tools/localhost-acceptance/test_topdown_bundle.py')
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class SelectedRecoveryTests(unittest.TestCase):
    def setUp(self):
        base.RecoveryTests.setUp(self)
        self.map = fixture.TopdownTests()
        self.map.setUp()
        self.addCleanup(self.map.doCleanups)
        for name, data in self.map.sources.items():
            path = self.source / 'source' / name
            for parent in reversed(path.parent.parents):
                if parent.is_relative_to(self.source / 'source') and not parent.exists():
                    newdir(parent)
            if not path.parent.exists(): newdir(path.parent)
            put(path, data)
        self.record['topdown'] = self.map.validate()
        r.fresh.topdown.copy_bundle(self.map.bundle, self.source, self.record['topdown'])
        self.record['sourceTreeSha256'] = r.fresh.tree_hash(self.source / 'source')
        for svc in r.fresh.SERVICES:
            iid = self.record['images'][svc]['imageId']
            self.io.image_data[iid]['Config']['Labels'] = r.fresh.image_metadata(self.record, svc, {})
        self.model = r.fresh.model_for(self.record, read(self.source / 'runtime.json'))
        write(self.source / 'compose.json', self.model, replace=True)
        self.record['configSha256'] = digest(self.source / 'compose.json')
        write(self.source / 'contract.json', self.record, replace=True)
        self.io.install(self.record, self.model)
        self.io.map_record = self.record
        self.io.map_manifest = (self.map.bundle / 'manifest.json').read_bytes()

    def backup(self):
        return base.RecoveryTests.backup(self)

    def version(self, incompatible=False):
        self.version_sources = dict(self.map.sources)
        if incompatible:
            path = r.fresh.topdown.KIT + '/export.json'
            export = json.loads(self.version_sources[path])
            export['source']['mergeCommit'] = 'c' * 40
            self.version_sources[path] = r.fresh.topdown.canonical(export)
        return base.RecoveryTests.version(self)

    def test_selected_A_backup_B_observe_A_rollback_preserves_every_byte_and_pin(self):
        self.backup()
        version = self.version()
        selected = self.record['topdown']
        self.assertEqual(read(version)['topdown'], selected)
        b, a = self.root / 'B', self.root / 'A-return'
        self.engine.restore(self.bundle, b, version)
        self.engine.observe(b)
        self.engine.stop_target(b)
        self.engine.rollback(self.bundle, b, a)
        self.engine.observe(a)
        for target in (b, a):
            self.assertEqual(read(target / 'target.json')['record']['topdown'], selected)
            r.selected_tree(target / 'runtime', self.record, True)
            model = read(target / 'compose.json')
            mount = model['services']['game-api']['volumes']
            self.assertEqual(len(mount), 1)
            self.assertEqual(mount[0]['source'], str(target / 'runtime/topdown'))
            self.assertTrue(mount[0]['read_only'])
            for name in ('manifest.json', *self.map.files):
                restored = target / 'runtime/topdown' / self.map.bake_id / name
                self.assertEqual(restored.read_bytes(), (self.map.bundle / name).read_bytes())
                self.assertEqual(restored.stat().st_mode & 0o777, 0o644)
                archived = self.bundle / 'custody/topdown' / self.map.bake_id / name
                self.assertEqual(archived.stat().st_mode & 0o777, 0o600)
        self.engine.stop_target(a)
        self.assertTrue(self.engine.resume(self.bundle)['fullFlowObserved'])

    def test_missing_extra_and_corrupt_source_files_refused_before_stop(self):
        tree = self.source / 'topdown' / self.map.bake_id
        path = tree / 'defects.json'
        original = path.read_bytes()
        for mode in ('missing', 'corrupt', 'extra'):
            with self.subTest(mode=mode):
                if mode == 'missing': path.unlink()
                elif mode == 'corrupt': path.write_bytes(b'changed')
                else: (tree / 'extra.json').write_bytes(b'{}')
                with self.assertRaises(Exception): self.backup()
                self.assertFalse(any(c[1:2] == ['kill'] for c in self.io.calls))
                if mode == 'extra': (tree / 'extra.json').unlink()
                else: path.write_bytes(original); path.chmod(0o644)

    def test_resealed_backup_cannot_bypass_manifest_inventory(self):
        self.backup()
        put(self.bundle / 'custody/topdown' / self.map.bake_id / 'extra.json', b'{}')
        manifest = read(self.bundle / 'manifest.json')
        manifest['files'] = seal(self.bundle)
        write(self.bundle / 'manifest.json', manifest, replace=True)
        with self.assertRaises(Exception): self.engine.restore(self.bundle, self.root / 'bad')
        self.assertFalse((self.root / 'bad').exists())

    def test_different_B_source_pin_and_tampered_version_selection_refused(self):
        self.backup()
        with self.assertRaisesRegex(Exception, 'VERSION_TOPDOWN_SOURCE'): self.version(True)
        version = self.version()
        value = read(version); value['topdown']['manifestSha256'] = '0' * 64
        write(version, value, replace=True)
        with self.assertRaisesRegex(Exception, 'VERSION_TOPDOWN_BINDING'):
            self.engine.restore(self.bundle, self.root / 'bad', version)
        self.assertFalse((self.root / 'bad').exists())

    def test_foreign_RO_RW_stopped_running_and_desktop_alias_consumers_refused(self):
        for running in (True, False):
            for rw in (True, False):
                for prefix in ('', '/host_mnt'):
                    with self.subTest(running=running, rw=rw, prefix=prefix):
                        row = copy.deepcopy(next(iter(self.io.containers.values())))
                        row.update(Id='f' * 64, Name='foreign')
                        row['Config']['Labels'] = {}
                        row['State']['Running'] = running
                        row['Mounts'] = [{'Type':'bind', 'Source':prefix + str(self.source / 'topdown'),
                                          'Destination':'/shared', 'RW':rw}]
                        self.io.containers[row['Id']] = row
                        with self.assertRaisesRegex(Exception, 'FOREIGN_BIND_CONSUMER'): self.backup()
                        self.assertFalse(any(c[1:2] == ['kill'] for c in self.io.calls))
        del self.io.containers['f' * 64]

    def test_writable_or_extra_owned_mount_refused(self):
        row = next(c for c in self.io.containers.values()
                   if c['Config']['Labels']['com.docker.compose.service'] == 'game-api')
        original = copy.deepcopy(row['Mounts'])
        for mounts in ([dict(original[0], RW=True)], original + original):
            row['Mounts'] = mounts
            with self.assertRaises(Exception): self.backup()
            self.assertFalse(any(c[1:2] == ['kill'] for c in self.io.calls))
        row['Mounts'] = original

    def test_target_drift_and_served_binding_are_rechecked_before_observation(self):
        self.backup(); version = self.version(); target = self.root / 'B'
        self.engine.restore(self.bundle, target, version)
        path = target / 'runtime/topdown' / self.map.bake_id / 'defects.json'
        original = path.read_bytes(); path.write_bytes(b'changed')
        with self.assertRaises(Exception): self.engine.observe(target)
        path.write_bytes(original)
        self.io.map_manifest = b'wrong served manifest'
        with self.assertRaisesRegex(Exception, 'SERVED_MANIFEST'): self.engine.observe(target)
        self.assertEqual(read(target / 'target.json')['phase'], 'RUNNING_NOT_ACCEPTED')
