"""A keeps application identity; B supplies release metadata. Docker is entirely fake."""
import hashlib
import json
import unittest
from unittest.mock import patch

import recovery as r
import storage
import test_recovery as fixtures


class VersionArgsTests(unittest.TestCase):
    setUp = fixtures.RecoveryTests.setUp
    backup = fixtures.RecoveryTests.backup
    B = 'b'*40

    def args_hash(self, record, service):
        return hashlib.sha256(json.dumps(r.fresh.build_args(record, service), sort_keys=True).encode()).hexdigest()

    def pins(self, stale_backend=False, foreign_web=False):
        record = dict(self.record, appSha=self.B, sourceTreeSha256='f'*64)
        if foreign_web:
            record['serverId'] = 'lha'+'c'*16
        pins = {}
        for service in r.fresh.SERVICES:
            image = fixtures.image_id('B-'+service)
            labels = r.fresh.image_metadata(record, service, {})
            if stale_backend and service not in ('web-gateway', 'web-game'):
                labels['org.opensamguk.local.build-args'] = self.args_hash(self.record, service)
            self.io.image_data[image] = {'Id':image, 'RepoTags':[], 'Config':{'Labels':labels}}
            pins[service] = image
        return pins

    def pin(self, pins, name='B.json'):
        output = self.root/name
        with patch.object(r.fresh, 'source_archive', return_value=b'fake public archive'), \
                patch.object(r.fresh, 'archive_tree_hash', return_value='f'*64), \
                patch.object(r.fresh, 'git', return_value=b'FROM fixture'):
            self.engine.version(self.bundle, self.B, pins, output, self.root/'B-source')
        return output

    def version_file(self, pins):
        # Feed restore directly so pin acceptance cannot mask a separate restore/observe defect.
        output = self.root/'input-version.json'
        storage.write(output, {'schema':1, 'appSha':self.B, 'images':pins,
            'identity':r.identity(self.record), 'sourceTreeSha256':'f'*64,
            'dockerfiles':{s:hashlib.sha256(b'FROM fixture').hexdigest() for s in r.fresh.SERVICES}})
        return output

    def test_pin_accepts_B_release_for_all_four_backends_and_keeps_A_web_identity(self):
        self.backup()
        pins = self.pins()
        result = storage.read(self.pin(pins))
        self.assertEqual(self.B, result['appSha'])
        self.assertEqual(r.identity(self.record), result['identity'])
        for service in r.fresh.SERVICES:
            expected = r.fresh.build_args(dict(self.record, appSha=self.B), service)
            if service not in ('web-gateway', 'web-game'):
                self.assertEqual({'IMAGE_TAG':self.B}, expected)
                self.assertNotEqual(self.args_hash(self.record, service), self.args_hash(dict(self.record, appSha=self.B), service))
            else:
                self.assertEqual(r.fresh.build_args(self.record, service), expected)
        self.assertEqual('https://localhost/game/'+self.record['serverId'],
                         r.fresh.build_args(dict(self.record, appSha=self.B), 'web-gateway')['NEXT_PUBLIC_GAME_URL'])

    def test_pin_rejects_B_revision_with_old_A_backend_release_arguments(self):
        self.backup()
        with self.assertRaisesRegex(storage.Refused, 'VERSION_APP_IDENTITY'):
            self.pin(self.pins(stale_backend=True))
        self.assertFalse((self.root/'B.json').exists())

    def test_restore_and_observe_accept_proper_B_release_without_changing_A_identity(self):
        self.backup()
        version = self.version_file(self.pins())
        target = self.root/'B'
        self.engine.restore(self.bundle, target, version)
        self.assertEqual('USER_OBSERVED', self.engine.observe(target)['phase'])
        state = storage.read(target/'target.json')
        self.assertEqual(self.B, state['record']['appSha'])
        self.assertEqual(r.identity(self.record), r.identity(state['record']))
        model = storage.read(target/'compose.json')
        for service in self.model['services']:
            self.assertEqual(self.model['services'][service].get('environment'), model['services'][service].get('environment'))

    def test_restore_rejects_old_A_release_before_creating_target_or_volumes(self):
        self.backup()
        version = self.version_file(self.pins(stale_backend=True))
        target = self.root/'B'
        before = set(self.io.volumes)
        with self.assertRaisesRegex(storage.Refused, 'VERSION_IMAGE_CHANGED'):
            self.engine.restore(self.bundle, target, version)
        self.assertFalse(target.exists())
        self.assertEqual(before, set(self.io.volumes))

    def test_target_revalidates_every_backend_release_before_observation(self):
        self.backup()
        pins = self.pins()
        target = self.root/'B'
        self.engine.restore(self.bundle, target, self.version_file(pins))
        for service in r.fresh.SERVICES[:4]:
            with self.subTest(service=service):
                labels = self.io.image_data[pins[service]]['Config']['Labels']
                original = labels['org.opensamguk.local.build-args']
                labels['org.opensamguk.local.build-args'] = self.args_hash(self.record, service)
                with self.assertRaisesRegex(storage.Refused, 'TARGET_B_IMAGES'):
                    self.engine.observe(target)
                self.assertEqual('RUNNING_NOT_ACCEPTED', storage.read(target/'target.json')['phase'])
                labels['org.opensamguk.local.build-args'] = original

    def test_foreign_server_web_gateway_is_refused_at_pin_restore_and_target(self):
        self.backup()
        pins = self.pins(foreign_web=True)
        with self.assertRaisesRegex(storage.Refused, 'VERSION_APP_IDENTITY'):
            self.pin(pins)
        target = self.root/'B'
        with self.assertRaisesRegex(storage.Refused, 'VERSION_IMAGE_CHANGED'):
            self.engine.restore(self.bundle, target, self.version_file(pins))
        self.assertFalse(target.exists())
        proper = self.pins()
        self.engine.restore(self.bundle, target, self.root/'input-version.json')
        labels = self.io.image_data[proper['web-gateway']]['Config']['Labels']
        labels['org.opensamguk.local.build-args'] = self.args_hash(dict(self.record, appSha=self.B, serverId='lha'+'c'*16), 'web-gateway')
        with self.assertRaisesRegex(storage.Refused, 'TARGET_B_IMAGES'):
            self.engine.observe(target)


if __name__ == '__main__':
    unittest.main()
