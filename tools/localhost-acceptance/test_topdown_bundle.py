"""Pure public fixtures only: no Docker, sockets, credentials, bake, image build or GUI."""
import copy
from contextlib import nullcontext, redirect_stdout
import gzip
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import shutil
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location('lha_map_harness', Path(__file__).with_name('harness.py'))
h = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(h)
t = h.topdown


class TopdownTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.sources = {}
        catalog = {'artifactId': t.RELEASE, 'cityCount': 1428, 'files': []}
        for key, name in t.INPUTS.items():
            data = ('public source ' + key).encode()
            compressed = gzip.compress(data, mtime=0)
            blob = 'blobs/' + t.sha(data) + '.json.gz'
            catalog['files'].append({'path': name, 'sha256': t.sha(data), 'blob': blob,
                                     'compressedSha256': t.sha(compressed)})
            self.sources[name] = data
            self.sources['data/map/' + t.RELEASE + '-artifacts/' + blob] = compressed
        self.sources[t.CATALOG] = t.canonical(catalog)
        kit = t.KIT + '/catalog.json'
        self.sources[kit] = b'public kit catalog'
        export = {'schemaVersion': 1, 'kitId': '273d596',
                  'source': {'repository': 'peppone-choi/opensamguk-images', 'mergeCommit': 'a' * 40},
                  'mirrors': ['web/game/public/map/waryong/273d596', 'web/gateway/public/map/waryong/273d596'],
                  'files': {kit: {'bytes': len(self.sources[kit]), 'sha256': t.sha(self.sources[kit])}}}
        self.sources[t.KIT + '/export.json'] = t.canonical(export)
        self.pins = t.source_pins(self.sources.__getitem__)
        raw = {'grid/L0/0_0.bin.gz': bytes(4 * 256 * 256), 'grid/L2.bin.gz': bytes(4 * 64 * 64),
               'places.json.gz': b'{"public":true}', 'defects.json': b'{}'}
        self.files = {name: gzip.compress(data, mtime=0) if name.endswith('.gz') else data for name, data in raw.items()}
        entries = {name: dict(file=name, bytes=len(self.files[name]), sha256=t.sha(self.files[name]),
                              rawSha256=t.sha(data), compression='gzip' if name.endswith('.gz') else 'none')
                   for name, data in raw.items()}
        fp = dict(self.pins['inputFingerprint'], region=None, bakeInputs=self.pins['kitInputs'])
        identity = dict(inputFingerprint=fp, mapRelease=t.RELEASE, kitVersion='273d596', formatVersion=1)
        self.bake_id = t.sha(t.canonical(identity))
        self.manifest = dict(identity, schemaVersion=1, artifactId='topdown-bake', bakeId=self.bake_id,
                             partial=False, shape={'cols': 256, 'rows': 256}, chunkSize=256, undrawnTile=65535,
                             chunks=[dict(entries['grid/L0/0_0.bin.gz'], cx=0, cy=0)], files=list(entries.values()),
                             overview=dict(entries['grid/L2.bin.gz'], cols=64, rows=64),
                             places=entries['places.json.gz'], defects=entries['defects.json'])
        self.bundle = self.root / self.bake_id
        self.bundle.mkdir()
        for name, data in self.files.items():
            path = self.bundle / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        self.write_manifest()

    def write_manifest(self):
        raw = t.canonical(self.manifest)
        (self.bundle / 'manifest.json').write_bytes(raw)
        self.manifest_sha = t.sha(raw)

    def validate(self, **kw):
        return t.validate(self.bundle, self.bake_id, self.manifest_sha, self.pins, **kw)

    def record(self):
        return dict(custody=str(self.root / 'custody'), topdown=self.validate())

    def model(self):
        record = dict(self.record(), nonce='0123456789abcdef', session='0' * 36,
                      project='osglha0123456789abcdef', serverId='lha0123456789abcdef', appSha='a'*40)
        fixtures = {key: 'fake' for key in ('DB_PASSWORD', 'JWT_PRIVATE_KEY', 'JWT_PUBLIC_KEY',
                                          'INTERNAL_TOKEN', 'DEPLOYER_TOKEN', 'ADMIN_USERNAME', 'ADMIN_PASSWORD')}
        return record, h.model_for(record, fixtures)

    def test_complete_bundle_uses_explicit_identity_manifest_and_source_pins(self):
        selected = self.validate()
        self.assertEqual({'bakeId', 'manifestSha256', 'sourcePins'}, set(selected))
        self.assertEqual(self.pins, selected['sourcePins'])

    def test_missing_or_wrong_explicit_pins_are_refused(self):
        for bake, manifest in [('', self.manifest_sha), ('a' * 64, self.manifest_sha),
                               (self.bake_id, '0' * 64), (self.bake_id, '')]:
            with self.subTest(bake=bake, manifest=manifest), self.assertRaises(t.Refused):
                t.validate(self.bundle, bake, manifest, self.pins)

    def test_partial_region_shape_chunk_and_public_inventory_are_refused(self):
        original = copy.deepcopy(self.manifest)
        for change in ({'partial': True}, {'chunkSize': 512}, {'chunks': []}, {'places': self.manifest['defects']},
                       {'shape': {'cols': 2**40, 'rows': 1}},
                       {'chunks': [dict(self.manifest['chunks'][0], file='grid/L0/1_0.bin.gz')]},
                       {'chunks': [{'cx':0,'cy':0,'uniform':{'tile':65535,'province':0},'rawSha256':'0'*64}]},
                       {'chunks': [{'cx':0,'cy':0,'uniform':{'tile':True,'province':0},'rawSha256':'0'*64}]}):
            with self.subTest(change=change), self.assertRaises(t.Refused):
                self.manifest = dict(original, **change); self.write_manifest(); self.validate()
        self.manifest = copy.deepcopy(original)
        self.manifest['inputFingerprint']['region'] = [0, 1, 0, 1]
        self.write_manifest()
        with self.assertRaisesRegex(t.Refused, 'FULL_BUNDLE'): self.validate()

    def test_different_active_world_or_kit_export_pins_are_refused(self):
        for group, key in [('inputFingerprint', 'tilesSha256'), ('inputFingerprint', 'worldJsonSha256'),
                           ('inputFingerprint', 'roadsSha256'), ('inputFingerprint', 'artifactCatalogSha256'),
                           ('kitInputs', 'kit/export.json'), ('kitInputs', 'kit/sourceMergeCommit')]:
            pins = copy.deepcopy(self.pins); pins[group][key] = '0' * 64
            with self.subTest(key=key), self.assertRaisesRegex(t.Refused, 'ACTIVE_INPUTS'):
                t.validate(self.bundle, self.bake_id, self.manifest_sha, pins)

    def test_source_catalog_blobs_and_kit_bytes_are_verified(self):
        for path in (t.INPUTS['tilesSha256'], next(k for k in self.sources if '/blobs/' in k), t.KIT + '/catalog.json'):
            sources = dict(self.sources); sources[path] += b'drift'
            with self.subTest(path=path), self.assertRaises(t.Refused):t.source_pins(sources.__getitem__)
        catalog=json.loads(self.sources[t.CATALOG]);catalog['files'][0]['blob']='../../.env'
        sources=dict(self.sources);sources[t.CATALOG]=t.canonical(catalog);read=Mock(side_effect=sources.__getitem__)
        with self.assertRaisesRegex(t.Refused,'SOURCE_BLOB_PATH'):t.source_pins(read)
        self.assertFalse(any('.env' in call.args[0] for call in read.call_args_list))

    def test_transport_raw_hash_and_missing_files_are_refused(self):
        path = self.bundle / 'places.json.gz'
        original = path.read_bytes(); path.write_bytes(original + b'drift')
        with self.assertRaisesRegex(t.Refused, 'TRANSPORT_HASH'):self.validate()
        path.write_bytes(original)
        self.manifest['files'][0]['rawSha256'] = '0' * 64
        self.manifest['chunks'][0]['rawSha256'] = '0' * 64;self.write_manifest()
        with self.assertRaisesRegex(t.Refused, 'RAW_HASH'):self.validate()
        self.manifest['files'][0]['rawSha256'] = t.sha(bytes(4*256*256))
        self.manifest['chunks'][0]['rawSha256'] = t.sha(bytes(4*256*256));self.write_manifest()
        path.unlink()
        with self.assertRaises(OSError):self.validate()

    def test_symlink_hardlink_extra_files_and_traversal_are_refused(self):
        extra = self.bundle / 'extra'; extra.write_bytes(b'no')
        with self.assertRaisesRegex(t.Refused, 'EXTRA_ENTRY'):self.validate()
        extra.unlink(); extra.symlink_to(self.bundle / 'defects.json')
        with self.assertRaisesRegex(t.Refused, 'SYMLINK'):self.validate()
        extra.unlink(); os.link(self.bundle / 'defects.json', extra)
        with self.assertRaises(t.Refused):self.validate()
        extra.unlink(); self.manifest['files'][0]['file'] = '../private'; self.write_manifest()
        with self.assertRaisesRegex(t.Refused, 'FILE_ENTRY'):self.validate()

    def test_copy_is_public_readable_and_source_bytes_remain_unchanged(self):
        selected = self.validate(); custody = self.root / 'custody'; custody.mkdir(mode=0o700)
        before = {p.relative_to(self.bundle): p.read_bytes() for p in self.bundle.rglob('*') if p.is_file()}
        t.copy_bundle(self.bundle, custody, selected)
        target = custody / 'topdown' / self.bake_id
        self.assertEqual(selected, t.validate(target, self.bake_id, self.manifest_sha, self.pins, True))
        self.assertEqual(before, {p.relative_to(self.bundle): p.read_bytes() for p in self.bundle.rglob('*') if p.is_file()})
        (target / 'defects.json').chmod(0o600)
        with self.assertRaisesRegex(t.Refused, 'PUBLIC_MODE'):t.validate(target, self.bake_id, self.manifest_sha, self.pins, True)

    def test_source_custody_overlap_both_directions_and_case_alias_are_refused(self):
        for custody in (self.bundle, self.bundle / 'new', self.root):
            with self.subTest(custody=custody), self.assertRaisesRegex(t.Refused, 'OUTPUT_OVERLAP'):
                t.copy_bundle(self.bundle, custody, self.validate())
        alias = self.root.with_name(self.root.name.upper()) / self.bake_id
        if not alias.exists():
            alias.mkdir(parents=True)
            self.addCleanup(shutil.rmtree,alias.parent)
        original = os.path.samefile
        def samefile(a, b):
            return (a == alias and b == self.bundle) or (b == alias and a == self.bundle) or original(a, b)
        with patch.object(t.os.path, 'samefile', side_effect=samefile):
            self.assertTrue(t.overlap(alias / 'new', self.bundle))

    def test_profile_adds_only_exact_game_api_readonly_mount_and_environment(self):
        record, model = self.model()
        env, mounts = t.settings(record)
        self.assertEqual({'TOPDOWN_MAP_ROOT': t.TARGET, 'TOPDOWN_BAKE_ID': self.bake_id}, env)
        self.assertEqual(mounts, model['services']['game-api'].get('volumes', []))
        self.assertEqual(str(self.root / 'custody/topdown'), mounts[0]['source'])
        self.assertEqual({'create_host_path': False}, mounts[0]['bind'])
        self.assertTrue(mounts[0]['read_only'])
        for svc in ('game-engine', 'gateway-api'):
            self.assertFalse(any(k.startswith('TOPDOWN_') for k in model['services'][svc]['environment']))

    def test_wrong_missing_extra_rw_and_foreign_map_mounts_are_refused(self):
        record, original = self.model()
        for delta in ({'source': '/foreign'}, {'target': '/other'}, {'read_only': False},
                      {'bind': {'create_host_path': True}}, {'type': 'volume'}):
            model = copy.deepcopy(original); model['services']['game-api']['volumes'][0].update(delta)
            with self.subTest(delta=delta), self.assertRaises(h.Refused):h.validate_model(model, record)
        for mounts in ([], original['services']['game-api']['volumes'] * 2):
            model = copy.deepcopy(original); model['services']['game-api']['volumes'] = mounts
            with self.assertRaises(h.Refused):h.validate_model(model, record)
        model = copy.deepcopy(original);model['services']['game-api']['environment']['TOPDOWN_BAKE_ID'] = 'f' * 64
        with self.assertRaises(h.Refused):h.validate_model(model, record)

    def test_runtime_mount_projection_requires_exact_readonly_source_and_destination(self):
        record, model = self.model(); service = model['services']['game-api']
        actual = [{'Type': 'bind', 'Source': record['custody'] + '/topdown', 'Destination': t.TARGET, 'RW': False}]
        h.verify_mounts(actual, service, model)
        for delta in ({'Source': '/foreign'}, {'Destination': '/other'}, {'RW': True}):
            with self.subTest(delta=delta), self.assertRaises(h.Refused):h.verify_mounts([dict(actual[0], **delta)], service, model)

    def test_incomplete_pin_or_mismatch_refuses_before_custody_docker_or_key_generation(self):
        custody = self.root / 'not-created'
        args = SimpleNamespace(source=self.root/'app',app_sha='a'*40,docker_sha='b'*40,custody=custody,
                               topdown_bundle=self.bundle,topdown_bake_id=self.bake_id,topdown_manifest_sha256=None)
        def git(repo, *argv):
            if argv[0] == 'rev-parse':return (args.app_sha if repo == args.source else args.docker_sha).encode()
            return b'public nginx'
        with patch.dict(os.environ,{'OPENSAMGUK_TASK_OWNER_SESSION':'0'*36}),patch.object(h,'git',side_effect=git), \
             patch.object(h,'source_archive',return_value=b'public archive'),patch.object(h,'inventory') as inventory, \
             patch.object(h,'port_free') as port,patch.object(h,'run') as run:
            with self.assertRaises(h.Refused):h.prepare(args)
            args.topdown_manifest_sha256='0'*64
            with patch.object(t,'source_pins',return_value=self.pins),self.assertRaises(t.Refused):h.prepare(args)
            self.assertFalse(custody.exists());inventory.assert_not_called();port.assert_not_called();run.assert_not_called()

    def test_profile_smoke_requires_actual_preview_binding_and_exact_manifest(self):
        record=self.record(); manifest=(self.bundle/'manifest.json').read_bytes()
        read=Mock(side_effect=lambda path: t.canonical({'topdownBakeId':self.bake_id}) if path=='/api/map/preview' else manifest)
        t.smoke(record,read);self.assertEqual(2,read.call_count)
        for preview in ({}, {'topdownBakeId':'f'*64}):
            with self.assertRaisesRegex(t.Refused,'PREVIEW_BINDING'):t.smoke(record,lambda _:t.canonical(preview))
        with self.assertRaisesRegex(t.Refused,'SERVED_MANIFEST'):
            t.smoke(record,lambda path:t.canonical({'topdownBakeId':self.bake_id}) if path=='/api/map/preview' else b'drift')
        read.reset_mock();t.smoke({},read);read.assert_not_called()

    def test_prepare_copies_then_revalidates_profile_before_any_future_runtime_use(self):
        custody=self.root/'new-custody'
        args=SimpleNamespace(source=self.root/'app',app_sha='a'*40,docker_sha='b'*40,custody=custody,
                             clone_source_custody=None,topdown_bundle=self.bundle,
                             topdown_bake_id=self.bake_id,topdown_manifest_sha256=self.manifest_sha)
        def git(repo,*argv):
            if argv[0]=='rev-parse':return (args.app_sha if repo==args.source else args.docker_sha).encode()
            return self.sources[argv[-1].split(':',1)[1]] if argv[-1].startswith(args.app_sha+':') else b'public nginx'
        def unpack(archive,directory):
            directory.mkdir(mode=0o700)
            for name,data in self.sources.items():
                path=directory/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
        def fake_openssl(argv,**kwargs):
            self.assertEqual('openssl',argv[0])
            if argv[1]=='genpkey':Path(argv[argv.index('-out')+1]).write_bytes(b'synthetic test key')
            if argv[1]=='req':
                for flag in ('-keyout','-out'):Path(argv[argv.index(flag)+1]).write_bytes(b'synthetic test cert')
            return b'synthetic test bytes'
        with patch.dict(os.environ,{'OPENSAMGUK_TASK_OWNER_SESSION':'0'*36}),patch.object(h,'git',side_effect=git), \
             patch.object(h,'source_archive',return_value=b'public archive'),patch.object(h,'unpack_archive',side_effect=unpack), \
             patch.object(h,'inventory',return_value={}),patch.object(h,'assert_owned'),patch.object(h,'port_free'), \
             patch.object(h,'run',side_effect=fake_openssl),redirect_stdout(__import__('io').StringIO()):
            h.prepare(args)
            record=json.loads((custody/'contract.json').read_bytes())
            model=h.verify_files(custody,record)
            self.assertEqual(self.validate(),record['topdown'])
            self.assertEqual(record['topdown']['bakeId'],model['services']['game-api']['environment']['TOPDOWN_BAKE_ID'])
            (custody/'topdown'/self.bake_id/'defects.json').write_bytes(b'drift')
            with self.assertRaisesRegex(t.Refused,'TRANSPORT_HASH'):h.verify_files(custody,record)

    def test_harness_smoke_cannot_mark_passed_without_profile_binding(self):
        record,model=self.model();record['status']='RUNNING'
        for valid in (True,False):
            candidate=copy.deepcopy(record)
            def compose(directory,rec,*args,**kwargs):
                if args[2]=='nginx':return b''
                return (t.canonical({'topdownBakeId':self.bake_id} if valid else {})
                        if args[-1].endswith('/preview') else (self.bundle/'manifest.json').read_bytes())
            opener=SimpleNamespace(open=Mock(side_effect=[nullcontext(SimpleNamespace(status=s)) for s in (200,401,404,404,404,200)]))
            with patch.object(h,'load',return_value=(self.root,candidate)),patch.object(h,'verify_files',return_value=model), \
                 patch.object(h,'verify_images'),patch.object(h,'verify_running'),patch.object(h,'inventory'), \
                 patch.object(h,'compose',side_effect=compose),patch.object(h.ssl,'create_default_context'), \
                 patch.object(h.urllib.request,'build_opener',return_value=opener),patch.object(h,'sql',side_effect=['160','1']), \
                 patch.object(h,'startup_disk_check'),patch.object(h,'write_json') as write,redirect_stdout(__import__('io').StringIO()):
                if valid:
                    h.smoke(SimpleNamespace(custody=self.root));self.assertEqual('SMOKE_PASSED',candidate['status'])
                    write.assert_called_once()
                else:
                    with self.assertRaisesRegex(t.Refused,'PREVIEW_BINDING'):h.smoke(SimpleNamespace(custody=self.root))
                    self.assertEqual('RUNNING',candidate['status']);write.assert_not_called()


if __name__ == '__main__':
    unittest.main()
