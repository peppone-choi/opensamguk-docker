"""Synthetic reviewed route provenance; no real daemon, HTTP, custody or keys."""
import base64
import copy
import hashlib
import json
from pathlib import Path
import unittest
import urllib.error
from unittest.mock import patch

import recovery as r
import runtime_binding as route
import test_recovery as base
from storage import Refused, newdir, put, read, write, digest, seal
from transport import LocalIO
from test_transport import Response


class RuntimeBindingTests(unittest.TestCase):
    def setUp(self):
        base.RecoveryTests.setUp(self)
        self.reviewed_route_fixture()

    def reviewed_route_fixture(self):
        self.verifier = newdir(self.root / 'verifier')
        newdir(self.verifier / 'tools'); newdir(self.verifier / 'tools/localhost-acceptance')
        self.harness = b'FAKE REVIEWED PUBLIC HARNESS'
        put(self.verifier / 'tools/localhost-acceptance/harness.py', self.harness)
        self.sha = hashlib.sha256(self.harness).hexdigest()
        patched = patch.object(route, 'VERIFIER_HARNESS_SHA256', self.sha)
        patched.start(); self.addCleanup(patched.stop)
        self.dirty = False
        self.head = route.VERIFIER_HEAD
        # The legacy proof starts at d35, independently of later canonical main routes.
        self.old_nginx = (Path(__file__).parent / 'fixtures/nginx-d35.conf').read_bytes()
        self.assertEqual(hashlib.sha256(self.old_nginx).hexdigest(),
                         'e2a4a6fa66cf4a2583b83f90a7d38c13c6e7dad02e163f6974fc6029f83f4268')
        pattern = b'location ~ "^/api/battle-ws/'
        block = b'        location /api/battle-ws/ {\n            access_log off;\n            return 404;\n        }\n'
        alias = b'        location = /ws/battles {\n            access_log off;\n            return 404;\n        }\n        location /ws/battles/ {\n            access_log off;\n            return 404;\n        }\n'
        self.new_nginx = self.old_nginx.replace(pattern, b'location ~ "^/(?:api/battle-ws|ws/battles)/').replace(block, block + alias)
        self.assertEqual(hashlib.sha256(self.new_nginx).hexdigest(),
                         'd23ce61bb12751acb806e04cacd39bf73255bcd186c61171deb032cc7a753900')
        patched = patch.object(r.fresh, 'git', side_effect=self.git)
        patched.start(); self.addCleanup(patched.stop)
        self.record.update(dockerSha=route.BUILD_HEAD, profile='tactical', startupPaused=True,
                           nginxSha256=hashlib.sha256(self.old_nginx).hexdigest())
        fixtures = read(self.source / 'runtime.json')
        fixtures[r.fresh.TACTICAL_KEY] = base64.b64encode(b'z' * 32).decode()
        write(self.source / 'runtime.json', fixtures, replace=True)
        self.model = r.fresh.model_for(self.record, fixtures)
        write(self.source / 'compose.json', self.model, replace=True)
        self.record['configSha256'] = digest(self.source / 'compose.json')
        original = dict(self.record, status='RUNNING')
        write(self.source / route.PROOF_FILES[0], original)
        put(self.source / route.PROOF_FILES[1], self.old_nginx)
        put(self.source / 'nginx.conf', self.new_nginx, replace=True)
        self.record.update(runtimeVerifierHead=route.VERIFIER_HEAD,
            runtimeVerifierPath=str(self.verifier), runtimeVerifierHarnessSha256=self.sha,
            runtimeNginxSha256=hashlib.sha256(self.new_nginx).hexdigest(),
            runtimeNginxFileIdentity=route.file_identity(self.source / 'nginx.conf'),
            battleRouting={'schema': 1, 'file': route.ROUTE_FILE,
                          'sha256': hashlib.sha256(route.route_bytes(original)).hexdigest()})
        fields = {k: v for k, v in self.record.items() if k.startswith('runtime') or k == 'battleRouting'}
        write(self.source / route.PROOF_FILES[2], {'schema': 1,
            'originalContractSha256': digest(self.source / route.PROOF_FILES[0]), **fields})
        put(self.source / 'battle-ws' / route.ROUTE_FILE, route.route_bytes(original))
        write(self.source / 'contract.json', self.record, replace=True)
        install = self.io.install
        def aliases(record, model, running=True):
            install(record, model, running)
            for row in self.io.containers.values():
                if row['Config']['Labels'][r.fresh.PROJECT_LABEL] != record['project']:
                    continue
                svc = row['Config']['Labels']['com.docker.compose.service']
                row['NetworkSettings']['Networks'][record['project'] + '_local']['Aliases'] = (
                    [row['Name'], svc] + (['s' + record['serverId'] + '-game-api'] if svc == 'game-api' else []))
        self.io.install = aliases
        self.io.install(self.record, self.model)

    backup = base.RecoveryTests.backup

    def git(self, root, *args):
        if Path(root) == self.verifier:
            if args == ('rev-parse', '--show-toplevel'): return str(self.verifier).encode()
            if args == ('rev-parse', 'HEAD'): return self.head.encode()
            if args[0] in ('status', 'ls-files'): return b'dirty' if self.dirty else b''
            if args[0] == 'show':
                if args[1].endswith(':tools/localhost-acceptance/harness.py'): return self.harness
                return self.old_nginx if args[1].startswith(route.BUILD_HEAD + ':') else self.new_nginx
        if args[0] == 'show' and ':docker/' in args[-1]: return b'FROM fixture'
        if args[0] == 'show':
            path = args[-1].split(':', 1)[-1]
            if path in getattr(self, 'version_sources', {}): return self.version_sources[path]
        raise AssertionError('Unexpected synthetic public Git request')

    def version(self):
        pins = {s: base.image_id('B-' + s) for s in r.fresh.SERVICES}
        for svc, iid in pins.items():
            labels = r.fresh.image_metadata(dict(self.record, appSha='b' * 40, sourceTreeSha256='f' * 64), svc, {})
            self.io.image_data[iid] = {'Id': iid, 'RepoTags': [], 'Config': {'Labels': labels}}
        out = self.root / 'B.json'
        with patch.object(r.fresh, 'source_archive', return_value=b'fake archive'), patch.object(
                r.fresh, 'archive_tree_hash', return_value='f' * 64):
            self.engine.version(self.bundle, 'b' * 40, pins, out, self.root / 'B-source')
        return out

    def test_repaired_full_A_B_A_preserves_proofs_images_and_distinct_copy_inodes(self):
        original = {name: (self.source / name).read_bytes() for name in route.PROOF_FILES}
        inode = route.file_identity(self.source / 'nginx.conf')
        self.backup(); version = self.version()
        b, a = self.root / 'B', self.root / 'A-return'
        self.engine.restore(self.bundle, b, version)
        self.engine.observe(b); self.engine.stop_target(b)
        self.engine.rollback(self.bundle, b, a)
        self.engine.observe(a); self.engine.stop_target(a)
        self.assertTrue(self.engine.resume(self.bundle)['fullFlowObserved'])
        self.assertEqual(route.file_identity(self.source / 'nginx.conf'), inode)
        for target in (b, a):
            t = read(target / 'target.json')
            self.assertEqual(t['record']['runtimeNginxFileIdentity'], inode)
            self.assertNotEqual(t['runtimeBinding']['copiedNginxFileIdentity'], inode)
            self.assertEqual(t['record']['dockerSha'], route.BUILD_HEAD)
            for name, value in original.items():
                self.assertEqual((target / 'runtime' / name).read_bytes(), value)
                self.assertEqual((self.bundle / 'custody' / name).read_bytes(), value)
        self.assertFalse(any('/admin/turn-daemon/resume' in ' '.join(c) for c in self.io.calls))

    def test_replaced_live_inode_refuses_before_stop(self):
        path = self.source / 'nginx.conf'; replacement = self.source / 'replacement'
        put(replacement, path.read_bytes()); replacement.replace(path)
        with self.assertRaisesRegex(Refused, 'ROUTE_LIVE_INODE'): self.backup()
        self.assertFalse(any(c[1:2] == ['kill'] for c in self.io.calls))

    def test_verifier_wrong_head_or_dirty_refuses_before_stop(self):
        for mutation in ('head', 'dirty'):
            with self.subTest(mutation=mutation):
                self.head = 'c' * 40 if mutation == 'head' else route.VERIFIER_HEAD
                self.dirty = mutation == 'dirty'
                with self.assertRaisesRegex(Refused, 'ROUTE_VERIFIER_DIRTY_OR_HEAD'): self.backup()
                self.assertFalse(any(c[1:2] == ['kill'] for c in self.io.calls))

    def test_verifier_source_file_drift_refuses(self):
        put(self.verifier / 'tools/localhost-acceptance/harness.py', b'changed', replace=True)
        with self.assertRaisesRegex(Refused, 'ROUTE_VERIFIER_BYTES'): self.backup()

    def test_unknown_battle_route_alias_key_refuses(self):
        changed = dict(self.record, battle_route_override={'allow': 'foreign'})
        with self.assertRaisesRegex(Refused, 'ROUTE_UNKNOWN_BINDING'):
            route.snapshot(self.source, changed, r.fresh)

    def test_missing_or_changed_source_proof_refuses(self):
        path = self.source / route.PROOF_FILES[2]
        proof = read(path); proof['runtimeNginxSha256'] = '0' * 64
        write(path, proof, replace=True)
        with self.assertRaisesRegex(Refused, 'ROUTE_SOURCE_PROOF'): self.backup()

    def test_route_bytes_or_extra_file_refuses(self):
        put(self.source / 'battle-ws/foreign.map', b'foreign')
        with self.assertRaisesRegex(Refused, 'ROUTE_BYTES'): self.backup()

    def test_changed_route_bytes_refuses_before_stop(self):
        put(self.source / 'battle-ws' / route.ROUTE_FILE, b'foreign route', replace=True)
        with self.assertRaisesRegex(Refused, 'ROUTE_BYTES'): self.backup()
        self.assertFalse(any(c[1:2] == ['kill'] for c in self.io.calls))

    def test_missing_original_proof_refuses_before_stop(self):
        (self.source / route.PROOF_FILES[0]).unlink()
        with self.assertRaises(FileNotFoundError): self.backup()
        self.assertFalse(any(c[1:2] == ['kill'] for c in self.io.calls))

    def test_verifier_symlink_refuses_before_source_read(self):
        link = self.root / 'verifier-link'; link.symlink_to(self.verifier, target_is_directory=True)
        changed = dict(self.record, runtimeVerifierPath=str(link))
        with self.assertRaisesRegex(Refused, 'ROUTE_VERIFIER_SYMLINK'):
            route.snapshot(self.source, changed, r.fresh)

    def test_bundle_does_not_claim_archive_inode_is_live_source_inode(self):
        self.backup()
        archived = self.bundle / 'custody/nginx.conf'
        self.assertNotEqual(route.file_identity(archived), self.record['runtimeNginxFileIdentity'])
        route.snapshot(self.bundle / 'custody', self.record, r.fresh)
        with self.assertRaisesRegex(Refused, 'ROUTE_LIVE_INODE'):
            route.snapshot(self.bundle / 'custody', self.record, r.fresh, live=True)

    def test_snapshot_keeps_source_inode_and_separately_checks_copied_inode(self):
        self.backup(); target = self.root / 'A'
        self.engine.restore(self.bundle, target)
        path = target / 'runtime/nginx.conf'; replacement = target / 'replacement'
        put(replacement, path.read_bytes()); replacement.replace(path)
        with self.assertRaisesRegex(Refused, 'TARGET_RUNTIME_COPY_BINDING'): self.engine.target(target)

    def test_target_cannot_drop_or_change_runtime_provenance(self):
        self.backup(); target = self.root / 'A'; self.engine.restore(self.bundle, target)
        original = read(target / 'target.json')
        for key in ('runtimeVerifierHead', 'runtimeNginxSha256', 'battleRouting', 'dockerSha'):
            changed = copy.deepcopy(original); changed['record'].pop(key)
            write(target / 'target.json', changed, replace=True)
            with self.assertRaisesRegex(Refused, 'TARGET_RUNTIME_PROVENANCE'): self.engine.target(target)
        write(target / 'target.json', original, replace=True)

    def test_repaired_source_still_requires_six_different_B_images(self):
        self.backup()
        pins = {svc: self.record['images'][svc]['imageId'] for svc in r.fresh.SERVICES}
        with self.assertRaisesRegex(Refused, 'DIFFERENT_VERSION_IMAGES'):
            self.engine.version(self.bundle, 'b' * 40, pins, self.root / 'bad-B.json', self.root / 'B-source')
        self.assertFalse((self.root / 'bad-B.json').exists())

    def test_target_alias_collision_refuses(self):
        self.backup(); target = self.root / 'A'; self.engine.restore(self.bundle, target)
        t, model = self.engine.target(target)
        row = next(c for c in self.io.containers.values() if c['Config']['Labels'][r.fresh.PROJECT_LABEL] ==
                   t['record']['project'] and c['Config']['Labels']['com.docker.compose.service'] == 'board-api')
        row['NetworkSettings']['Networks'][t['record']['project'] + '_local']['Aliases'].append(
            's' + self.record['serverId'] + '-game-api')
        with self.assertRaisesRegex(Refused, 'ROUTE_FOREIGN_ALIAS'): self.engine.observe(target)

    def test_archive_proof_cannot_be_forged_even_if_resealed(self):
        self.backup(); proof = self.bundle / 'custody' / route.PROOF_FILES[2]
        changed = read(proof); changed['runtimeNginxFileIdentity']['inode'] += 1
        write(proof, changed, replace=True)
        m = read(self.bundle / 'manifest.json'); m['files'] = seal(self.bundle)
        write(self.bundle / 'manifest.json', m, replace=True)
        with self.assertRaisesRegex(Refused, 'ROUTE_SOURCE_PROOF'): self.engine.bundle(self.bundle)

    def test_tactical_boundaries_keep_both_aliases_and_foreign_world_and_id_denials(self):
        checks = route.boundaries(self.record)
        self.assertEqual(len(checks), 8)
        self.assertEqual([s for _, s in checks], [403, 404, 404, 404] * 2)
        self.assertEqual(len(route.boundaries({'serverId': self.record['serverId']})), 1)

    def probe(self, foreign_status=404):
        seen = []
        self.probe_seen = seen
        boundaries = dict(route.boundaries(self.record))
        boundaries['/api/gateway/auth/me'] = 401
        boundaries.update({'/d_pic/.ops/private': 404, '/game/': 404, '/': 200})
        class Opener:
            def open(inner, request, timeout):
                seen.append(request)
                if isinstance(request, str):
                    path = request.removeprefix('https://localhost')
                    status = foreign_status if '/foreign/' in path else boundaries[path]
                    if status >= 400: raise urllib.error.HTTPError(request, status, 'boundary', {}, None)
                    return Response(b'ok')
                path = request.full_url
                if path.endswith('/health'): return Response(b'ok')
                if path.endswith(('/api/auth/login', '/api/auth/me')):
                    return Response(b'{"user":{"id":7,"role":"USER"}}')
                if 'front-info' in path: return Response(b'{"general":{"generalId":2}}')
                return Response(b'{"status":"RESOLVED","ok":true}')
        adapter = LocalIO(newdir(self.root / ('probe-' + str(foreign_status))))
        with patch('transport.ssl.create_default_context'), patch(
                'transport.urllib.request.build_opener', return_value=Opener()):
            return adapter.user_probe(self.source, r.identity(self.record), 2, base.RID), seen

    def test_user_probe_enforces_tactical_aliases_before_normal_login(self):
        result, seen = self.probe()
        self.assertTrue(result['login'])
        paths = [p.removeprefix('https://localhost') for p in seen if isinstance(p, str)]
        self.assertTrue(all(path in paths for path, _ in route.boundaries(self.record)))

    def test_user_probe_foreign_403_refuses_without_login(self):
        with self.assertRaisesRegex(Refused, 'BOUNDARY_STATUS'): self.probe(foreign_status=403)
        self.assertFalse(any(not isinstance(req, str) and req.method == 'POST' for req in self.probe_seen))


if __name__ == '__main__': unittest.main()
