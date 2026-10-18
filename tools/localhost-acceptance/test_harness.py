import copy
import base64
import datetime
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('lha_harness', Path(__file__).with_name('harness.py'))
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)


class HarnessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name).resolve()
        self.directory.chmod(0o700)
        self.record = {'nonce': '0123456789abcdef', 'session': '01a14994-f8a1-7282-9f45-f9d3c5390cee',
                       'project': 'osglha0123456789abcdef', 'serverId': 'lha0123456789abcdef',
                       'origin': h.ORIGIN, 'worldId': 160, 'generation': 0, 'custody': str(self.directory),
                       'appSha': 'a'*40, 'dockerSha': 'b'*40, 'sourceTreeSha256': 'c'*64, 'images': {}}
        self.fixture = {k: 'testvalue' for k in ('DB_PASSWORD', 'JWT_PRIVATE_KEY', 'JWT_PUBLIC_KEY',
                        'INTERNAL_TOKEN', 'DEPLOYER_TOKEN', 'ADMIN_USERNAME', 'ADMIN_PASSWORD')}
        (self.directory / 'source/docker').mkdir(parents=True)
        for svc in h.SERVICES:
            (self.directory / 'source/docker' / (svc + '.Dockerfile')).write_text('FROM scratch\n')
        self.model = h.model_for(self.record, self.fixture)

    def rejects(self, change):
        model = copy.deepcopy(self.model)
        change(model)
        with self.assertRaises(h.Refused):
            h.validate_model(model, self.record)

    def tactical(self):
        record = {**self.record, 'profile': 'tactical'}
        fixture = h.profile_fixtures(record, self.fixture)
        return record, fixture, h.model_for(record, fixture)

    def test_standard_profile_keeps_existing_model_and_does_not_generate_a_key(self):
        with patch.object(h.secrets, 'token_bytes', side_effect=AssertionError('unexpected generation')):
            self.assertIs(self.fixture, h.profile_fixtures(self.record, self.fixture))
            self.assertEqual(self.model, h.model_for({**self.record, 'profile': 'standard'}, self.fixture))
        self.assertNotIn(h.TACTICAL_KEY, self.fixture)
        self.rejects(lambda m: m['services']['game-api']['environment'].update(BATTLE_SESSION_ENABLED='true'))

    def test_tactical_profile_changes_only_exact_api_and_engine_environment_keys(self):
        record, fixture, model = self.tactical()
        api, engine = (model['services'][service]['environment'] for service in ('game-api', 'game-engine'))
        self.assertEqual(h.TACTICAL_API, {key: api[key] for key in h.TACTICAL_API})
        self.assertEqual(h.TACTICAL_ENGINE, {key: engine[key] for key in h.TACTICAL_ENGINE})
        self.assertEqual(record['serverId'], api['SERVER_ID'])
        self.assertEqual('160', api['OPENSAMGUK_WORLD_ID'])
        self.assertEqual(fixture[h.TACTICAL_KEY], api[h.TACTICAL_KEY])
        stripped = copy.deepcopy(model)
        for key in {*h.TACTICAL_API, h.TACTICAL_KEY}:
            del stripped['services']['game-api']['environment'][key]
        for key in h.TACTICAL_ENGINE:
            del stripped['services']['game-engine']['environment'][key]
        self.assertEqual(self.model, stripped)

    def test_tactical_signing_keys_are_fresh_canonical_private_fixture_values(self):
        record = {**self.record, 'profile': 'tactical'}
        first, second = (h.profile_fixtures(record, self.fixture) for _ in range(2))
        self.assertNotEqual(first[h.TACTICAL_KEY], second[h.TACTICAL_KEY])
        self.assertNotIn(h.TACTICAL_KEY, self.fixture)
        self.assertEqual(32, len(base64.b64decode(first[h.TACTICAL_KEY], validate=True)))
        path = self.directory / 'private-profile-fixture.json'
        h.write_json(path, first)
        self.assertEqual(0o600, path.stat().st_mode & 0o777)
        with self.assertRaises(h.Refused):
            h.profile_fixtures(record, first)

    def test_tactical_missing_or_invalid_key_fails_without_echoing_it(self):
        record = {**self.record, 'profile': 'tactical'}
        invalid = [None, '', 'not-a-private-key!', base64.b64encode(b'x' * 16).decode(),
                   base64.b64encode(b'x' * 33).decode()]
        for key in invalid:
            with self.subTest(kind=type(key).__name__):
                fixture = dict(self.fixture)
                if key is not None:
                    fixture[h.TACTICAL_KEY] = key
                with self.assertRaises(h.Refused) as caught:
                    h.model_for(record, fixture)
                if key:
                    self.assertNotIn(key, str(caught.exception))

    def test_tactical_key_cannot_reuse_or_escape_to_other_service_secrets(self):
        record, fixture, model = self.tactical()
        reused = {**fixture, 'DB_PASSWORD': fixture[h.TACTICAL_KEY]}
        with self.assertRaises(h.Refused):
            h.model_for(record, reused)
        for service in h.SERVICES:
            if service == 'game-api':
                continue
            changed = copy.deepcopy(model)
            changed['services'][service]['environment'][h.TACTICAL_KEY] = fixture[h.TACTICAL_KEY]
            with self.assertRaises(h.Refused):
                h.validate_model(changed, record)

    def test_tactical_flags_origin_server_world_and_internal_url_are_exact(self):
        record, _, model = self.tactical()
        changes = [('game-api', key, 'false') for key in h.TACTICAL_API]
        changes += [('game-api', 'SERVER_ID', 'foreign'), ('game-api', 'OPENSAMGUK_WORLD_ID', '1'),
                    ('game-engine', 'OPENSAMGUK_WORLD_ID', '1'),
                    ('game-engine', 'BATTLE_PIPELINE_ENABLED', 'false'),
                    ('game-engine', 'BATTLE_PIPELINE_API_BASE_URL', 'http://external.invalid:8081')]
        for service, key, value in changes:
            with self.subTest(service=service, key=key):
                changed = copy.deepcopy(model)
                changed['services'][service]['environment'][key] = value
                with self.assertRaises(h.Refused):
                    h.validate_model(changed, record)

    def test_unknown_profile_is_refused_before_prepare_dependencies_or_writes(self):
        from types import SimpleNamespace
        for value in ('other', None, False, 1):
            with self.subTest(kind=type(value).__name__):
                with self.assertRaises(h.Refused):
                    h.model_for({**self.record, 'profile': value}, self.fixture)
        with patch.object(h, 'git', side_effect=AssertionError('unexpected dependency')):
            with self.assertRaises(h.Refused):
                h.prepare(SimpleNamespace(profile='other'))

    def ready_payload(self):
        payload = {key: 'a' * 64 for key in ('dbFingerprint', 'nativeFenceSha256', 'ruleSha256',
                                           'catalogSha256', 'combatSha256', 'spaceSha256')}
        payload.update(schemaVersion=1, status='READY', worldId=160, reasons=[],
                       moraleEncoding='CAMPAIGN_NATIVE_D177_V1', checkedAt='2026-10-18T00:00:00Z')
        now = datetime.datetime(2026, 10, 18, tzinfo=datetime.timezone.utc).timestamp()
        return payload, now

    def test_tactical_readiness_requires_current_exact_contract_not_just_http200(self):
        payload, now = self.ready_payload()
        h.validate_tactical_readiness(payload, self.record, now=now)
        h.validate_tactical_readiness(payload, self.record, now=now + 5)
        for key, value in [('schemaVersion', True), ('worldId', True), ('worldId', 1), ('status', 'NOT_READY'),
                           ('reasons', ['SCANNER_STALE']), ('moraleEncoding', 'SOLDIER_RAW_0_200'),
                           ('dbFingerprint', None), ('ruleSha256', 'A' * 64), ('checkedAt', 'invalid'),
                           ('checkedAt', '2026-10-18T09:00:00+09:00')]:
            with self.subTest(key=key):
                with self.assertRaises(h.Refused):
                    h.validate_tactical_readiness({**payload, key: value}, self.record, now=now)
        for observed in (now - 0.01, now + 5.01):
            with self.assertRaises(h.Refused):
                h.validate_tactical_readiness(payload, self.record, now=observed)
        with self.assertRaises(h.Refused):
            h.validate_tactical_readiness({**payload, 'unexpected': True}, self.record, now=now)

    def test_tactical_smoke_uses_owned_api_and_rejects_unexposed_redirect_or_oversized_response(self):
        payload, now = self.ready_payload()
        calls = []
        def compose(*args, **kwargs):
            calls.append(args)
            return json.dumps(payload).encode() + b'\nSTATUS:200'
        with patch.object(h, 'compose', side_effect=compose), patch.object(h.time, 'time', return_value=now):
            h.tactical_smoke(self.directory, self.record)
        self.assertIn('game-api', calls[0])
        self.assertIn('http://127.0.0.1:8081/internal/battles/pipeline-readiness?worldId=160', calls[0])
        self.assertNotIn('-L', calls[0])
        for raw in (b'not-json\nSTATUS:200', b'{}\nSTATUS:404', b'{}\nSTATUS:302',
                    b'x' * 16385 + b'\nSTATUS:200'):
            with patch.object(h, 'compose', return_value=raw):
                with self.assertRaises(h.Refused):
                    h.tactical_smoke(self.directory, self.record)

    def test_tactical_smoke_rejects_duplicate_readiness_fields_before_validation(self):
        payload, now = self.ready_payload()
        original = json.dumps(payload).encode()
        for extra in (b'"status":"NOT_READY",', b'"worldId":1,', b'"reasons":["SCANNER_STALE"],'):
            # A normal JSON decoder keeps the later READY value and hides the contradiction.
            body = b'{' + extra + original[1:]
            self.assertEqual(payload, json.loads(body))
            with self.subTest(field=extra), patch.object(h, 'compose', return_value=body + b'\nSTATUS:200'), \
                 patch.object(h.time, 'time', return_value=now), \
                 patch.object(h, 'validate_tactical_readiness') as validate:
                with self.assertRaisesRegex(h.Refused, 'duplicate fields'):
                    h.tactical_smoke(self.directory, self.record)
                validate.assert_not_called()

    def test_smoke_requires_403_for_tactical_and_refuses_its_disabled_404(self):
        from unittest.mock import MagicMock
        for mode, websocket_status, accepted in [('standard', 404, True), ('tactical', 403, True),
                                                  ('tactical', 404, False)]:
            with self.subTest(mode=mode, websocket_status=websocket_status):
                record = {**self.record, 'profile': mode, 'status': 'RUNNING'}
                opener = MagicMock()
                def response(url, **kwargs):
                    status = websocket_status if '/api/battle-ws/' in url else 401 if '/auth/me' in url else (
                        404 if '/d_pic/' in url or url.endswith('/game/') else 200)
                    result = MagicMock()
                    result.__enter__.return_value.status = status
                    return result
                opener.open.side_effect = response
                with patch.object(h, 'load', return_value=(self.directory, record)), \
                     patch.object(h, 'verify_files', return_value=self.model), \
                     patch.object(h, 'verify_images'), patch.object(h, 'verify_running'), \
                     patch.object(h, 'inventory', return_value={}), patch.object(h, 'compose'), \
                     patch.object(h.ssl, 'create_default_context'), \
                     patch.object(h.urllib.request, 'build_opener', return_value=opener), \
                     patch.object(h, 'sql', side_effect=['160', '1']), \
                     patch.object(h, 'startup_disk_check'), patch.object(h, 'write_json') as written, \
                     patch.object(h, 'tactical_smoke') as readiness:
                    if accepted:
                        h.smoke(type('Args', (), {'custody': self.directory})())
                        self.assertEqual('SMOKE_PASSED', record['status'])
                        self.assertEqual(int(mode == 'tactical'), readiness.call_count)
                    else:
                        with self.assertRaises(h.Refused):
                            h.smoke(type('Args', (), {'custody': self.directory})())
                        self.assertEqual('RUNNING', record['status'])
                        readiness.assert_not_called()
                        written.assert_not_called()

    def test_privileged_port_probe_handles_mac_denial_without_ignoring_listener(self):
        from unittest.mock import MagicMock
        import errno
        primary, probe = MagicMock(), MagicMock()
        primary.bind.side_effect = OSError(errno.EACCES,'denied')
        probe.connect_ex.return_value = errno.ECONNREFUSED
        primary.__enter__.return_value = primary
        probe.__enter__.return_value = probe
        with patch.object(h.socket,'socket',side_effect=[primary,probe]):
            h.port_free()
        probe.connect_ex.return_value = 0
        with patch.object(h.socket,'socket',side_effect=[primary,probe]):
            with self.assertRaises(h.Refused): h.port_free()
        primary.bind.side_effect = OSError(errno.EADDRINUSE,'occupied')
        with patch.object(h.socket,'socket',return_value=primary):
            with self.assertRaises(h.Refused): h.port_free()

    def test_valid_model_is_separate_auth_world_and_no_private_key_in_verifiers(self):
        h.validate_model(self.model, self.record)
        services = self.model['services']
        self.assertIn('gateway-postgres', services['board-api']['environment']['GAME_DATABASE_URL'])
        self.assertIn('game-postgres', services['game-api']['environment']['GAME_DATABASE_URL'])
        self.assertNotIn('JWT_PRIVATE_KEY', services['game-api']['environment'])
        self.assertNotIn('JWT_PRIVATE_KEY', services['board-api']['environment'])
        self.assertEqual('160', services['game-engine']['environment']['OPENSAMGUK_WORLD_ID'])
        self.assertEqual('false', str(services['game-engine'].get('privileged', False)).lower())

    def test_non_loopback_or_extra_port_is_refused(self):
        for host in ('0.0.0.0', '::', '127.0.0.2', ''):
            self.rejects(lambda m: m['services']['nginx']['ports'][0].update(host_ip=host))
        self.rejects(lambda m: m['services']['game-api'].update(ports=[{'target': 8081, 'published': '8081'}]))
        self.rejects(lambda m: m['services']['nginx']['ports'][0].update(published='19443'))

    def test_external_network_and_volume_refused(self):
        self.rejects(lambda m: m['networks']['local'].update(external=True))
        self.rejects(lambda m: m['volumes']['game-pgdata'].update(external=True))
        self.rejects(lambda m: m['volumes']['game-pgdata'].update(name='qa160'))
        self.rejects(lambda m: m['services']['game-api'].update(network_mode='host'))
        self.rejects(lambda m: m['networks']['local'].update(driver='host'))

    def test_bind_socket_or_existing_db_refused(self):
        for source in ('/var/run/docker.sock', '/tmp/qa160', '/etc/nginx/nginx.conf'):
            self.rejects(lambda m: m['services']['nginx']['volumes'][0].update(source=source))
        self.rejects(lambda m: m['services']['nginx']['volumes'][0].update(read_only=False))
        self.rejects(lambda m: m['services']['game-api'].update(env_file=['.env']))
        self.rejects(lambda m: m['services']['game-api'].update(privileged=True))

    def test_foreign_image_service_alias_and_owner_refused(self):
        self.rejects(lambda m: m['services']['game-api'].update(image='ghcr.io/example:main'))
        self.rejects(lambda m: m['services']['game-api'].update(container_name='opensamguk-qa160-game-api'))
        self.rejects(lambda m: m['services']['game-api']['labels'].update({h.NONCE_LABEL: 'other'}))
        self.rejects(lambda m: m['services']['game-api'].update(build='.'))

    def resource(self, kind, **changes):
        own = {**h.labels(self.record), h.PROJECT_LABEL: self.record['project']}
        row = {'Name': self.record['project'] + ('-game-api-1' if kind=='container' else '_local'), 'Labels': own}
        if kind == 'container':
            row['Config'] = {'Labels': own}
        row.update(changes)
        return row

    def test_inventory_and_image_inspect_never_request_env_or_health_log(self):
        own=self.resource('container',Id='owned')
        calls=[]
        def run(args,**kwargs):
            calls.append(args)
            if 'inspect' in args:
                self.assertIn('--format',args)
                projection=args[args.index('--format')+1]
                self.assertNotIn('.Env',projection)
                self.assertNotIn('.Log',projection)
                self.assertNotIn('.Options',projection)
                return json.dumps(own).encode()
            return b'owned\n'
        with patch.object(h,'run',side_effect=run):
            resources=h.inventory(self.record)
            h.inspect_image('public-image')
        self.assertEqual(3,len(resources))
        self.assertEqual(4,len([args for args in calls if 'inspect' in args]))

    def test_real_support_image_inspect_projection_excludes_environment(self):
        if not __import__('shutil').which('docker'):self.skipTest('docker absent')
        try:exists=h.run(['docker','image','ls','-q','--filter','reference=postgres:16-alpine'])
        except h.Refused:self.skipTest('local Docker daemon unavailable')
        if not exists.strip():self.skipTest('local support image absent')
        image=h.inspect_image('postgres:16-alpine')
        self.assertEqual({'Id','RepoTags','Config'},set(image))
        self.assertEqual({'Labels'},set(image['Config']))
        self.assertTrue(image['Id'].startswith('sha256:'))

    def test_name_alone_or_nonce_alone_does_not_authorize_cleanup(self):
        for kind in ('container', 'network', 'volume'):
            row = self.resource(kind)
            h.assert_owned(self.record, {kind: [row]})
            own = row['Config']['Labels'] if kind=='container' else row['Labels']
            for key in (h.NONCE_LABEL, h.SESSION_LABEL, h.PROJECT_LABEL):
                bad = copy.deepcopy(row)
                target = bad['Config']['Labels'] if kind=='container' else bad['Labels']
                target[key] = 'foreign'
                with self.assertRaises(h.Refused):
                    h.assert_owned(self.record, {kind: [bad]})
            with self.assertRaises(h.Refused):
                h.assert_owned(self.record, {kind: [row]}, empty=True)
        h.assert_owned(self.record, {'container': [], 'network': [], 'volume': []}, empty=True)

    def test_nonce_identity_session_and_world_are_bound(self):
        with patch.dict(os.environ, OPENSAMGUK_TASK_OWNER_SESSION=self.record['session']):
            h.identity(self.record)
            for key, value in [('project','opensamguk-qa160'), ('serverId','qa160'), ('worldId',1),
                               ('generation',1), ('origin','http://localhost'), ('session','other')]:
                bad = {**self.record, key: value}
                with self.assertRaises(h.Refused):
                    h.identity(bad)

    def test_source_digest_detects_bytes_mode_and_symlink_changes(self):
        source = self.directory / 'source'
        expected = h.tree_hash(source)
        p = source / 'docker/game-api.Dockerfile'
        p.write_text('FROM changed')
        self.assertNotEqual(expected, h.tree_hash(source))
        expected = h.tree_hash(source)
        p.chmod(0o755)
        self.assertNotEqual(expected, h.tree_hash(source))
        p.unlink()
        p.symlink_to('/etc/passwd')
        with self.assertRaises(h.Refused):
            h.tree_hash(source)

    def test_archive_refuses_path_traversal_symlink_and_tracked_key(self):
        for name, kind in [('../escape', tarfile.REGTYPE), ('key.pem', tarfile.REGTYPE),
                           ('.env',tarfile.REGTYPE), ('link',tarfile.SYMTYPE),
                           ('hardlink', tarfile.LNKTYPE), ('pipe', tarfile.FIFOTYPE),
                           ('device', tarfile.CHRTYPE), ('/outside', tarfile.REGTYPE)]:
            data = io.BytesIO()
            with tarfile.open(fileobj=data, mode='w') as tar:
                member = tarfile.TarInfo(name)
                member.type = kind
                member.linkname = '/etc/passwd' if kind == tarfile.SYMTYPE else ''
                tar.addfile(member)
            destination = self.directory / ('bad' + str(len(list(self.directory.iterdir()))))
            with self.assertRaises(h.Refused):
                h.unpack_archive(data.getvalue(), destination)
            self.assertFalse(destination.exists())

    def public_archive(self):
        data = io.BytesIO()
        files = {'public/battle/asset.json': (b'{"public":true}', 0o644),
                 'bin/start': (b'#!/bin/sh\nexit 0\n', 0o755)}
        with tarfile.open(fileobj=data, mode='w') as tar:
            for name in ('public', 'public/battle', 'bin'):
                member = tarfile.TarInfo(name)
                member.type = tarfile.DIRTYPE
                member.mode = 0o755
                tar.addfile(member)
            for name, (body, mode) in files.items():
                member = tarfile.TarInfo(name)
                member.mode, member.size = mode, len(body)
                tar.addfile(member, io.BytesIO(body))
        return data.getvalue(), files

    def assert_public_export(self, destination, archive, files):
        for directory in (destination, destination/'public', destination/'public/battle', destination/'bin'):
            self.assertEqual(0o755, directory.stat().st_mode & 0o777)
        for name, (body, mode) in files.items():
            self.assertEqual(body, (destination/name).read_bytes())
            self.assertEqual(mode, (destination/name).stat().st_mode & 0o777)
        self.assertEqual(h.archive_tree_hash(archive), h.tree_hash(destination))

    def test_archive_export_under_private_umask_preserves_files_and_private_boundary(self):
        archive, files = self.public_archive()
        private = self.directory/'private'
        private.mkdir(mode=0o700)
        key = private/'test-fixture.key'
        h.private_write(key, b'new-test-fixture')
        destination = self.directory/'public-export'
        before = os.umask(0o077)
        try:
            h.unpack_archive(archive, destination)
        finally:
            os.umask(before)
        self.assert_public_export(destination, archive, files)
        self.assertEqual(0o700, self.directory.stat().st_mode & 0o777)
        self.assertEqual(0o700, private.stat().st_mode & 0o777)
        self.assertEqual(0o600, key.stat().st_mode & 0o777)
        self.assertEqual(b'new-test-fixture', key.read_bytes())

    def test_clone_normalizes_only_destination_under_private_umask(self):
        archive, files = self.public_archive()
        source, destination = self.directory/'original-public', self.directory/'cloned-public'
        h.unpack_archive(archive, source)
        private = self.directory/'clone-private-fixture.json'
        h.private_write(private, b'private-clone-test-fixture')
        original_directories = [source, *[p for p in source.rglob('*') if p.is_dir()]]
        for directory in original_directories:
            directory.chmod(0o700)
        source_hash = h.tree_hash(source)

        def clone(args, **kwargs):
            self.assertEqual(['/bin/cp', '-cRp', str(source), str(destination)], args)
            shutil.copytree(source, destination)

        before = os.umask(0o077)
        try:
            with patch.object(h, 'run', side_effect=clone):
                h.clone_export(archive, source, destination)
        finally:
            os.umask(before)
        self.assert_public_export(destination, archive, files)
        self.assertEqual(source_hash, h.tree_hash(source))
        for directory in original_directories:
            self.assertEqual(0o700, directory.stat().st_mode & 0o777)
        for name, (body, mode) in files.items():
            self.assertEqual(body, (source/name).read_bytes())
            self.assertEqual(mode, (source/name).stat().st_mode & 0o777)
        self.assertEqual(0o700, self.directory.stat().st_mode & 0o777)
        self.assertEqual(0o600, private.stat().st_mode & 0o777)
        self.assertEqual(b'private-clone-test-fixture', private.read_bytes())
        self.assertFalse((destination/private.name).exists())

    def test_normalization_refuses_links_and_special_files_before_any_chmod(self):
        outside = self.directory/'outside-private'
        outside.mkdir(mode=0o700)
        marker = outside/'marker'
        h.private_write(marker, b'untouched')
        for kind in ('symlink', 'fifo'):
            with self.subTest(kind=kind):
                root = self.directory/kind
                nested = root/'public'
                nested.mkdir(parents=True, mode=0o700)
                root.chmod(0o700)
                if kind == 'symlink':
                    (nested/'unsafe').symlink_to(outside, target_is_directory=True)
                else:
                    os.mkfifo(nested/'unsafe')
                with patch.object(h.os, 'fchmod', wraps=os.fchmod) as chmod:
                    with self.assertRaises(h.Refused):
                        h.normalize_export_directories(root)
                    chmod.assert_not_called()
                self.assertEqual(0o700, root.stat().st_mode & 0o777)
                self.assertEqual(0o700, nested.stat().st_mode & 0o777)
        self.assertEqual(0o700, outside.stat().st_mode & 0o777)
        self.assertEqual(0o600, marker.stat().st_mode & 0o777)
        self.assertEqual(b'untouched', marker.read_bytes())

    def test_export_refuses_symlink_parents_and_traversal_before_outside_changes(self):
        archive, _ = self.public_archive()
        outside = self.directory/'outside'
        outside.mkdir(mode=0o700)
        alias = self.directory/'alias'
        alias.symlink_to(outside, target_is_directory=True)
        for target in (alias/'export', self.directory/'missing/../escape'):
            with self.subTest(target=str(target)), self.assertRaises(h.Refused):
                h.unpack_archive(archive, target)
        self.assertEqual([], list(outside.iterdir()))
        self.assertEqual(0o700, outside.stat().st_mode & 0o777)

    def test_clone_rejects_unsafe_source_before_hash_or_copy(self):
        archive, _ = self.public_archive()
        for kind in ('symlink-root', 'symlink-child', 'fifo'):
            with self.subTest(kind=kind):
                source = self.directory/kind
                if kind == 'symlink-root':
                    source.symlink_to(self.directory/'source', target_is_directory=True)
                else:
                    h.unpack_archive(archive, source)
                    if kind == 'symlink-child':
                        (source/'unsafe').symlink_to(self.directory/'source', target_is_directory=True)
                    else:
                        os.mkfifo(source/'unsafe')
                destination = self.directory/('clone-'+kind)
                with patch.object(h, 'tree_hash') as digest, patch.object(h, 'run') as clone:
                    with self.assertRaises(h.Refused):
                        h.clone_export(archive, source, destination)
                    digest.assert_not_called()
                    clone.assert_not_called()
                self.assertFalse(destination.exists())

    def test_clone_refuses_destination_inside_source(self):
        archive, _ = self.public_archive()
        source = self.directory/'original-public'
        h.unpack_archive(archive, source)
        source.chmod(0o700)
        with patch.object(h, 'run') as clone:
            with self.assertRaises(h.Refused):
                h.clone_export(archive, source, source/'recursive-copy')
            clone.assert_not_called()

    def test_clone_refuses_unsafe_copy_result_before_hash_or_chmod(self):
        archive, _ = self.public_archive()
        source, destination = self.directory/'original-public', self.directory/'cloned-public'
        h.unpack_archive(archive, source)
        digest = h.tree_hash

        def hash_source_only(path):
            self.assertEqual(source, path)
            return digest(path)

        def unsafe_copy(*args, **kwargs):
            shutil.copytree(source, destination)
            (destination/'unsafe').symlink_to(self.directory/'source', target_is_directory=True)

        with patch.object(h, 'run', side_effect=unsafe_copy), \
                patch.object(h, 'tree_hash', side_effect=hash_source_only), \
                patch.object(h.os, 'fchmod', wraps=os.fchmod) as chmod:
            with self.assertRaises(h.Refused):
                h.clone_export(archive, source, destination)
            chmod.assert_not_called()

    def test_apfs_clone_matches_archive_and_preserves_original_on_later_write(self):
        if sys.platform!='darwin':self.skipTest('APFS clone is macOS-only')
        data=io.BytesIO()
        with tarfile.open(fileobj=data,mode='w') as tar:
            member=tarfile.TarInfo('file');member.mode=0o644;member.size=8
            tar.addfile(member,io.BytesIO(b'original'))
        archive=data.getvalue()
        source=self.directory/'original-export'
        h.unpack_archive(archive,source)
        self.assertEqual(h.archive_tree_hash(archive),h.tree_hash(source))
        source.chmod(0o700)
        destination=self.directory/'clone-export'
        before=os.umask(0o077)
        try:h.clone_export(archive,source,destination)
        finally:os.umask(before)
        self.assertEqual(0o755,destination.stat().st_mode & 0o777)
        self.assertEqual(0o700,source.stat().st_mode & 0o777)
        (destination/'file').write_text('changed')
        self.assertEqual('original',(source/'file').read_text())
        (source/'file').write_text('wrong')
        with self.assertRaises(h.Refused):h.clone_export(archive,source,self.directory/'bad-clone')

    def test_private_write_refuses_existing_file_and_symlink(self):
        path = self.directory / 'fixture.json'
        h.private_write(path, b'new-local-fixture')
        self.assertEqual(0o600, path.stat().st_mode & 0o777)
        with self.assertRaises(FileExistsError):
            h.private_write(path, b'changed')
        path.unlink()
        path.symlink_to(self.directory / 'source/docker/game-api.Dockerfile')
        with self.assertRaises(OSError):
            h.private_write(path, b'changed', replace=True)
        self.assertEqual('FROM scratch\n', (self.directory / 'source/docker/game-api.Dockerfile').read_text())

    def image(self, svc='game-api'):
        image = {'Id': 'sha256:' + 'd'*64, 'RepoTags': [h.image_ref(self.record, svc)],
                 'Config': {'Labels': h.image_metadata(self.record, svc, {})}}
        self.record['images'][svc] = {'imageId': image['Id'], 'dockerfileSha256': image['Config']['Labels']['org.opensamguk.local.dockerfile'],
                                       'buildArgs': h.build_args(self.record, svc)}
        return image

    def test_image_id_revision_dockerfile_and_public_build_args_are_verified(self):
        image = self.image()
        h.check_image(self.record, 'game-api', image)
        for key in h.image_metadata(self.record, 'game-api', {}):
            bad = copy.deepcopy(image)
            bad['Config']['Labels'][key] = 'changed'
            with self.assertRaises(h.Refused):
                h.check_image(self.record, 'game-api', bad)
        image['Id'] = 'sha256:' + 'e'*64
        with self.assertRaises(h.Refused):
            h.check_image(self.record, 'game-api', image)
        image = self.image()
        self.record['images']['game-api']['buildArgs']['IMAGE_TAG'] = 'other'
        with self.assertRaises(h.Refused):
            h.check_image(self.record, 'game-api', image)

    def test_build_args_registry_and_aliases_share_nonce_origin(self):
        sid = self.record['serverId']
        self.assertEqual(h.ORIGIN + '/game/' + sid, h.build_args(self.record, 'web-gateway')['NEXT_PUBLIC_GAME_URL'])
        registry = h.registry(self.record)[0]
        self.assertEqual('opensamguk-s'+sid, registry['deployProject'])
        self.assertNotEqual(self.record['project'], registry['deployProject'])
        self.assertEqual('http://s'+sid+'-game-engine:8082', registry['gameEngineUrl'])
        self.assertEqual(0, registry['generation'])
        self.assertEqual('scenario_3190', registry['scenarioCode'])
        self.assertEqual('http://s'+sid+'-game-api:8081', registry['gameApiUrl'])
        for svc in ('game-api', 'game-engine', 'web-game'):
            self.assertEqual(['s'+sid+'-'+svc], self.model['services'][svc]['networks']['local']['aliases'])
        self.assertNotIn('qa160', json.dumps(self.model))

    def test_registry_repair_accepts_only_exact_legacy_deployment_coordinate(self):
        legacy=copy.deepcopy(self.model)
        for service in legacy['services'].values():
            env=service.get('environment',{})
            if 'SERVER_REGISTRY_JSON' in env:
                rows=json.loads(env['SERVER_REGISTRY_JSON']);rows[0]['deployProject']=self.record['project']
                env['SERVER_REGISTRY_JSON']=json.dumps(rows,separators=(',',':'))
        self.assertEqual(self.model,h.registry_repair_model(self.record,self.fixture,legacy))
        for change in [lambda m:m['services']['gateway-api']['environment'].update(ADMIN_PASSWORD='changed'),
                       lambda m:m['services']['game-engine'].update(image='foreign'),
                       lambda m:m['services']['gateway-api']['environment'].update(SERVER_REGISTRY_JSON='[]')]:
            bad=copy.deepcopy(legacy);change(bad)
            with self.assertRaises(h.Refused):h.registry_repair_model(self.record,self.fixture,bad)
        with self.assertRaises(h.Refused):h.registry_repair_model(self.record,self.fixture,self.model)

    def test_registry_repair_recreates_only_gateway_and_preserves_other_resources(self):
        resources=self.running_resources()
        resources['network'][0]['Id']='owned-network'
        self.record['status']='RUNNING'
        legacy=copy.deepcopy(self.model)
        for service in legacy['services'].values():
            env=service.get('environment',{})
            if 'SERVER_REGISTRY_JSON' in env:
                rows=json.loads(env['SERVER_REGISTRY_JSON']);rows[0]['deployProject']=self.record['project']
                env['SERVER_REGISTRY_JSON']=json.dumps(rows,separators=(',',':'))
        h.write_json(self.directory/'compose.json',legacy)
        self.record['configSha256']=h.sha((self.directory/'compose.json').read_bytes())
        h.write_json(self.directory/'contract.json',self.record)
        h.write_json(self.directory/'runtime.json',self.fixture)
        h.write_json(self.directory/'fixture.json',{'private':'unchanged'})
        h.write_json(self.directory/'pre-repair-c56171e-verification.json',{
            'verifierHead':'c56171ee5d583672235fea8fece5b3ab2b38b217',
            'oldPublicContract':copy.deepcopy(self.record),'gatewaySeed':{'count':0,'initialized':False}})
        after=copy.deepcopy(resources)
        for row in after['container']:
            if row['Config']['Labels']['com.docker.compose.service']=='gateway-api':row['Id']='new-gateway'
        args=type('Args',(),{'custody':self.directory,'meta':self.directory})()
        with patch.object(h,'load',return_value=(self.directory,self.record)), \
             patch.object(h,'verify_custody_files',return_value=(self.fixture,legacy)), \
             patch.object(h,'verify_files',return_value=self.model),patch.object(h,'verify_images'), \
             patch.object(h,'verify_running'),patch.object(h,'runtime_caps',return_value=6016*1024**2), \
             patch.object(h,'heavy',return_value=__import__('contextlib').nullcontext()) as heavy, \
             patch.object(h,'inventory',side_effect=[resources,after]), \
             patch.object(h,'sql',return_value='{"count":0,"initialized":false}'), \
             patch.object(h,'compose',return_value=b'') as compose,patch.object(h,'smoke') as smoke:
            h.repair_registry(args)
            heavy.assert_called_once_with(self.directory,self.record,'gateway-repair')
            self.assertEqual(('up','-d','--no-build','--pull','never','--no-deps','--wait','--wait-timeout','180','gateway-api'),compose.call_args.args[2:])
            smoke.assert_called_once_with(args)
        self.assertEqual(self.model,json.loads((self.directory/'compose.json').read_text()))
        self.assertEqual(legacy,json.loads((self.directory/'registry-repair-original-compose.json').read_text()))
        self.assertEqual({'private':'unchanged'},json.loads((self.directory/'fixture.json').read_text()))
        self.assertEqual('SMOKE_PASSED',json.loads((self.directory/'registry-repair.json').read_text())['status'])

    def test_remote_docker_host_and_context_refused_before_daemon_access(self):
        with patch.dict(os.environ,DOCKER_HOST='tcp://remote.example:2375',clear=True), \
             patch.object(h.subprocess,'run') as run:
            with self.assertRaises(h.Refused):h.run(['docker','ps'])
            run.assert_not_called()
        with patch.dict(os.environ,DOCKER_HOST='unix:///tmp/local.sock',DOCKER_CONTEXT='remote',clear=True), \
             patch.object(h.subprocess,'run',return_value=type('P',(),{'returncode':0,'stdout':b'ssh://remote.example\n'})()) as run:
            with self.assertRaises(h.Refused):h.run(['docker','ps'])
            self.assertEqual(1,run.call_count)
            self.assertEqual(['docker','context','inspect'],run.call_args.args[0][:3])

    def test_run_suppresses_arbitrary_child_output_and_drops_inherited_secrets(self):
        canary = 'NEVER_PRINT_NEW_FIXTURE_123'
        with patch.dict(os.environ, LHA_TEST_SECRET=canary, COMPOSE_FILE='/tmp/foreign.yml'):
            output = h.run([sys.executable, '-c', 'import os;print(os.getenv("LHA_TEST_SECRET"));print(os.getenv("COMPOSE_FILE"))'])
            self.assertEqual(b'None\nNone\n', output)
            with self.assertRaises(h.Refused) as caught:
                h.run([sys.executable, '-c', 'import sys;print(sys.argv[1]);sys.exit(1)', canary])
            self.assertNotIn(canary, str(caught.exception))
        logfile = self.directory / 'private.log'
        with self.assertRaises(h.Refused):
            h.run([sys.executable, '-c', 'import sys;print(sys.argv[1]);sys.exit(1)', canary], log_path=logfile)
        self.assertIn(canary, logfile.read_text())
        self.assertEqual(0o600, logfile.stat().st_mode & 0o777)

    def test_resource_gate_matches_managed_load_bound_and_independent_vm_capacity(self):
        info=json.dumps({'NCPU':8,'MemTotal':8*h.GIB}).encode()
        free=type('Disk',(),{'free':20*h.GIB})()
        with patch.object(h.shutil,'disk_usage',return_value=free), patch.object(h.os,'getloadavg',return_value=(10,400,10)), \
             patch.object(h,'run',side_effect=[info,b'']):
            h.resource_gate(self.directory, 'build')
        with patch.object(h.shutil,'disk_usage',return_value=free), patch.object(h.os,'getloadavg',return_value=(10,401,10)), \
             patch.object(h,'run',side_effect=[info,b'']):
            with self.assertRaises(h.Refused):h.resource_gate(self.directory, 'build')
        with patch.object(h.shutil,'disk_usage',return_value=free), patch.object(h,'run',return_value=json.dumps({'NCPU':1,'MemTotal':8*h.GIB}).encode()):
            with self.assertRaises(h.Refused):h.resource_gate(self.directory, 'build')
        with patch.object(h.shutil,'disk_usage',return_value=free), \
             patch.object(h,'run',side_effect=[info,json.dumps({'MemUsage':'3GiB / 8GiB'}).encode()]):
            with self.assertRaises(h.Refused):h.resource_gate(self.directory, 'build')

    def test_build_and_startup_disk_admission_are_explicit_and_keep_memory_gate(self):
        info=json.dumps({'NCPU':8,'MemTotal':8*h.GIB}).encode()
        for phase, gib, accepted, stats in [('build',11.9,False,b''), ('build',12,True,b''),
                ('startup',7.9,False,b''), ('startup',8,True,b''),
                ('gateway-repair',8,True,json.dumps({'MemUsage':'5GiB / 8GiB'}).encode()),
                ('gateway-repair',8,False,json.dumps({'MemUsage':'7.5GiB / 8GiB'}).encode()),
                ('startup',8,False,json.dumps({'MemUsage':'3GiB / 8GiB'}).encode())]:
            with self.subTest(phase=phase, gib=gib, stats=stats), \
                 patch.object(h.shutil,'disk_usage',return_value=type('Disk',(),{'free':gib*h.GIB})()), \
                 patch.object(h.os,'getloadavg',return_value=(10,10,10)), patch.object(h,'run',side_effect=[info,stats]):
                if accepted:h.resource_gate(self.directory,phase)
                else:
                    with self.assertRaises(h.Refused):h.resource_gate(self.directory,phase)
        with patch.object(h,'run') as run:
            with self.assertRaises(h.Refused):h.resource_gate(self.directory,'unknown')
            with self.assertRaises(h.Refused):
                with h.heavy(self.directory,self.record,'unknown'):self.fail('Unknown phase entered')
            run.assert_not_called()

    def test_up_keeps_verified_images_no_build_no_pull_and_explicit_startup_phase(self):
        self.record['status']='BUILT'
        args=type('Args',(),{'custody':self.directory,'meta':self.directory})()
        with patch.object(h,'load',return_value=(self.directory,self.record)), \
             patch.object(h,'verify_files',return_value=self.model), patch.object(h,'verify_images'), \
             patch.object(h,'heavy',return_value=__import__('contextlib').nullcontext()) as heavy, \
             patch.object(h,'inventory',return_value={'container':[],'network':[],'volume':[]}), \
             patch.object(h,'port_free'), patch.object(h,'verify_running'), patch.object(h,'smoke'), \
             patch.object(h,'startup_disk_check') as disk, \
             patch.object(h,'compose',side_effect=[json.dumps(self.model).encode(),b'']) as compose:
            h.up(args)
            heavy.assert_called_once_with(self.directory,self.record,'startup')
            self.assertEqual(('up','-d','--no-build','--pull','never','--wait','--wait-timeout','600'),compose.call_args.args[2:])
            self.assertEqual('afterStartupFreeBytes',disk.call_args.args[1])

    def test_startup_disk_observations_preserve_consumption_and_refuse_low_reserve(self):
        with patch.object(h.shutil,'disk_usage',return_value=type('Disk',(),{'free':8*h.GIB})()):
            h.startup_disk_check(self.directory,'afterStartupFreeBytes',10*h.GIB)
        with patch.object(h.shutil,'disk_usage',return_value=type('Disk',(),{'free':2.9*h.GIB})()):
            with self.assertRaises(h.Refused):h.startup_disk_check(self.directory,'beforeSmokePassedFreeBytes')
        report=json.loads((self.directory/'startup-disk.json').read_text())
        self.assertEqual(10*h.GIB,report['startupFreeBytes'])
        self.assertEqual(8*h.GIB,report['afterStartupFreeBytes'])
        self.assertEqual(2.9*h.GIB,report['beforeSmokePassedFreeBytes'])
        self.assertAlmostEqual(7.1*h.GIB,report['consumedBytes'])

    def test_foreign_heavy_lock_is_never_deleted(self):
        meta = self.directory / 'meta'
        (meta / 'bin').mkdir(parents=True)
        (meta / 'bin/start-task').touch()
        (meta / '.locks/heavy-run').mkdir(parents=True)
        owner = meta / '.locks/heavy-run/owner'
        owner.write_text('FOREIGN')
        with patch.object(h.time, 'sleep', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                with h.heavy(meta, self.record, 'build'):
                    self.fail('Must not enter')
        self.assertEqual('FOREIGN', owner.read_text())

    def test_heavy_release_checks_own_nonce_and_cleanup_works_under_pressure(self):
        meta = self.directory / 'meta'
        (meta / 'bin').mkdir(parents=True)
        (meta / 'bin/start-task').touch()
        with patch.object(h, 'resource_gate', side_effect=h.Refused('low disk')):
            with self.assertRaises(h.Refused):
                with h.heavy(meta, self.record, 'build'):
                    self.fail('Gate must run')
            self.assertFalse((meta / '.locks/heavy-run').exists())
            with h.heavy(meta, self.record, 'cleanup'):
                self.assertTrue((meta / '.locks/heavy-run/owner').is_file())
            self.assertFalse((meta / '.locks/heavy-run').exists())

    def test_cleanup_foreign_volume_consumer_refuses_before_any_delete(self):
        self.record['images'] = {}
        rows = {'container': [], 'network': [], 'volume': [self.resource('volume', Name=self.record['project']+'_game-pgdata')]}
        with patch.object(h, 'load', return_value=(self.directory, self.record)), patch.object(h, 'verify_files'), \
             patch.object(h, 'heavy', return_value=__import__('contextlib').nullcontext()), \
             patch.object(h, 'inventory', return_value=rows), patch.object(h, 'run', return_value=b'foreign-container\n') as run:
            with self.assertRaises(h.Refused):
                h.down(type('Args', (), {'custody':self.directory, 'meta':self.directory})())
            self.assertEqual(1, run.call_count)
            self.assertNotIn('rm', run.call_args.args[0])

    def owned_files(self):
        h.private_write(self.directory/'nginx.conf',b'canonical nginx bytes')
        (self.directory/'certs').mkdir()
        h.private_write(self.directory/'certs/opensamguk.crt',b'new local cert')
        (self.directory/'battle-ws').mkdir()
        h.write_json(self.directory/'runtime.json',self.fixture)
        h.write_json(self.directory/'compose.json',self.model)
        self.record.update(nginxSha256=h.sha(b'canonical nginx bytes'),
            templateSha256=h.sha((h.ROOT/'docker-compose.localhost-acceptance.yml').read_bytes()),
            sourceTreeSha256=h.tree_hash(self.directory/'source'),certsSha256=h.tree_hash(self.directory/'certs'),
            configSha256=h.sha((self.directory/'compose.json').read_bytes()))

    def test_canonical_nginx_config_fixture_and_source_changes_refuse_before_up(self):
        self.owned_files()
        with patch.object(h,'git',return_value=b'canonical nginx bytes'):
            h.verify_files(self.directory,self.record)
            (self.directory/'nginx.conf').write_text('synthetic nginx')
            with self.assertRaises(h.Refused):
                h.verify_files(self.directory,self.record)
            (self.directory/'nginx.conf').write_bytes(b'canonical nginx bytes')
            (self.directory/'compose.json').write_text('{}')
            with self.assertRaises(h.Refused):
                h.verify_files(self.directory,self.record)
            h.write_json(self.directory/'compose.json',self.model,replace=True)
            h.private_write(self.directory/'runtime.json',b'{}',replace=True)
            with self.assertRaises((h.Refused,KeyError)):
                h.verify_files(self.directory,self.record)
        with patch.object(h,'git',return_value=b'other Docker nginx'):
            with self.assertRaises(h.Refused):
                h.verify_files(self.directory,self.record)

    def test_real_git_archive_removes_worktree_state_and_preserves_tracked_modes(self):
        repo=self.directory/'git-source'
        repo.mkdir()
        subprocess.run(['git','init','-q',str(repo)],check=True)
        for key,value in [('user.name','Local Fixture'),('user.email','fixture@localhost')]:
            subprocess.run(['git','-C',str(repo),'config',key,value],check=True)
        (repo/'tracked').write_text('source fixture')
        (repo/'tracked').chmod(0o755)
        subprocess.run(['git','-C',str(repo),'add','tracked'],check=True)
        subprocess.run(['git','-C',str(repo),'commit','-qm','fixture'],check=True)
        revision=h.git(repo,'rev-parse','HEAD').decode().strip()
        archive=h.source_archive(repo,revision)
        export=self.directory/'export'
        h.unpack_archive(archive,export)
        self.assertEqual(['tracked'],[p.name for p in export.iterdir()])
        self.assertEqual(h.archive_tree_hash(archive),h.tree_hash(export))
        self.assertEqual(0o755,(export/'tracked').stat().st_mode & 0o777)
        (repo/'untracked').write_text('ignored by archive but fail closed')
        with self.assertRaises(h.Refused):
            h.source_archive(repo,revision)

    def test_snapshot_rejects_sql_input_before_any_docker_command(self):
        for gid, request in [('0', None), ('1;DELETE',None), ('1', "x' OR true")]:
            args = type('Args', (), {'general_id':gid, 'request_id':request, 'custody':self.directory})()
            with patch.object(h, 'load') as load:
                with self.assertRaises(h.Refused):
                    h.snapshot(args)
                load.assert_not_called()

    def test_snapshot_is_fixed_read_only_projection_and_suppresses_log_body(self):
        h.write_json(self.directory / 'compose.json', self.model)
        self.record['configSha256'] = h.sha((self.directory / 'compose.json').read_bytes())
        result = {'generalId': 123, 'cityId': 1, 'userId': 2, 'nationId': 0, 'npcState': 0,
                  'experience': 5, 'dedication': 5, 'turnTime': '2026-10-17T01:00:00Z',
                  'world': {'tickSeconds': 120, 'worldVersion': 42, 'writerEpoch': 0},
                  'appliedCount': 2, 'personal': None}
        args = type('Args', (), {'general_id':'123', 'request_id':'12345678-1234-1234-1234-123456789abc',
                                'custody':self.directory})()
        with patch.object(h, 'load', return_value=(self.directory,self.record)), \
             patch.object(h, 'inventory', return_value={}), patch.object(h, 'verify_running'), \
             patch.object(h, 'sql', return_value=json.dumps(result)) as sql, patch('sys.stdout', new_callable=io.StringIO) as out:
            h.snapshot(args)
            self.assertEqual(result, json.loads(out.getvalue()))
            query = sql.call_args.args[-1]
            self.assertIn('BEGIN READ ONLY', query)
            self.assertIn("'worldVersion',world_version,'writerEpoch',writer_epoch", query)
            self.assertIn("'appliedCount', (SELECT count(*) FROM command_result WHERE world_id=160", query)
            self.assertIn("AND request_id='12345678-1234-1234-1234-123456789abc' AND terminal_status='APPLIED' AND ok=true", query)
            self.assertIn('g.id=123', query)
            self.assertIn('g.world_id=160', query)
            self.assertNotIn('log_entry.body', query)
            self.assertNotIn('password', query)
            self.assertNotIn('UPDATE', query)

    def test_snapshot_without_request_has_raw_world_counters_and_no_applied_count(self):
        h.write_json(self.directory / 'compose.json', self.model)
        self.record['configSha256'] = h.sha((self.directory / 'compose.json').read_bytes())
        result = {'generalId': 123, 'world': {'worldVersion': 0, 'writerEpoch': 0}}
        args = type('Args', (), {'general_id': '123', 'request_id': None,
                                'custody': self.directory})()
        with patch.object(h, 'load', return_value=(self.directory, self.record)), \
             patch.object(h, 'inventory', return_value={}), patch.object(h, 'verify_running'), \
             patch.object(h, 'sql', return_value=json.dumps(result)) as sql, patch('sys.stdout', new_callable=io.StringIO) as out:
            h.snapshot(args)
            self.assertEqual(result, json.loads(out.getvalue()))
            query = sql.call_args.args[-1]
            self.assertIn("'worldVersion',world_version,'writerEpoch',writer_epoch", query)
            self.assertNotIn('appliedCount', query)
            self.assertNotIn('command_result', query)
            self.assertIn('BEGIN READ ONLY', query)

    def running_resources(self):
        for svc in h.SERVICES: self.image(svc)
        self.record['supportImages']={ref:'sha256:'+str(i)*64 for i,ref in enumerate(h.SUPPORT_IMAGES)}
        rows=[]
        for index,(svc,model) in enumerate(self.model['services'].items()):
            own={**h.labels(self.record),h.PROJECT_LABEL:self.record['project'],'com.docker.compose.service':svc}
            image=(self.record['images'][svc]['imageId'] if svc in h.SERVICES else self.record['supportImages'][model['image']])
            row={'Id':'container-'+str(index),'Name':self.record['project']+'-'+svc+'-1',
                 'Config':{'Labels':own},'State':{'Running':True,'Health':{'Status':'healthy'}},'Image':image,
                 'NetworkSettings':{'Networks':{self.record['project']+'_local':{}}},
                 'HostConfig':{'PortBindings':({'443/tcp':[{'HostIp':'127.0.0.1','HostPort':'443'}]} if svc=='nginx' else {})},
                 'Mounts':[]}
            for mount in model.get('volumes',[]):
                if mount['type']=='bind': row['Mounts'].append({'Type':'bind','Source':mount['source'],'RW':False})
                else: row['Mounts'].append({'Type':'volume','Name':self.model['volumes'][mount['source']]['name']})
            rows.append(row)
        network=self.resource('network',Driver='bridge',Containers={r['Id']:{} for r in rows})
        return {'container':rows,'network':[network],'volume':[]}

    def test_actual_runtime_ports_images_mounts_health_and_network_members_are_checked(self):
        resources=self.running_resources()
        h.verify_running(self.record,resources,self.model)
        for mutate in [lambda r:r['container'][0]['NetworkSettings']['Networks'].update(foreign={}),
                       lambda r:r['container'][0]['HostConfig'].update(PortBindings={'5432/tcp':[{'HostIp':'0.0.0.0','HostPort':'5432'}]}),
                       lambda r:r['container'][0].update(Image='different'),
                       lambda r:r['container'][0]['State']['Health'].update(Status='unhealthy'),
                       lambda r:r['container'][0]['Mounts'].append({'Type':'volume','Name':'qa160'}),
                       lambda r:r['network'][0]['Containers'].update(foreign={})]:
            bad=copy.deepcopy(resources)
            mutate(bad)
            with self.assertRaises(h.Refused):h.verify_running(self.record,bad,self.model)

    def test_source_requires_clean_head_and_rejects_ignored_data_without_reading_it(self):
        with patch.object(h, 'git', side_effect=[('a'*40+'\n').encode(),b'',b'.env\n']) as git:
            with self.assertRaises(h.Refused):
                h.source_archive(self.directory, 'a'*40)
            self.assertEqual('ls-files', git.call_args.args[1])
        with patch.object(h, 'git', return_value=('b'*40+'\n').encode()) as git:
            with self.assertRaises(h.Refused):
                h.source_archive(self.directory, 'a'*40)
            self.assertEqual(1,git.call_count)

    def test_cleanup_removes_only_preinspected_owned_ids_and_preserves_custody(self):
        rows = {'container':[self.resource('container', Id='own-id')],
                'network':[self.resource('network',Id='own-net',Containers={'own-id':{}})],
                'volume':[self.resource('volume',Name=self.record['project']+'_game-pgdata')]}
        with patch.object(h,'load',return_value=(self.directory,self.record)), patch.object(h,'verify_files'), \
             patch.object(h,'heavy',return_value=__import__('contextlib').nullcontext()), \
             patch.object(h,'inventory',return_value=rows), patch.object(h,'run',return_value=b'own-id\n') as run:
            h.down(type('Args',(),{'custody':self.directory,'meta':self.directory})())
            commands = [call.args[0] for call in run.call_args_list]
            self.assertEqual(['docker','container','rm','-f','own-id'],commands[1])
            self.assertEqual(['docker','network','rm','own-net'],commands[2])
            self.assertEqual(['docker','volume','rm',self.record['project']+'_game-pgdata'],commands[3])
            self.assertEqual('REMOVED',json.loads((self.directory/'contract.json').read_text())['status'])
            self.assertTrue((self.directory/'source').exists())

    def test_compose_round_trip_with_real_cli_does_not_read_dotenv(self):
        if not __import__('shutil').which('docker'):
            self.skipTest('docker compose CLI absent')
        (self.directory / '.env').write_text('COMPOSE_PROJECT_NAME=FOREIGN\n')
        h.write_json(self.directory / 'compose.json', self.model)
        normalized = json.loads(h.compose(self.directory, self.record, 'config', '--format', 'json'))
        self.assertEqual(self.record['project'], normalized['name'])
        self.assertEqual({'127.0.0.1'}, {p['host_ip'] for s in normalized['services'].values() for p in s.get('ports',[])})
        self.assertEqual(set(self.model['services']), set(normalized['services']))
        self.assertEqual(self.fixture['ADMIN_PASSWORD'], normalized['services']['gateway-api']['environment']['ADMIN_PASSWORD'])


if __name__ == '__main__':
    unittest.main()
