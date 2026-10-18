import copy
import importlib.util
import json
import os
import re
import subprocess
from pathlib import Path
import tempfile
import unittest
from contextlib import ExitStack, nullcontext
from unittest.mock import MagicMock, patch

spec = importlib.util.spec_from_file_location('route_harness', Path(__file__).with_name('harness.py'))
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)


class TacticalRouteTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.directory = Path(temp.name).resolve()
        self.directory.chmod(0o700)
        (self.directory / 'battle-ws').mkdir(mode=0o700)
        self.record = {'schema': 1, 'nonce': '0123456789abcdef',
            'session': '01a14994-f8a1-7282-9f45-f9d3c5390cee',
            'project': 'osglha0123456789abcdef', 'serverId': 'lha0123456789abcdef',
            'origin': h.ORIGIN, 'worldId': 160, 'generation': 0,
            'custody': str(self.directory), 'appSha': 'a' * 40,
            'dockerSha': h.LEGACY_TACTICAL_DOCKER, 'profile': 'tactical', 'status': 'RUNNING',
            'images': {service: {'imageId': service} for service in h.SERVICES}}
        self.verifier = {'runtimeVerifierHead': 'd' * 40, 'runtimeVerifierPath': str(h.ROOT),
                        'runtimeVerifierHarnessSha256': 'e' * 64}
        self.args = type('Args', (), {'custody': self.directory, 'meta': self.directory,
            'verifier_sha': 'd' * 40, 'authorize_project': self.record['project']})()
        self.resources = {'container': [{'Id': 'nginx-id', 'Image': 'nginx-image'},
            {'Id': 'api-id', 'Image': 'api-image'}],
            'network': [{'Id': 'network-id'}], 'volume': [{'Name': 'game-volume'}]}

    def install_route(self):
        self.record['battleRouting'] = h.battle_route_binding(self.record)
        h.private_write(self.directory / 'battle-ws' / h.ROUTE_FILE, h.battle_route_bytes(self.record))

    def test_standard_stays_empty_and_tactical_requires_exact_map(self):
        standard = {**self.record, 'profile': 'standard'}
        h.verify_battle_route(self.directory, standard)
        with self.assertRaises(h.Refused):
            h.verify_battle_route(self.directory, self.record)
        self.install_route()
        h.verify_battle_route(self.directory, self.record)
        self.assertEqual(b'"lha0123456789abcdef" "http://slha0123456789abcdef-game-api:8081";\n',
                         (self.directory / 'battle-ws' / h.ROUTE_FILE).read_bytes())
        with self.assertRaises(h.Refused):
            h.verify_battle_route(self.directory, standard)

    def test_map_content_hash_inventory_owner_mode_and_links_are_bound(self):
        self.install_route()
        path = self.directory / 'battle-ws' / h.ROUTE_FILE
        original = path.read_bytes()
        for value in [b'"foreign" "http://slha0123456789abcdef-game-api:8081";\n',
                      original.replace(b':8081', b':8082'), original + b'default http://foreign;\n']:
            path.write_bytes(value)
            # Even a rewritten receipt cannot authorize arbitrary bytes or upstream.
            self.record['battleRouting']['sha256'] = h.sha(value)
            with self.assertRaises(h.Refused):
                h.verify_battle_route(self.directory, self.record)
        path.write_bytes(original)
        self.record['battleRouting'] = h.battle_route_binding(self.record)
        extra = path.with_name('extra.map')
        extra.write_bytes(b'')
        with self.assertRaises(h.Refused):
            h.verify_battle_route(self.directory, self.record)
        extra.unlink()
        path.chmod(0o644)
        with self.assertRaises(h.Refused):
            h.verify_battle_route(self.directory, self.record)
        path.chmod(0o600)
        outside = self.directory / 'outside-map'
        os.link(path, outside)
        with self.assertRaises(h.Refused):
            h.verify_battle_route(self.directory, self.record)
        outside.unlink()
        path.unlink()
        outside.write_bytes(original)
        path.symlink_to(outside)
        with self.assertRaises(h.Refused):
            h.verify_battle_route(self.directory, self.record)

    def test_directory_symlink_and_contract_alias_are_refused(self):
        route = self.directory / 'battle-ws'
        route.rmdir()
        other = self.directory / 'other'
        other.mkdir(mode=0o700)
        route.symlink_to(other, target_is_directory=True)
        with self.assertRaises(h.Refused):
            h.verify_battle_route(self.directory, self.record)
        route.unlink()
        route.mkdir(mode=0o700)
        self.install_route()
        self.record['battle_routing'] = self.record['battleRouting']
        with self.assertRaises(h.Refused):
            h.verify_battle_route(self.directory, self.record)

    def test_legacy_escape_is_only_unpassed_exact_d35_tactical(self):
        h.verify_battle_route(self.directory, self.record, legacy=True)
        for changes in [{'dockerSha': 'a' * 40}, {'status': 'SMOKE_PASSED'},
                        {'profile': 'standard'}, {'runtimeVerifierHead': 'd' * 40}]:
            with self.subTest(changes=changes), self.assertRaises(h.Refused):
                h.verify_battle_route(self.directory, {**self.record, **changes}, legacy=True)

    def test_runtime_alias_must_resolve_only_to_the_owned_game_api(self):
        alias = 's' + self.record['serverId'] + '-game-api'
        net = self.record['project'] + '_local'
        rows = {'container': [{'Name': '/api-container',
            'Config': {'Labels': {'com.docker.compose.service': 'game-api'}},
            'NetworkSettings': {'Networks': {net: {'Aliases': ['api-container', 'game-api', alias]}}}},
            {'Name': '/web-container', 'Config': {'Labels': {'com.docker.compose.service': 'web-game'}},
             'NetworkSettings': {'Networks': {net: {'Aliases': ['web-container', 'web-game']}}}}]}
        h.verify_battle_route_runtime(self.record, rows)
        for index, aliases in [(0, ['api-container', 'game-api']),
                               (0, ['api-container', 'game-api', alias, 'foreign']),
                               (1, ['web-container', 'web-game', alias])]:
            changed = copy.deepcopy(rows)
            changed['container'][index]['NetworkSettings']['Networks'][net]['Aliases'] = aliases
            with self.subTest(index=index, aliases=aliases), self.assertRaises(h.Refused):
                h.verify_battle_route_runtime(self.record, changed)

    def test_verifier_requires_exact_clean_head_and_tracked_harness_bytes(self):
        def git(*args):
            if args[1:3] == ('rev-parse', 'HEAD'):
                return ('d' * 40).encode()
            if args[1] in ('status', 'ls-files'):
                return b''
            return Path(h.__file__).read_bytes()
        with patch.object(h, 'git', side_effect=git):
            self.assertEqual('d' * 40, h.route_verifier_identity('d' * 40)['runtimeVerifierHead'])
            with self.assertRaises(h.Refused):
                h.route_verifier_identity('e' * 40)
        for output in [b'foreign source', b'M dirty', b'ignored-file']:
            with patch.object(h, 'git', return_value=output), self.assertRaises(h.Refused):
                h.route_verifier_identity('d' * 40)

    def setup_repair(self):
        self.old_nginx, self.new_nginx = b'original nginx config\n', b'reviewed new nginx config\n'
        self.record['nginxSha256'] = h.sha(self.old_nginx)
        h.private_write(self.directory / 'nginx.conf', self.old_nginx)
        h.write_json(self.directory / 'contract.json', self.record)
        h.write_json(self.directory / 'h-execution.json', {'status': 'FAILED_OR_REFUSED',
            'exceptionType': 'Refused', 'fixedFailureCode':
                'Boundary smoke failed at /api/battle-ws/' + self.record['serverId'] + '/160/probe'})
        self.original = (self.directory / 'contract.json').read_bytes()
        stack = ExitStack()
        self.addCleanup(stack.close)
        patches = {
            'load': lambda *a, **kw: (self.directory, self.record),
            'route_verifier_identity': lambda revision: self.verifier,
            'git': lambda *a: b'canonical source',
            'heavy': lambda *a: nullcontext(),
            'verify_images': lambda *a: None,
            'verify_running': lambda *a: None,
            'runtime_caps': lambda *a: None,
            'inventory': lambda *a: self.resources,
            'wait_tactical_route': lambda *a: None,
            'route_nginx_transition': lambda *a: (self.old_nginx, self.new_nginx),
        }
        for name, fn in patches.items():
            stack.enter_context(patch.object(h, name, side_effect=fn))
        def files(directory, record, *, legacy_route=False):
            h.verify_battle_route(directory, record, legacy=legacy_route)
            return {}
        stack.enter_context(patch.object(h, 'verify_files', side_effect=files))
        self.commands = []
        stack.enter_context(patch.object(h, 'compose', side_effect=lambda *a, **kw: self.commands.append(a[2:]) or b''))
        def smoke(args, *, finalize=True):
            current = json.loads((self.directory / 'contract.json').read_bytes())
            h.verify_battle_route(self.directory, current)
            self.assertFalse(finalize)
            self.assertEqual('RUNNING', current['status'])
        stack.enter_context(patch.object(h, 'smoke', side_effect=smoke))

    def test_repair_preserves_original_build_inputs_and_only_tests_then_reloads_nginx(self):
        self.setup_repair()
        h.repair_tactical_route(self.args)
        current = json.loads((self.directory / 'contract.json').read_bytes())
        self.assertEqual(self.original, (self.directory / h.ROUTE_ORIGINAL).read_bytes())
        self.assertEqual(h.LEGACY_TACTICAL_DOCKER, current['dockerSha'])
        self.assertEqual(self.record['images'], current['images'])
        self.assertEqual('SMOKE_PASSED', current['status'])
        self.assertEqual(self.verifier['runtimeVerifierHead'], current['runtimeVerifierHead'])
        self.assertEqual([('exec', '-T', 'nginx', 'nginx', '-t'),
                          ('exec', '-T', 'nginx', 'nginx', '-s', 'reload')], self.commands)
        h.verify_route_recovery_binding(self.directory, current)
        for field, value in [('appSha', 'f' * 40), ('configSha256', 'f' * 64),
                             ('runtimeVerifierPath', '/foreign'), ('dockerSha', 'f' * 40)]:
            with self.subTest(field=field), self.assertRaises(h.Refused):
                h.verify_route_recovery_binding(self.directory, {**current, field: value})

    def test_preflight_refusals_write_no_attempt_map_or_contract(self):
        for name in ['route_verifier_identity', 'verify_files', 'verify_images', 'inventory',
                     'verify_running', 'runtime_caps']:
            with self.subTest(gate=name):
                self.setup_repair()
                with patch.object(h, name, side_effect=h.Refused('fixed refusal')):
                    with self.assertRaises(h.Refused):
                        h.repair_tactical_route(self.args)
                self.assertEqual(self.original, (self.directory / 'contract.json').read_bytes())
                self.assertFalse((self.directory / 'tactical-route-execution.json').exists())
                self.assertFalse((self.directory / h.ROUTE_ORIGINAL).exists())
                self.assertEqual([], list((self.directory / 'battle-ws').iterdir()))
                # Each subcase has its own patched admission, but reuses only untouched private files.
                (self.directory / 'contract.json').unlink()
                (self.directory / 'h-execution.json').unlink()
                (self.directory / 'nginx.conf').unlink()

    def test_reload_failure_preserves_failure_original_and_refuses_retry(self):
        self.setup_repair()
        with patch.object(h, 'compose', side_effect=h.Refused('reload failure')):
            with self.assertRaises(h.Refused):
                h.repair_tactical_route(self.args)
        self.assertEqual(self.original, (self.directory / h.ROUTE_ORIGINAL).read_bytes())
        self.assertEqual('FAILED_OR_REFUSED',
            json.loads((self.directory / 'tactical-route-execution.json').read_bytes())['status'])
        with self.assertRaises(h.Refused):
            h.repair_tactical_route(self.args)

    def test_failed_reloaded_boundary_restores_original_inode_bytes_contract_and_empty_map(self):
        self.setup_repair()
        inode = h.nginx_file_identity(self.directory / 'nginx.conf')
        with patch.object(h, 'wait_tactical_route', side_effect=h.Refused('boundary failure')):
            with self.assertRaises(h.Refused):
                h.repair_tactical_route(self.args)
        self.assertEqual(self.old_nginx, (self.directory / 'nginx.conf').read_bytes())
        self.assertEqual(inode, h.nginx_file_identity(self.directory / 'nginx.conf'))
        self.assertEqual(self.original, (self.directory / 'contract.json').read_bytes())
        self.assertEqual([], list((self.directory / 'battle-ws').iterdir()))
        audit = json.loads((self.directory / 'tactical-route-execution.json').read_bytes())
        self.assertEqual('FAILED_OR_REFUSED', audit['status'])
        self.assertEqual('ORIGINAL_FAILURE_CONFIG_RESTORED', audit['restoration'])
        self.assertEqual(2, sum(command[-2:] == ('-s', 'reload') for command in self.commands))
        self.assertEqual('FAILED_OR_REFUSED', json.loads((self.directory / 'h-execution.json').read_bytes())['status'])

    def test_restoration_refuses_foreign_config_instead_of_overwriting_it(self):
        self.setup_repair()
        def changed(*args):
            (self.directory / 'nginx.conf').write_bytes(b'foreign configuration')
            raise h.Refused('foreign config')
        with patch.object(h, 'wait_tactical_route', side_effect=changed):
            with self.assertRaises(h.Refused):
                h.repair_tactical_route(self.args)
        self.assertEqual(b'foreign configuration', (self.directory / 'nginx.conf').read_bytes())
        audit = json.loads((self.directory / 'tactical-route-execution.json').read_bytes())
        self.assertEqual('REFUSED_OR_FAILED_REQUIRES_OPERATOR', audit['restoration'])
        self.assertEqual(1, sum(command[-2:] == ('-s', 'reload') for command in self.commands))

    def test_post_smoke_identity_failure_cannot_publish_pass(self):
        self.setup_repair()
        different = copy.deepcopy(self.resources)
        different['container'][0]['Id'] = 'replacement'
        with patch.object(h, 'inventory', side_effect=[self.resources, self.resources, different]):
            with self.assertRaises(h.Refused):
                h.repair_tactical_route(self.args)
        self.assertEqual('RUNNING', json.loads((self.directory / 'contract.json').read_bytes())['status'])
        self.assertEqual(self.original, (self.directory / h.ROUTE_ORIGINAL).read_bytes())

    def test_reload_wait_only_accepts_own_403_foreign_404(self):
        for statuses, accepted in [([404, 404, 404, 404, 403, 404, 403, 404], True),
                                   ([403, 403, 403, 404], False),
                                   ([200, 404, 403, 404], False), ([404, 404, 404, 404], False)]:
            opener = MagicMock()
            responses = [nullcontext(type('Response', (), {'status': value})()) for value in statuses]
            opener.open.side_effect = responses
            with self.subTest(statuses=statuses), patch.object(h.ssl, 'create_default_context'), \
                 patch.object(h.urllib.request, 'build_opener', return_value=opener), \
                 patch.object(h.time, 'sleep'), patch.object(h.time, 'monotonic', side_effect=[0, 31]):
                # A 404 from old workers can be observed before the one reload takes effect.
                if accepted:
                    with patch.object(h.time, 'monotonic', side_effect=[0, 1]):
                        h.wait_tactical_route(self.directory, self.record)
                else:
                    with self.assertRaises(h.Refused):
                        h.wait_tactical_route(self.directory, self.record)

    def test_file_bind_write_preserves_inode_and_rejects_changed_inode_or_bytes(self):
        path = self.directory / 'nginx.conf'
        h.private_write(path, b'original')
        inode = h.nginx_file_identity(path)
        h.write_bound_nginx(path, b'original', b'new reviewed bytes', inode)
        self.assertEqual(inode, h.nginx_file_identity(path))
        h.write_bound_nginx(path, b'new reviewed bytes', b'original', inode)
        self.assertEqual(b'original', path.read_bytes())
        with patch.object(h.os, 'getuid', return_value=os.getuid()+1), self.assertRaises(h.Refused):
            h.write_bound_nginx(path, b'original', b'other', inode)
        for current, identity in [(b'foreign', inode), (b'original', {**inode, 'inode': -1})]:
            with self.assertRaises(h.Refused):
                h.write_bound_nginx(path, current, b'other', identity)
        self.assertEqual(b'original', path.read_bytes())

    def test_canonical_http_and_https_aliases_share_strict_path_and_header_guards(self):
        source = (h.ROOT / 'infra/nginx/nginx.conf').read_text()
        blocks = re.findall(r'location ~ "(\^/\(\?:api/battle-ws\|ws/battles\)/[^"\n]+)" \{(.*?)\n        \}', source, re.S)
        self.assertEqual(2, len(blocks))
        self.assertEqual(blocks[0], blocks[1])
        for expression, body in blocks:
            matcher = re.compile(expression.replace('(?<', '(?P<'))
            for prefix in ('/api/battle-ws', '/ws/battles'):
                for tail in ('pep/1/battle-1', 'lha0123456789abcdef/160/probe'):
                    self.assertIsNotNone(matcher.fullmatch(prefix + '/' + tail))
                for tail in ('pep/0/battle', 'pep/01/battle', 'PEP/1/battle',
                             'pep/10000000000/battle', 'pep/1/bad.dot', 'pep/1/' + 'a'*129):
                    self.assertIsNone(matcher.fullmatch(prefix + '/' + tail))
                self.assertIn('location = ' + prefix + ' {', source)
                self.assertIn('location ' + prefix + '/ {', source)
            for header in ('Authorization', 'Proxy-Authorization', 'Cookie'):
                self.assertIn('proxy_set_header ' + header + ' "";', body)
            self.assertIn('if ($battle_ws_upstream = "") {\n                return 404;', body)
            self.assertIn('$is_args$args;', body)
            self.assertNotIn('location /ws/ {', source)

    def test_only_the_exact_two_alias_source_transition_is_allowed(self):
        old = subprocess.run(['git', '-C', str(h.ROOT), 'show',
            h.LEGACY_TACTICAL_DOCKER + ':infra/nginx/nginx.conf'], check=True, capture_output=True).stdout
        new = (h.ROOT / 'infra/nginx/nginx.conf').read_bytes()
        record = {**self.record, 'nginxSha256': h.sha(old)}
        for candidate, accepted in [(new, True), (old, False),
                                    (new.replace(b'proxy_set_header Cookie "";', b''), False),
                                    (new + b'\n# unreviewed config\n', False)]:
            def git(repo, operation, target):
                return old if target.startswith(h.LEGACY_TACTICAL_DOCKER + ':') else candidate
            with self.subTest(accepted=accepted), patch.object(h, 'git', side_effect=git):
                if accepted:
                    self.assertEqual((old, new), h.route_nginx_transition(record, 'd'*40))
                else:
                    with self.assertRaises(h.Refused):
                        h.route_nginx_transition(record, 'd'*40)

    def test_wrong_owner_or_project_never_opens_legacy_admission(self):
        with patch.dict(os.environ, {'OPENSAMGUK_TASK_OWNER_SESSION': 'other'}):
            with self.assertRaises(h.Refused):
                h.identity(self.record)
        self.setup_repair()
        self.args.authorize_project = 'foreign'
        with self.assertRaises(h.Refused):
            h.repair_tactical_route(self.args)
        self.assertFalse((self.directory / h.ROUTE_ORIGINAL).exists())


if __name__ == '__main__':
    unittest.main()

