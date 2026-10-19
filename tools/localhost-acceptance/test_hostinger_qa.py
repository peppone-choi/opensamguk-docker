"""Policy tests are synthetic; the explicitly selected Compose test is read-only CLI only."""
import contextlib
import copy
import importlib.util
import json
import os
from pathlib import Path
import socket
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from test_qa_builder import BuilderCLI

spec = importlib.util.spec_from_file_location('hostinger_test_harness', Path(__file__).with_name('harness.py'))
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)
q = h.qa


class HostingerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name).resolve()
        self.directory.chmod(0o700)
        self.record = {'nonce': '0123456789abcdef', 'session': '01a14994-f8a1-7282-9f45-f9d3c5390cee',
                       'project': 'osglha0123456789abcdef', 'serverId': 'lha0123456789abcdef',
                       'origin': h.ORIGIN, 'worldId': 160, 'generation': 0, 'custody': str(self.directory),
                       'appSha': 'a'*40, 'dockerSha': 'b'*40, 'sourceTreeSha256': 'c'*64, 'images': {}}
        self.fixtures = {k: 'synthetic-only' for k in ('DB_PASSWORD', 'JWT_PRIVATE_KEY', 'JWT_PUBLIC_KEY',
                         'INTERNAL_TOKEN', 'DEPLOYER_TOKEN', 'ADMIN_USERNAME', 'ADMIN_PASSWORD')}

    def qa_record(self):
        record = dict(self.record, origin=q.ORIGIN, hostingerQA=q.selection('t_9906f2dd'))
        record['project'] = q.project(record)
        return record

    def test_default_model_is_exact_template_substitution(self):
        record = self.record
        values = dict(self.fixtures, CUSTODY=record['custody'], PROJECT=record['project'], NONCE=record['nonce'],
                      SESSION=record['session'], SERVER_ID=record['serverId'],
                      REGISTRY=json.dumps(h.registry(record), separators=(',', ':')))
        values.update({'IMAGE_' + s: h.image_ref(record, s) for s in h.SERVICES})
        canonical = h.substitute(json.loads((h.ROOT / 'docker-compose.localhost-acceptance.yml').read_bytes()), values)
        self.assertEqual(canonical, h.model_for(record, self.fixtures))
        self.assertEqual(443, q.port(record))
        self.assertEqual(h.ORIGIN, q.origin(record))

    def test_qa_origin_project_buildargs_registry_and_cors_are_bound(self):
        record = dict(self.qa_record(), profile='tactical')
        fixtures = h.profile_fixtures(record, self.fixtures)
        model = h.model_for(record, fixtures)
        h.identity(record, read_only=True)
        self.assertEqual('opensamguk-qa-t_9906f2dd-0123456789abcdef', record['project'])
        self.assertEqual(q.ORIGIN, h.build_args(record, 'web-game')['NEXT_PUBLIC_GATEWAY_URL'])
        self.assertEqual(q.ORIGIN + '/game/' + record['serverId'], h.build_args(record, 'web-gateway')['NEXT_PUBLIC_GAME_URL'])
        self.assertEqual(record['appSha'], h.build_args(record, 'game-engine')['IMAGE_TAG'])
        self.assertEqual(q.ORIGIN, model['services']['game-api']['environment']['BATTLE_WS_ALLOWED_ORIGINS'])
        for service in ('gateway-api', 'web-gateway', 'web-game'):
            self.assertEqual(q.ORIGIN + '/game/' + record['serverId'], json.loads(model['services'][service]['environment']['SERVER_REGISTRY_JSON'])[0]['gameUrl'])

    def test_other_origins_and_policy_aliases_are_refused(self):
        for origin in ('https://localhost', 'https://localhost:19443', 'http://localhost:18443',
                       'https://127.0.0.1:18443', 'https://example.invalid:18443'):
            with self.subTest(origin=origin), self.assertRaises(h.Refused):
                h.identity(dict(self.qa_record(), origin=origin), read_only=True)
        for key, value in [('port', 443), ('cgroupParent', 'system.slice'), ('schema', 2), ('policySha256', 'f'*64)]:
            record = copy.deepcopy(self.qa_record())
            record['hostingerQA'][key] = value
            with self.subTest(key=key), self.assertRaises(h.Refused):
                q.selected(record)
        with self.assertRaises(h.Refused):
            q.selected(dict(self.record, hostingerQAAlias=True))

    def test_no_existing_custody_or_default_project_conversion(self):
        with self.assertRaises(h.Refused):
            h.identity(dict(self.qa_record(), project=self.record['project']), read_only=True)
        with self.assertRaises(h.Refused):
            h.identity(dict(self.record, origin=q.ORIGIN), read_only=True)
        # Existing path is refused before any fixtures/port/resources are generated.
        args = SimpleNamespace(hostinger_qa_task='t_9906f2dd', source=self.directory, custody=self.directory,
                               app_sha='a'*40, docker_sha='b'*40)
        def git(repo, *args):
            return Path(q.__file__).read_bytes() if args[-1].endswith('hostinger_qa.py') else b'b'*40 if repo == h.ROOT else b'a'*40
        with patch.dict(os.environ, OPENSAMGUK_TASK_OWNER_SESSION=self.record['session']), patch.object(h, 'git', side_effect=git), patch.object(h, 'source_archive', return_value=b'archive'), patch.object(h, 'inventory', side_effect=AssertionError('resource access')):
            with self.assertRaisesRegex(h.Refused, 'Custody already exists'):
                h.prepare(args)

    def test_invalid_task_rejected_before_dependencies(self):
        for value in ('t_123', 'other', 't_ABCDEF12', '', False):
            with self.subTest(value=value), patch.object(h, 'git', side_effect=AssertionError('dependency')):
                with self.assertRaises(h.Refused):
                    h.prepare(SimpleNamespace(hostinger_qa_task=value))

    def test_all_eleven_caps_and_total_preserve_canonical_memory_and_jvm(self):
        baseline = h.model_for(self.record, self.fixtures)
        model = h.model_for(self.qa_record(), self.fixtures)
        self.assertEqual(6016 * q.MIB, sum(q.memory_bytes(s['mem_limit']) for s in model['services'].values()))
        self.assertEqual(1400000, sum(int(float(s['cpus'])*1000000) for s in model['services'].values()))
        for name, service in model['services'].items():
            self.assertEqual(q.CGROUP, service['cgroup_parent'])
            self.assertEqual(baseline['services'][name]['mem_limit'], service['mem_limit'])
            self.assertEqual(service['mem_limit'], service['memswap_limit'])
            if 'JAVA_OPTS' in service.get('environment', {}):
                self.assertEqual(baseline['services'][name]['environment']['JAVA_OPTS'], service['environment']['JAVA_OPTS'])

    def test_public_bind_other_port_foreign_parent_and_budget_override_refused(self):
        record = self.qa_record()
        original = h.model_for(record, self.fixtures)
        changes = [('nginx', 'ports', [{'target':443,'published':'18443','host_ip':'0.0.0.0','protocol':'tcp'}]),
                   ('nginx', 'ports', [{'target':443,'published':'19443','host_ip':'127.0.0.1','protocol':'tcp'}]),
                   ('game-engine', 'cgroup_parent', 'system.slice'), ('game-engine', 'mem_limit', '128m'),
                   ('game-api', 'memswap_limit', '2g'), ('nginx', 'cpus', '1.6'), ('nginx', 'deploy', {})]
        for service, key, value in changes:
            model = copy.deepcopy(original)
            model['services'][service][key] = value
            with self.subTest(key=key), self.assertRaises(h.Refused):
                h.validate_model(model, record)

    def test_nginx_preserves_tls_and_internal_routes_but_keeps_external_port(self):
        canonical = (h.ROOT / 'infra/nginx/nginx.conf').read_bytes()
        self.assertEqual(canonical, q.nginx(self.record, canonical))
        changed = q.nginx(self.qa_record(), canonical)
        self.assertIn(b'proxy_set_header Host localhost:18443;', changed)
        self.assertIn(b'X-Forwarded-Port 18443;', changed)
        self.assertIn(b'https://localhost:18443$request_uri', changed)
        self.assertIn(b'listen 443 ssl;', changed)
        self.assertEqual(canonical, changed.replace(b'    proxy_set_header Host localhost:18443;\n    proxy_set_header X-Forwarded-Port 18443;', b'    proxy_set_header Host $host;').replace(b'https://localhost:18443$request_uri', b'https://$host$request_uri'))

    def test_port_busy_or_denied_fails_without_fallback(self):
        with patch.object(socket, 'socket') as sock:
            sock.return_value.__enter__.return_value.bind.side_effect = OSError('occupied')
            with self.assertRaisesRegex(h.Refused, '18443 unavailable'):
                h.port_free(self.qa_record())
            sock.return_value.__enter__.return_value.bind.assert_called_once_with(('127.0.0.1', 18443))
            sock.return_value.__enter__.return_value.connect_ex.assert_not_called()

    def sample(self, ceiling=10*1024**3, current=1024**3, inactive=0, cpu=1600000):
        return {'current': current, 'inactiveFile': inactive, 'ceiling': ceiling, 'cpuMicros': cpu}

    def test_runtime_never_fits_current_slice_even_when_idle(self):
        with self.assertRaisesRegex(h.Refused, 'minimumCeilingBytes=6576668672'):
            q.evaluate(6016*q.MIB, 1400000, [self.sample(4539912192, 0)], 20*1024**3)

    def test_nonreclaimable_plus_reserve_and_host_actual_availability(self):
        report = q.evaluate(2*1024**3, 1000000, [self.sample(current=3*1024**3, inactive=1024**3)], 5*1024**3)
        self.assertEqual(2*1024**3, report['cgroups'][0]['nonreclaimableBytes'])
        for samples, host in [([self.sample(3*1024**3, current=1024**3)], 20*1024**3),
                              ([self.sample(), self.sample(2*1024**3, current=0)], 20*1024**3),
                              ([self.sample()], 2*1024**3), ([self.sample(cpu=1000000)], 20*1024**3)]:
            with self.subTest(samples=samples, host=host), self.assertRaises(h.Refused):
                q.evaluate(2*1024**3, 1000000, samples, host)

    def test_invalid_capacity_evidence_fails_closed(self):
        for sample in (self.sample(current=-1), self.sample(inactive=2*1024**3), self.sample(cpu=True)):
            with self.assertRaises(h.Refused):
                q.evaluate(1, 1, [sample], 1000000)
        with self.assertRaises(h.Refused):
            q.evaluate(1, 1, [], 1000000)

    def test_resource_gate_uses_cgroup_not_host_docker_stats(self):
        record = self.qa_record()
        with patch.object(h.shutil, 'disk_usage', return_value=SimpleNamespace(free=20*1024**3)), patch.object(q, 'admission', return_value={'synthetic':True}) as admission, patch.object(h, 'run', side_effect=AssertionError('host stats are not admission')):
            self.assertEqual({'synthetic':True}, h.resource_gate(self.directory, 'startup', record))
            admission.assert_called_once_with(record, 'startup')

    def test_runtime_inspection_checks_cgroup_cpu_memory_and_swap(self):
        cap = {'CgroupParent':q.CGROUP,'Memory':2048*q.MIB,'MemorySwap':2048*q.MIB,'NanoCpus':300000000}
        q.runtime_cap({'HostConfig':cap}, 'game-engine')
        for key, value in [('CgroupParent','system.slice'), ('Memory', 0), ('NanoCpus', 0), ('MemorySwap', -1)]:
            with self.subTest(key=key), self.assertRaises(h.Refused):
                q.runtime_cap({'HostConfig':dict(cap, **{key:value})}, 'game-engine')

    def test_shared_heavy_and_browser_locks_are_nonblocking_and_released_on_exception(self):
        for name in ('host-heavy.lock', 'browser.lock'):
            (self.directory / name).touch()
            with patch.object(q, 'LOCKROOT', self.directory):
                with self.assertRaisesRegex(RuntimeError, 'synthetic'), q.lock(name):
                    with self.assertRaisesRegex(h.Refused, 'busy'), q.lock(name):
                        self.fail('second owner entered')
                    raise RuntimeError('synthetic')
                with q.lock(name):
                    pass

    def test_heavy_refuses_before_work_and_cleanup_does_not_require_capacity(self):
        with patch.object(q, 'lock', return_value=contextlib.nullcontext()) as lock, patch.object(q, 'admission', side_effect=h.Refused('budget')):
            with self.assertRaisesRegex(h.Refused, 'budget'), h.heavy(self.directory, self.qa_record(), 'build'):
                self.fail('work admitted')
            with h.heavy(self.directory, self.qa_record(), 'cleanup'):
                pass
            self.assertEqual([('host-heavy.lock',), ('host-heavy.lock',)], [c.args for c in lock.call_args_list])

    def test_default_build_never_selects_or_creates_qa_builder(self):
        with patch.object(h, 'run', side_effect=AssertionError('default builder changed')):
            with h.qa_builder(self.directory, self.record) as builder:
                self.assertIsNone(builder)

    def test_qa_builder_bounds_and_cleanup_even_when_build_raises(self):
        record = self.qa_record()
        cli = BuilderCLI(h)
        name = 'opensamguk-qa-build-' + record['nonce']
        with patch.object(q, 'admission'), patch.object(h, 'run', side_effect=cli):
            with self.assertRaisesRegex(RuntimeError, 'synthetic'), h.qa_builder(self.directory, record) as actual:
                self.assertEqual(name, actual['name'])
                raise RuntimeError('synthetic')
        calls = [args for args, kwargs in cli.calls]
        create = next(a for a in calls if a[:3] == ['docker','buildx','create'])
        for option in ('cgroup-parent=user-999.slice','memory=2g','memory-swap=2g','cpu-quota=100000','cpu-period=100000'):
            self.assertIn(option, create)
        self.assertIn(['docker','buildx','rm','--force','--keep-daemon',name], calls)

    def test_builder_collision_is_preserved_not_removed(self):
        name = 'opensamguk-qa-build-' + self.record['nonce']
        with patch.object(h, 'run', return_value=name.encode()) as run:
            with self.assertRaisesRegex(h.Refused, 'already exists'), h.qa_builder(self.directory, self.qa_record()):
                self.fail('collision admitted')
            self.assertEqual(1, run.call_count)

    def test_helper_timeout_cleans_only_verified_own_id(self):
        record = self.qa_record()
        token, cid = 'a'*32, 'b'*64
        name = record['project'] + '-helper-' + token
        labels = {'org.opensamguk.qa.helper':token, h.NONCE_LABEL:record['nonce'],
                  h.SESSION_LABEL:record['session'], h.PROJECT_LABEL:record['project']}
        calls = []
        found = [cid.encode(), b'']
        def run(args):
            calls.append(args)
            if args[:2] == ['docker','inspect']:
                return json.dumps({'Id':cid,'Name':'/'+name,'Labels':labels}).encode()
            if '--no-trunc' in args:
                return found.pop(0)
            return b''
        with patch.object(q.secrets, 'token_hex', return_value=token), patch.object(q, 'admission'):
            with self.assertRaisesRegex(RuntimeError, 'timeout'), q.helper(record, run) as limits:
                self.assertIn('--cgroup-parent', limits)
                raise RuntimeError('timeout')
        self.assertIn(['docker','container','rm','-f',cid], calls)

    def test_helper_cleanup_never_removes_a_foreign_candidate(self):
        record, cid = self.qa_record(), 'b'*64
        calls = []
        def run(args):
            calls.append(args)
            if args[:2] == ['docker','inspect']:
                return json.dumps({'Id':cid,'Name':'/foreign','Labels':{}}).encode()
            return cid.encode() if '--no-trunc' in args else b''
        with patch.object(q, 'admission'), self.assertRaisesRegex(h.Refused, 'Foreign helper'):
            with q.helper(record, run):
                pass
        self.assertFalse(any(a[:3] == ['docker','container','rm'] for a in calls))

    def test_normalized_numeric_caps_keep_exact_origin_and_loopback_boundary(self):
        record = self.qa_record()
        model = h.model_for(record, self.fixtures)
        normalized = copy.deepcopy(model)
        for service in normalized['services'].values():
            service['mem_limit'] = str(q.memory_bytes(service['mem_limit']))
            service['memswap_limit'] = str(q.memory_bytes(service['memswap_limit']))
        normalized['services']['nginx']['ports'][0]['mode'] = 'ingress'
        q.normalized(normalized, model, record)
        for field, value in [('host_ip','0.0.0.0'), ('published','443'), ('mode','host')]:
            bad = copy.deepcopy(normalized)
            bad['services']['nginx']['ports'][0][field] = value
            with self.subTest(field=field), self.assertRaises(h.Refused):
                q.normalized(bad, model, record)
        bad = copy.deepcopy(normalized)
        bad['services']['web-game']['environment']['SERVER_REGISTRY_JSON'] = '[]'
        with self.assertRaises(h.Refused):
            q.normalized(bad, model, record)

    @unittest.skipUnless(os.environ.get('OPENSAMGUK_QA_READONLY_COMPOSE') == '1', 'explicit read-only Compose test only')
    def test_real_compose_hostinger_normalization(self):
        record = dict(self.qa_record(), profile='tactical')
        fixtures = h.profile_fixtures(record, self.fixtures)
        model = h.model_for(record, fixtures)
        h.write_json(self.directory / 'compose.json', model)
        # Real local CLI, no pull/build/up/inspect/daemon writes; generated fixture never printed.
        with q.lock('host-heavy.lock', timeout=300):
            normalized = json.loads(h.compose(self.directory, record, 'config', '--format', 'json'))
        self.assertEqual(model['name'], normalized['name'])
        q.normalized(normalized, model, record)
        for name, service in model['services'].items():
            self.assertEqual(service.get('environment', {}), normalized['services'][name].get('environment', {}))


if __name__ == '__main__':
    unittest.main()
