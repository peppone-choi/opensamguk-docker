"""Hostinger recovery policy tests. All Docker/DB/auth effects use the existing synthetic adapter."""
import copy
import hashlib
from pathlib import Path
from unittest.mock import patch
import unittest
import test_recovery as fixtures
from storage import digest, read, write, put
r = fixtures.r
q = r.fresh.qa


class HostingerRecoveryTests(unittest.TestCase):
    def setUp(self):
        # Reuse only fixture setup/helpers, not the inherited test list.
        self.fixture = fixtures.RecoveryTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        f = self.fixture
        f.record.update(hostingerQA=q.selection('t_9906f2dd'), origin=q.ORIGIN)
        f.record['project'] = q.project(f.record)
        canonical = (r.ROOT / 'infra/nginx/nginx.conf').read_bytes()
        put(f.source / 'nginx.conf', q.nginx(f.record, canonical), replace=True)
        write(f.source / 'hostinger-qa.json', {'nonce':f.record['nonce'], 'selection':f.record['hostingerQA']})
        f.record['nginxSha256'] = digest(f.source / 'nginx.conf')
        for svc in r.fresh.SERVICES:
            image = f.record['images'][svc]['imageId']
            f.io.image_data[image]['Config']['Labels'] = r.fresh.image_metadata(f.record, svc, {})
            f.record['images'][svc]['buildArgs'] = r.fresh.build_args(f.record, svc)
        f.model = r.fresh.model_for(f.record, read(f.source / 'runtime.json'))
        write(f.source / 'compose.json', f.model, replace=True)
        f.record['configSha256'] = digest(f.source / 'compose.json')
        write(f.source / 'contract.json', f.record, replace=True)
        # Canonical source reader only; fake adapter never accesses a real daemon.
        old_run = f.io.run
        def run(args, **kwargs):
            if args[0] == 'git' and args[-1].endswith(':infra/nginx/nginx.conf'):
                return canonical
            if args[0] == 'git' and args[-1].endswith(':tools/localhost-acceptance/hostinger_qa.py'):
                return Path(q.__file__).read_bytes()
            return old_run(args, **kwargs)
        f.io.run = run
        r.fresh.run = run
        old_install = f.io.install
        def install(record, model, running=True):
            old_install(record, model, running)
            for row in f.io.containers.values():
                if row['Config']['Labels'][r.fresh.PROJECT_LABEL] != record['project']:
                    continue
                service = row['Config']['Labels']['com.docker.compose.service']
                row['HostConfig'].update(CgroupParent=q.CGROUP, Memory=q.MEMORY[service]*q.MIB,
                                         MemorySwap=q.MEMORY[service]*q.MIB, NanoCpus=int(float(q.CPUS[service])*10**9))
                if service == 'nginx':
                    row['HostConfig']['PortBindings']['443/tcp'][0]['HostPort'] = '18443'
        f.io.install = install
        f.io.containers.clear(); f.io.volumes.clear(); f.io.networks.clear()
        install(f.record, f.model)
        self.admission = patch.object(q, 'admission', return_value={'scope':'synthetic'})
        self.admission.start(); self.addCleanup(self.admission.stop)
        self.port = patch.object(r.fresh, 'port_free')
        self.port.start(); self.addCleanup(self.port.stop)

    def test_synthetic_A_B_A_keeps_origin_caps_selection_and_exact_mounts(self):
        f = self.fixture
        f.backup(); version = f.version()
        self.assertEqual(f.record['hostingerQA'], read(version)['hostingerQA'])
        b, a = f.root / 'B', f.root / 'A-return'
        f.engine.restore(f.bundle, b, version)
        f.engine.observe(b); f.engine.stop_target(b)
        f.engine.rollback(f.bundle, b, a)
        f.engine.observe(a); f.engine.stop_target(a)
        self.assertTrue(f.engine.resume(f.bundle)['fullFlowObserved'])
        for path in (a, b):
            target = read(path / 'target.json')['record']
            self.assertEqual(q.ORIGIN, target['origin'])
            self.assertTrue(target['project'].startswith('opensamguk-qa-t_9906f2dd-recovery-'))
            self.assertEqual(f.record['hostingerQA'], target['hostingerQA'])
            model = read(path / 'compose.json')
            q.validate(model, target)
            self.assertEqual(f.model['services']['nginx']['ports'], model['services']['nginx']['ports'])
        helper_calls = [args for args in f.io.calls if args[:2] == ['docker','run']]
        self.assertTrue(helper_calls)
        for args in helper_calls:
            self.assertEqual(q.CGROUP, args[args.index('--cgroup-parent')+1])
            self.assertEqual('0.1', args[args.index('--cpus')+1])
            self.assertEqual('32m', args[args.index('--memory-swap')+1])

    def test_tampered_target_selection_and_foreign_runtime_caps_are_refused(self):
        f = self.fixture
        f.backup()
        target = f.root / 'target'
        f.engine.restore(f.bundle, target)
        t = read(target / 'target.json')
        t['record']['hostingerQA']['port'] = 443
        write(target / 'target.json', t, replace=True)
        with self.assertRaises(Exception):
            f.engine.target(target)
        row = next(iter(f.io.containers.values()))
        row['HostConfig']['CgroupParent'] = 'system.slice'
        with self.assertRaises(r.fresh.Refused):
            f.engine.verify(f.record, f.model)

    def test_over_budget_restore_creates_no_target_or_resources(self):
        f = self.fixture
        f.backup()
        before = copy.deepcopy(f.io.containers)
        target = f.root / 'target'
        with patch.object(q, 'admission', side_effect=r.fresh.Refused('budget REFUSED')):
            with self.assertRaisesRegex(r.fresh.Refused, 'budget REFUSED'):
                f.engine.restore(f.bundle, target)
        self.assertFalse(target.exists())
        self.assertEqual(before, f.io.containers)

    def test_native_grant_is_never_copied_or_silently_downgraded(self):
        f = self.fixture
        f.record['nativeWriter'] = {'proof':{'syntheticGrant':True}}
        write(f.source / 'contract.json', f.record, replace=True)
        with self.assertRaises(Exception):
            f.engine.source(f.source)
        self.assertFalse(any(args[1:2] == ['kill'] for args in f.io.calls))


if __name__ == '__main__':
    unittest.main()
