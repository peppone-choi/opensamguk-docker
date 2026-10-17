#!/usr/bin/env python3
"""Compare the original rate-limit RED with the repair through real proxy hops.

Only disposable labelled nginx sandboxes are used. Never probes the application.
Run only after the coordinator releases the shared heavy slot and authorizes it.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import shutil
import ssl
import subprocess
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
BASELINE = '0a835164023d18c4cccbab8e1cd23448caacaa0e'
ORIGINAL_HASH = 'f0507d5a8bf0ea90cb6cc722b2dde99c2e049c1d517605adbfe764b39721b5e7'
IMAGE = 'nginx:1.30.5-alpine'
LABEL = 'org.opensamguk.nginx-rate-test'
PATHS = ['/api/game/api/front-info', '/api/auth/me', '/api/board/posts',
         '/api/gateway/auth/me', '/api/account/profile-icon', '/api/gateway/auth/account/profile-icon']


def command(*args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=60)
    if result.returncode:
        raise RuntimeError('Synthetic dependency command failed; resources preserved for diagnosis')
    return result.stdout.strip()


@contextmanager
def heavy(meta, owner):
    lock = meta / '.locks/heavy-run'
    if not (meta / 'bin/start-task').is_file():
        raise RuntimeError('Managed meta root required')
    lock.mkdir(mode=0o700)  # Fail closed if the coordinator has not returned the slot.
    marker = f'nginx-rate {owner} driver-pid={os.getpid()}\n'
    try:
        (lock / 'owner').write_text(marker)
        if shutil.disk_usage(meta).free < 3*1024**3 or os.getloadavg()[1] > 400:
            raise RuntimeError('Synthetic resource gate refused')
        yield
    finally:
        if (lock / 'owner').is_file() and (lock / 'owner').read_text() == marker:
            (lock / 'owner').unlink()
            lock.rmdir()


class Sandbox:
    def __init__(self, source, root, case):
        self.owner = 'api-rate-' + secrets.token_hex(8)
        self.directory = root / (case + '-' + self.owner)
        self.directory.mkdir(mode=0o700)
        self.name, self.network = self.owner + '-nginx', self.owner + '-net'
        self.source = source
        self.created_container = self.created_network = False
        self.ports = {}
        self.rows = []

    def __enter__(self):
        try:
            certs = self.directory / 'certs'
            certs.mkdir(mode=0o700)
            (self.directory / 'battle-ws').mkdir()
            command('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                    '-subj', '/CN=localhost', '-keyout', str(certs / 'opensamguk.key'),
                    '-out', str(certs / 'opensamguk.crt'))
            (certs / 'opensamguk.key').chmod(0o600)
            before, closing = self.source.rsplit('}', 1)
            assert not closing.strip()
            # The outer canonical /api/ locations retain proxy_pass and limit_req.
            # These are separate upstream HTTP listeners, reached through actual sockets.
            upstreams = ''
            for port in (3000, 8080):
                upstreams += f'''
    server {{
        listen {port};
        access_log off;
        add_header X-Upstream-Fixture {self.owner} always;
        location = /api/__upstream503 {{ return 503 "upstream-unavailable"; }}
        location / {{ return 200 "upstream-ok"; }}
    }}
'''
            (self.directory / 'nginx.conf').write_text(before + upstreams + '}\n')
            command('docker', 'network', 'create', '--label', LABEL+'='+self.owner, self.network)
            self.created_network = True
            command('docker', 'run', '-d', '--pull=never', '--name', self.name,
                    '--label', LABEL+'='+self.owner, '--network', self.network,
                    '--memory', '64m', '--cpus', '0.5',
                    '--add-host', 'gateway-api:127.0.0.1', '--add-host', 'web-gateway:127.0.0.1',
                    '-p', '127.0.0.1::80', '-p', '127.0.0.1::443',
                    '-v', str(self.directory/'nginx.conf')+':/etc/nginx/nginx.conf:ro',
                    '-v', str(certs)+':/etc/nginx/certs:ro',
                    '-v', str(self.directory/'battle-ws')+':/etc/nginx/battle-ws:ro', IMAGE)
            self.created_container = True
            self.ports = {scheme:int(command('docker', 'port', self.name, port).rsplit(':',1)[1])
                          for scheme,port in [('http','80/tcp'),('https','443/tcp')]}
            for _ in range(40):
                try:
                    if self.request('http', 'GET', '/health')['status'] == 200:
                        break
                except (OSError, http.client.HTTPException):
                    pass
                time.sleep(0.1)
            else:
                raise AssertionError('Synthetic nginx did not become ready')
            command('docker', 'exec', self.name, 'nginx', '-t')
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def request(self, scheme, method, path, barrier=None):
        context = ssl.create_default_context(cafile=str(self.directory/'certs/opensamguk.crt'))
        context.check_hostname = False
        conn = (http.client.HTTPSConnection('127.0.0.1', self.ports[scheme], timeout=8, context=context)
                if scheme == 'https' else http.client.HTTPConnection('127.0.0.1', self.ports[scheme], timeout=8))
        if barrier:
            barrier.wait(timeout=20)
        started = time.monotonic()
        try:
            conn.request(method, path)
            response = conn.getresponse()
            body = response.read()
            row = {'scheme':scheme,'method':method,'path':path,'status':response.status,
                   'proxied':response.getheader('X-Upstream-Fixture') == self.owner,
                   'default503Html':b'<h1>503 Service Temporarily Unavailable</h1>' in body,
                   'elapsedSeconds':round(time.monotonic()-started,4)}
            self.rows.append(row)
            return row
        finally:
            conn.close()

    def fanout(self, scheme, count, methods=('GET','HEAD'), paths=PATHS):
        barrier = threading.Barrier(count)
        with ThreadPoolExecutor(max_workers=count) as pool:
            calls = [pool.submit(self.request, scheme, methods[i%len(methods)], paths[i%len(paths)], barrier)
                     for i in range(count)]
            return [call.result() for call in calls]

    def __exit__(self, *error):
        (self.directory/'requests.json').write_text(json.dumps(self.rows, indent=2))
        if self.created_container:
            result = subprocess.run(['docker','logs',self.name],capture_output=True,text=True)
            # These logs contain only synthetic method/path traffic, never app credentials.
            (self.directory/'nginx.log').write_text(result.stdout+'\n'+result.stderr)
            if command('docker','inspect','--format','{{index .Config.Labels "'+LABEL+'"}}',self.name) == self.owner:
                command('docker','rm','-f',self.name)
        if self.created_network and command('docker','network','inspect','--format',
                '{{index .Labels "'+LABEL+'"}}',self.network) == self.owner:
            command('docker','network','rm',self.network)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--meta', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700)  # Never overwrite a previous failure or run.
    original = command('git','-C',str(ROOT),'show',BASELINE+':infra/nginx/nginx.conf')+'\n'
    fixed = (ROOT/'infra/nginx/nginx.conf').read_text()
    assert hashlib.sha256(original.encode()).hexdigest() == ORIGINAL_HASH
    image_id = command('docker','image','inspect','--format','{{.Id}}',IMAGE)
    report = {'status':'RUNNING','baseline':BASELINE,'baselineSha256':ORIGINAL_HASH,
              'fixedSha256':hashlib.sha256(fixed.encode()).hexdigest(),
              'image':IMAGE,'imageId':image_id,'checks':[],
              'scope':'isolated proxy rate tests; application auth/role/USER acceptance NOT_RUN'}
    def save():
        (args.output/'result.json').write_text(json.dumps(report,indent=2))
    save()
    try:
        with heavy(args.meta.resolve(), secrets.token_hex(16)):
            for scheme in ('http','https'):
                for label, source in [('original',original),('fixed',fixed)]:
                    with Sandbox(source,args.output,label+'-fanout-'+scheme) as box:
                        rows=box.fanout(scheme,32)
                        rejected=sum(r['status']==503 and not r['proxied'] for r in rows)
                        if label=='original':
                            assert rejected>0 and any(r['proxied'] for r in rows)
                            assert any(r['default503Html'] for r in rows)
                        else:
                            assert all(r['status']==200 and r['proxied'] for r in rows)
                            assert any(r['elapsedSeconds']>=0.3 for r in rows)
                            assert max(r['elapsedSeconds'] for r in rows)<5
                        report['checks'].append({'case':label+'-fanout','scheme':scheme,'requests':32,
                                                 'limiter503':rejected,'observation':'RED' if label=='original' else 'PASS',
                                                 'maxSeconds':max(r['elapsedSeconds'] for r in rows)})
                    save()
                for name,methods,paths,count in [
                    ('mutations',('POST','PATCH','PUT','DELETE','OPTIONS'),PATHS,40),
                    ('login',('POST',),['/api/auth/login','/api/gateway/auth/login'],40),
                    ('read-overflow',('GET','HEAD'),PATHS,96)]:
                    with Sandbox(fixed,args.output,name+'-'+scheme) as box:
                        rows=box.fanout(scheme,count,methods,paths)
                        assert any(r['status']==503 and not r['proxied'] for r in rows)
                        assert any(r['status']==200 and r['proxied'] for r in rows)
                        if name=='read-overflow':
                            assert any(r['elapsedSeconds']>=0.3 for r in rows)
                            # Saturated read requests cannot consume the write bucket.
                            assert box.request(scheme,'POST','/api/auth/login')['proxied']
                        else:
                            # Saturated mutation/login requests cannot consume the read bucket.
                            assert box.request(scheme,'GET','/api/auth/me')['proxied']
                        report['checks'].append({'case':name,'scheme':scheme,'requests':count,
                            'limiter503':sum(r['status']==503 and not r['proxied'] for r in rows),
                            'maxSeconds':max(r['elapsedSeconds'] for r in rows)})
                    save()
                with Sandbox(fixed,args.output,'upstream503-'+scheme) as box:
                    row=box.request(scheme,'GET','/api/__upstream503')
                    assert row['status']==503 and row['proxied'] and not row['default503Html']
                    report['checks'].append({'case':'upstream503-preserved','scheme':scheme})
                save()
            with Sandbox(fixed,args.output,'shared-http-tls-write-bucket') as box:
                box.fanout('http',40,('POST',),['/api/auth/login'])
                row=box.request('https','POST','/api/auth/login')
                assert row['status']==503 and not row['proxied']
                report['checks'].append({'case':'shared-http-tls-write-bucket'})
            report['status']='PASS'
            save()
    except BaseException:
        report['status']='FAIL'
        save()
        raise
    print(json.dumps(report,indent=2))


if __name__ == '__main__':
    main()
