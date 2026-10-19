"""Local CLI/TLS adapters; raw auth and log bodies never enter diagnostic files."""
import http.cookiejar
import json
import os
from pathlib import Path
import ssl
import subprocess
import re
import urllib.request
import urllib.error

from storage import need, put, private, Refused
import runtime_binding as route


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise Refused('REDIRECT_REFUSED')


class LocalIO:
    def __init__(self, logs):
        self.logs = private(logs, True)
        self.seq = 0
        self.endpoint = None

    def command(self, args):
        if args[0] == 'docker' and self.endpoint:
            return ['docker', '--host', self.endpoint, *args[1:]]
        return args

    def environment(self):
        env = os.environ.copy()
        for key in ('DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH'):
            env.pop(key, None)
        return env

    def run(self, args, *, input=None, timeout=60, cwd=None, log_path=None):
        self.seq += 1
        try:
            done = subprocess.run(self.command(args), input=input, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, timeout=timeout, cwd=cwd, env=self.environment())
            put(self.logs / f'child-{self.seq}.json', json.dumps({'family':args[0],
                'returncode':done.returncode,'stdoutBytes':len(done.stdout),'stderrBytes':len(done.stderr)}).encode())
            need(done.returncode == 0, 'CHILD_FAILED')
            return done.stdout
        except (subprocess.TimeoutExpired, OSError):
            raise Refused('CHILD_UNAVAILABLE') from None

    def stream(self, args, path, *, incoming=False):
        self.seq += 1
        error = self.logs / f'child-{self.seq}.json'
        if not incoming:
            put(path, b'')
        else:
            private(path)
        with open(path, 'rb' if incoming else 'wb') as data:
            try:
                done = subprocess.run(self.command(args), stdin=data if incoming else subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL if incoming else data, stderr=subprocess.PIPE, timeout=1800, env=self.environment())
                if not incoming:
                    data.flush()
                    os.fsync(data.fileno())
                put(error,json.dumps({'family':args[0],'returncode':done.returncode,'stderrBytes':len(done.stderr)}).encode())
                need(done.returncode == 0, 'STREAM_FAILED')
            except (subprocess.TimeoutExpired, OSError):
                raise Refused('STREAM_UNAVAILABLE') from None

    def local(self):
        host = os.environ.get('DOCKER_HOST', '')
        if not host:
            host = json.loads(self.run(['docker', 'context', 'inspect', '--format',
                                       '{{json .Endpoints.docker.Host}}']))
        need(isinstance(host, str) and host.startswith('unix:///') and '\n' not in host,
             'REMOTE_DOCKER_REFUSED')
        self.endpoint = host

    def port_free(self):
        import socket
        with socket.socket() as sock:
            sock.settimeout(2)
            need(sock.connect_ex(('127.0.0.1', 443)) != 0, 'TLS_PORT_BUSY')

    def log_summary(self, cid, request_id):
        need(re.fullmatch('[a-f0-9]{64}',cid), 'LOG_CONTAINER_ID')
        try:
            done = subprocess.run(self.command(['docker','logs','--timestamps','--tail','500',cid]),
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,env=self.environment())
            need(done.returncode == 0,'LOG_READ_FAILED')
            lines=(done.stdout+done.stderr).splitlines()
            return {'lines':len(lines),'errorLines':sum(bool(re.search(rb'error|fatal|panic|exception',v,re.I)) for v in lines),
                    'requestLines':sum(request_id.encode() in v for v in lines),'tailLimit':500}
        except (subprocess.TimeoutExpired,OSError):
            raise Refused('LOG_READ_UNAVAILABLE') from None

    def user_probe(self, custody, identity, general_id, request_id):
        """Normal USER login only, without register/join/SQL repair or returned credentials."""
        contract_path = Path(custody) / 'contract.json'
        record = json.loads(private(contract_path).read_bytes()) if contract_path.exists() else identity
        origin = record.get('origin', 'https://localhost')
        need(origin == identity.get('origin', 'https://localhost') and
             origin == ('https://localhost:18443' if 'hostingerQA' in record else 'https://localhost'), 'USER_PROBE_ORIGIN')
        fixture = json.loads(private(Path(custody) / 'fixture.json').read_bytes())
        context = ssl.create_default_context(cafile=str(Path(custody) / 'certs/opensamguk.crt'))
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
            urllib.request.HTTPSHandler(context=context),
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        def request(path, body=None, json_body=True):
            payload = None if body is None else json.dumps(body).encode()
            req = urllib.request.Request(origin + path, data=payload,
                headers={'Content-Type': 'application/json'}, method='GET' if body is None else 'POST')
            with opener.open(req, timeout=30) as response:
                need(response.status == 200, 'HTTP_STATUS')
                raw = response.read(4 * 1024 * 1024)
                return json.loads(raw) if json_body else True
        request('/health', json_body=False)
        need(record.get('serverId') == identity['serverId'], 'USER_PROBE_IDENTITY')
        for path, status in [('/api/gateway/auth/me', 401), *route.boundaries(record),
            ('/d_pic/.ops/private', 404), ('/game/', 404), ('/', 200)]:
            try:
                with opener.open(origin + path, timeout=30) as response:
                    need(response.status == status, 'BOUNDARY_STATUS')
            except urllib.error.HTTPError as error:
                code = error.code
                error.close()
                need(code == status, 'BOUNDARY_STATUS')
        credentials = {k: fixture['user'][k] for k in ('username', 'password')}
        login = request('/api/auth/login', credentials)
        me = request('/api/auth/me')
        need(login.get('user', {}).get('role') == 'USER' and
             me.get('user', {}).get('role') == 'USER' and
             me['user']['id'] == login['user']['id'], 'NORMAL_USER_LOGIN')
        prefix = '/api/game/api/'
        suffix = '?server=' + identity['serverId']
        front = request(prefix + 'front-info' + suffix)
        need(front.get('general', {}).get('generalId') == general_id, 'USER_ACTOR')
        result = request(prefix + 'command/result/' + request_id + suffix)
        need(result.get('requestId', request_id) == request_id and
             result.get('status') == 'RESOLVED' and result.get('ok') is True, 'USER_RESULT')
        return {'login': True, 'generalId': general_id, 'requestId': request_id, 'resolved': True}
