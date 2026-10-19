"""Private subprocess/TLS boundary checks without Docker or network access."""
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import urllib.error
from unittest.mock import patch

from storage import Refused, newdir, put, write
from transport import LocalIO, NoRedirect


class Response:
    status=200
    def __init__(self, body): self.body=body
    def __enter__(self): return self
    def __exit__(self,*args): pass
    def read(self,limit): return self.body


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name).resolve()
        self.logs=newdir(self.root/'logs');self.io=LocalIO(self.logs)

    def test_remote_host_refused_and_valid_unix_socket_is_pinned(self):
        with patch.dict(os.environ,DOCKER_HOST='tcp://remote:2375'):
            with self.assertRaisesRegex(Refused,'REMOTE_DOCKER'):self.io.local()
        with patch.dict(os.environ,DOCKER_HOST='unix:///fixture.sock',DOCKER_CONTEXT='foreign'):
            self.io.local()
            self.assertEqual(self.io.command(['docker','ps']),['docker','--host','unix:///fixture.sock','ps'])
            self.assertNotIn('DOCKER_CONTEXT',self.io.environment())

    def test_raw_child_failure_stays_private_and_exception_has_no_secret(self):
        secret=b'FAKE_PASSWORD_SENTINEL'
        done=subprocess.CompletedProcess(['fake'],1,stdout=secret,stderr=secret)
        with patch('transport.subprocess.run',return_value=done):
            with self.assertRaisesRegex(Refused,'CHILD_FAILED') as raised:self.io.run(['docker','fake'])
        self.assertNotIn(secret.decode(),str(raised.exception))
        files=list(self.logs.iterdir());self.assertEqual(len(files),1)
        self.assertEqual(files[0].stat().st_mode & 0o777,0o600)
        self.assertNotIn(secret,files[0].read_bytes())
        self.assertEqual(json.loads(files[0].read_bytes())['returncode'],1)

    def test_redirect_never_forwards_cookie_or_login_payload(self):
        with self.assertRaisesRegex(Refused,'REDIRECT'):NoRedirect().redirect_request(None,None,None,None,None,None)

    def test_container_log_observation_retains_counts_without_auth_body(self):
        done=subprocess.CompletedProcess(['fake'],0,stdout=b'FAKE_PASSWORD_TOKEN\nrequest-123 ok\n',stderr=b'ERROR secret\n')
        with patch('transport.subprocess.run',return_value=done):
            result=self.io.log_summary('a'*64,'request-123')
        self.assertEqual(result['lines'],3);self.assertEqual(result['errorLines'],1)
        self.assertEqual(result['requestLines'],1)
        self.assertNotIn('secret',json.dumps(result))
        self.assertEqual(list(self.logs.iterdir()),[])

    def test_user_probe_logs_in_without_register_join_or_returned_auth(self):
        custody=newdir(self.root/'custody');newdir(custody/'certs')
        write(custody/'fixture.json',{'user':{'username':'FAKE','password':'FAKE_SECRET'}})
        seen=[]
        class Opener:
            def open(self,request,timeout):
                seen.append(request)
                if isinstance(request,str):
                    if request.endswith('/') and not request.endswith('/game/'):return Response(b'ok')
                    code=401 if request.endswith('/api/gateway/auth/me') else 404
                    raise urllib.error.HTTPError(request,code,'boundary',{},None)
                if request.full_url.endswith('/health'):return Response(b'ok\n')
                if request.full_url.endswith(('/api/auth/login','/api/auth/me')):
                    return Response(json.dumps({'user':{'id':7,'role':'USER'},'accessToken':'FAKE_TOKEN'}).encode())
                if 'front-info' in request.full_url:return Response(b'{"general":{"generalId":2}}')
                return Response(b'{"status":"RESOLVED","ok":true}')
        with patch('transport.ssl.create_default_context'),patch('transport.urllib.request.build_opener',return_value=Opener()):
            result=self.io.user_probe(custody,{'serverId':'lha'+'a'*16},2,'12345678-1234-1234-1234-123456789abc')
        self.assertTrue(result['login']);self.assertNotIn('FAKE_TOKEN',json.dumps(result))
        self.assertEqual([x.method for x in seen if not isinstance(x,str)],['GET','POST','GET','GET','GET'])
        self.assertFalse(any('register' in x.full_url or '/join' in x.full_url for x in seen if not isinstance(x,str)))
        self.assertEqual(list(self.logs.iterdir()),[])


if __name__ == '__main__': unittest.main()
