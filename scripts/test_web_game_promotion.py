#!/usr/bin/env python3
"""Lightweight source/fake-command workflow contract. No Go build or real Docker."""
import json, os, pathlib, re, shlex, subprocess, sys, tempfile, unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
BASE='bba2692b0073af6e6326c2bb7b5a181c3afa6ae9'
WORKFLOW=ROOT/'.github/workflows/promote-web-game.yml'
MAIN=(ROOT/'deployer/main.go').read_text()
WEB=(ROOT/'deployer/web_game_deploy.go').read_text()

def function(text,name):
    match=re.search(r'func (?:\([^\n]+\) )?'+re.escape(name)+r'\([^\n]*\)[^\n]*\{',text)
    if not match: raise AssertionError(name)
    start=match.start();depth=0
    for i in range(text.index('{',match.start()),len(text)):
        if text[i]=='{':depth+=1
        elif text[i]=='}':
            depth-=1
            if depth==0:return text[start:i+1]
    raise AssertionError('unclosed '+name)

def workflow_run(overrides=None,mutation=None):
    text=WORKFLOW.read_text()
    shell='\n'.join(line[10:] for line in text.split('        run: |\n',1)[1].splitlines())+'\n'
    if mutation:shell=mutation(shell)
    with tempfile.TemporaryDirectory(prefix='c8-web-workflow-fixture-') as directory:
        temp=pathlib.Path(directory);bin_dir=temp/'bin';bin_dir.mkdir()
        # Replace only the lock path to isolate the local fixture from any real host lock.
        shell=shell.replace('/tmp/opensamguk-production.lock',str(temp/'production.lock'))
        fake=temp/'docker-fixture.py'
        fake.write_text('''#!/usr/bin/env python3
import json,sys,os
expected=['exec','-i','opensamguk-deployer','/usr/local/bin/deployer','--authenticated-http','POST','/deploy/web-game','900']
if sys.argv[1:]!=expected:raise SystemExit(42)
p=json.load(sys.stdin)
open(os.environ['FIXTURE_CAPTURE'],'w').write(json.dumps({'args':sys.argv[1:],'payload':p}))
print(json.dumps({'ok':True,'service':'web-game','project':p['project'],'tag':p['tag'],'digest':p['digest']}))
''')
        fake.chmod(0o755)
        # Intercept the complete command shape in a shell function. No executable named
        # sudo/docker/timeout is launched; each original argument is checked by the fixture.
        prefix = 'flock() { return 0; }\ntimeout() { [ "$1" = 930s ] && [ "$2" = sudo ] && [ "$3" = -n ] && [ "$4" = docker ] || return 41; shift 4; ' + shlex.quote(sys.executable) + ' ' + shlex.quote(str(fake)) + ' "$@"; }\n'
        shell = prefix + shell
        env={'PATH':str(bin_dir)+os.pathsep+os.environ.get('PATH',''),'APPROVED_SERVER':'pep','APPROVED_SOURCE_SHA':'a'*40,'APPROVED_IMAGE_DIGEST':'sha256:'+'b'*64,'EXPECTED_WEB_GAME_TAG':'old-web','EXPECTED_WORLD_ID':'1','EXPECTED_GENERATION':'1','FIXTURE_CAPTURE':str(temp/'capture.json')}
        env.update(overrides or {})
        result=subprocess.run(['bash'],input=shell,text=True,env=env,capture_output=True,timeout=5)
        capture=json.loads((temp/'capture.json').read_text()) if (temp/'capture.json').exists() else None
        return result,capture

class WebPromotionContract(unittest.TestCase):
    def test_workflow_submits_exact_web_route_and_approval_preconditions(self):
        result,capture=workflow_run();self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(capture['payload'],{'project':'opensamguk-spep','tag':'a'*40,'digest':'sha256:'+'b'*64,'expectedWebGameTag':'old-web','expectedWorldId':1,'expectedGeneration':1})
        self.assertNotIn('DEPLOYER_TOKEN',' '.join(capture['args']))
    def test_workflow_preserves_existing_digest_pin_as_CAS(self):
        expected='c'*40+'@sha256:'+'d'*64
        result,capture=workflow_run({'EXPECTED_WEB_GAME_TAG':expected})
        self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(capture['payload']['expectedWebGameTag'],expected)
    def test_malformed_inputs_do_not_call_docker(self):
        for key,value in [('APPROVED_SERVER','../pep'),('APPROVED_SERVER','pep;echo bad'),('APPROVED_SOURCE_SHA','latest'),('APPROVED_IMAGE_DIGEST','sha256:bad'),('EXPECTED_WEB_GAME_TAG','old\nIMAGE_TAG=bad'),('EXPECTED_WORLD_ID','0'),('EXPECTED_WORLD_ID','2147483648'),('EXPECTED_GENERATION','-1')]:
            with self.subTest(key=key,value=value):
                result,capture=workflow_run({key:value});self.assertNotEqual(result.returncode,0);self.assertIsNone(capture)
    def test_host_lock_and_no_broad_control_operations(self):
        text=WORKFLOW.read_text();self.assertIn('exec 9>/tmp/opensamguk-production.lock',text);self.assertIn('flock -w 1800 9',text)
        for forbidden in ['actions/checkout','docker compose','git fetch','git merge','/maintenance/enter','/maintenance/leave','/deploy 900','build deployer','SCENARIO_DIR','RTK14_STATS']:
            self.assertNotIn(forbidden,text)
    def test_route_keeps_authentication_loopback_and_new_cli_allowlist(self):
        self.assertIn('mux.HandleFunc("/deploy/web-game", cfg.webGameDeployHTTPHandler())',MAIN)
        self.assertIn('c.withAuth(c.withLoopback(c.handleWebGameDeploy))',function(WEB,'webGameDeployHTTPHandler'))
        self.assertIn('"/deploy/web-game"',function(MAIN,'isAuthenticatedHTTPRouteAllowed'))
        self.assertIn('DisallowUnknownFields()',WEB)
    def test_native_legacy_deploy_and_compose_are_byte_preserved(self):
        baseline=subprocess.run(['git','show',BASE+':deployer/main.go'],cwd=ROOT,capture_output=True,text=True,check=True).stdout
        for name in ['handleDeploy','writeImageTag','tempImageTagEnvFile','pullStateless','upStateless']:
            self.assertEqual(function(MAIN,name),function(baseline,name),name)
        compose=(ROOT/'docker-compose.server.yml').read_bytes()
        old=subprocess.run(['git','show',BASE+':docker-compose.server.yml'],cwd=ROOT,capture_output=True,check=True).stdout
        self.assertEqual(compose,old)
        self.assertIn(b'web-game-${WEB_GAME_TAG:-${IMAGE_TAG:-latest}}',compose)
    def test_new_compose_calls_select_only_web_and_disable_dependency_recreate(self):
        self.assertIn('"pull", "web-game"',function(WEB,'pullWebGame'))
        self.assertIn('"--no-deps", "--no-build", "--pull", "never", "web-game"',function(WEB,'upWebGame'))
        for name in ['pullWebGame','upWebGame']:
            body=function(WEB,name);self.assertNotIn('"game-api"',body);self.assertNotIn('"game-engine"',body)
    def test_registered_world_generation_and_expected_pin_are_checked_without_registry_rewrite(self):
        body=function(WEB,'requireRegisteredWebGameTarget')
        for required in ['validateServerTarget','OPENSAMGUK_WORLD_ID','SERVER_GENERATION','parseRawRegistryEntries','canonicalRegistryEntries','entry.RepairRequired','entry.DeployProject','entry.GameAPIURL','entry.GameEngineURL']:
            self.assertIn(required,body)
        self.assertNotIn('readRegistry()',body);self.assertNotIn('writeRegistry',WEB);self.assertNotIn('syncRegistry',WEB)
        handler=function(WEB,'handleWebGameDeploy')
        self.assertLess(handler.index('beginMutation'),handler.index('requireExpectedWebGamePin'))
        self.assertEqual(handler.count('requireExpectedWebGamePin'),2)
        self.assertIn('writeWebGamePinDurable(target.EnvFile, req.pin())',handler)
        self.assertNotIn('"IMAGE_TAG":',handler)
        writer=function(WEB,'writeWebGamePinDurable')
        self.assertIn('writeEnvLinesAtomicDurable',writer)
        self.assertIn('validateWebGameEnvUniqueness',writer)
        self.assertNotIn('patchEnvFile',writer)
    def test_scoped_journal_recovery_never_uses_stateless_pair(self):
        self.assertIn('case "deploy-web":',MAIN)
        body=function(WEB,'repairWebGameDeploy')
        self.assertIn('requireRegisteredWebGameTarget',body);self.assertIn('upWebGame',body);self.assertIn('verifyWebGamePin',body)
        self.assertNotIn('upStateless',body)
        self.assertIn('pin != approved',body);self.assertIn('lifecycleJournalStagePrepared',body)
    def test_persistence_and_pull_failure_boundaries(self):
        body=function(WEB,'handleWebGameDeploy')
        self.assertLess(body.index('pullWebGame'),body.index('writeLifecycleJournalWithResetTarget'))
        self.assertLess(body.index('writeLifecycleJournalWithResetTarget'),body.index('writeWebGamePinDurable'))
        self.assertLess(body.index('writeWebGamePinDurable'),body.index('upWebGame'))
        self.assertLess(body.index('verifyWebGamePin'),body.index('clearLifecycleJournal'))

if __name__=='__main__':unittest.main()
