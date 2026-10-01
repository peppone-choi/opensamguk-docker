#!/usr/bin/env python3
"""격리 임시 파일과 가짜 Docker 경계로 승격/복구 CAS를 검증한다."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import sys
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import patch
import direct_web_promotion as p

NEW='a'*40; OLD='b'*40; MANIFEST='sha256:'+'c'*64; CONFIG='sha256:'+'d'*64
OLD_MANIFEST='sha256:'+'e'*64; OLD_CONFIG='sha256:'+'f'*64

def fixtures():
    candidate={'status':'VERIFIED_CANDIDATE','deployment_approved':False,'repository':p.REPO,
               'platform':'linux/amd64','source_sha':NEW,'platform_manifest_digest':MANIFEST,'config_digest':CONFIG}
    cr=json.dumps(candidate).encode()
    probe={'status':'PASS','owned_created_container_removed':True,'plan':{'candidate_sha256':p.digest(cr),
           'source_sha':NEW,'platform_manifest_digest':MANIFEST,'config_digest':CONFIG}}
    pr=json.dumps(probe).encode()
    old=[{'reference':r,'status':200,'registryDigest':OLD_MANIFEST,'rawManifestDigest':OLD_MANIFEST,
          'configDigest':OLD_CONFIG,'os':'linux','architecture':'amd64','metadataAndBlobAccess':True}
         for r in [OLD_MANIFEST,'web-game-'+OLD]]
    old_raw=json.dumps({'references':old}).encode()
    card={'schema':'direct-web-promotion/v1','serverId':'pep','worldId':1,'generation':1,
          'operations':p.OPS,'executorSha256':p.digest(Path(p.__file__).read_bytes()),
          'candidateSha256':p.digest(cr),'probeSha256':p.digest(pr),'sourceSha':NEW,'platformDigest':MANIFEST,
          'configDigest':CONFIG,'oldPlatformDigest':OLD_MANIFEST,'oldConfigDigest':OLD_CONFIG,'oldSourceSha':OLD,
          'oldRegistryVerified':True,'oldLocalImageVerified':True,'oldRegistrySha256':p.digest(old_raw),
          'controlBinarySha256':'0'*64,'composeSha256':p.digest(b'fixture compose\n')}
    return card,cr,pr,old_raw

class FakeHost(p.Host):
    def __init__(self,root,card,promotion):
        super().__init__(root,card,promotion)
        self.calls=[];self.state='open'; self.fail=None;self.control_change=False; self.other_change=False
        self.recreate_count=0
        self.ctrl={'id':'control-id','startedAt':'start','binarySha256':card['controlBinarySha256']}
        self.web={'id':'old-web','imageId':'old-local-id','configuredImage':promotion['oldReference'],'startedAt':'old-start','running':True}
        self.other={'id':'engine-original','imageId':'engine-img','configuredImage':'engine-pin','startedAt':'engine-start','running':True}
        card.update(controlContainerId='control-id',controlStartedAt='start',oldWebContainer=copy.deepcopy(self.web),
                    expectedSelectedEnv=p.selected_env(self.env),expectedComposeImages=[promotion['oldReference'],'engine-pin'])
    def maintenance(self,method='GET',path='/maintenance'):
        self.calls.append((method,path))
        if path=='/maintenance/enter-if-idle':
            self.state='drained';self.marker.write_text('{"capability":"maintenance-v1"}\n')
            return {'capability':'maintenance-v1','state':'drained','lease':'1'*32}
        if path=='/maintenance/leave':
            self.state='open';self.marker.unlink()
        return {'capability':'maintenance-v1','state':self.state}
    def control(self):
        return dict(self.ctrl,id='changed-control') if self.control_change else self.ctrl.copy()
    def containers(self):
        return {'spep-web-game':self.web.copy(),'spep-game-engine':dict(self.other,id='changed-engine') if self.other_change else self.other.copy(),
                'opensamguk-deployer':self.ctrl.copy()}
    def image(self,ref):
        return {'id':'old-local-id' if ref==self.promotion['oldReference'] else 'new-local-id',
                'repoDigests':[self.promotion['oldRepoDigest'] if ref==self.promotion['oldReference'] else p.REPO+'@'+MANIFEST],
                'os':'linux','architecture':'amd64'}
    def docker(self,*args,timeout=30):
        self.calls.append(args)
        if self.fail=='pull':raise p.Halt('fixture pull fail')
        if self.fail=='control-after-pull':self.control_change=True
        if self.fail=='other-after-pull':self.other_change=True
        return ''
    def compose(self,*args,timeout=30):
        self.calls.append(args)
        if args[0]=='config':
            pin=p.selected_env(self.env)['WEB_GAME_TAG']
            return '\n'.join([p.REPO+':web-game-'+pin,'engine-pin'])
        self.recreate_count+=1
        if self.fail=='up-once' and self.recreate_count==1:raise p.Halt('fixture up failure')
        ref=p.REPO+':web-game-'+p.selected_env(self.env)['WEB_GAME_TAG']
        self.web=dict(self.web,id='new-web' if ref==self.promotion['newReference'] else 'rollback-web',
                      imageId=self.image(ref)['id'],configuredImage=ref,startedAt='new-start')
        return ''
    def verify_web(self,ref,expected_image_id=None):
        self.calls.append(('verify',ref))
        p.require(self.web['configuredImage']==ref,'fixture reference')
        if expected_image_id:p.require(self.web['imageId']==expected_image_id,'fixture local id')
        return self.web.copy()

class DirectWebPromotionTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);(self.root/'servers').mkdir()
        self.env=self.root/'servers/spep.env'
        self.original=(f'SERVER_ID=pep\nOPENSAMGUK_WORLD_ID=1\nSERVER_GENERATION=1\nIMAGE_TAG={OLD}\nWEB_GAME_TAG={OLD}\n'
                       'GAME_POSTGRES_PASSWORD=fixture-secret-never-output\n# preserve\n').encode()
        self.env.write_bytes(self.original);(self.root/'docker-compose.server.yml').write_bytes(b'fixture compose\n')
        self.card,self.cr,self.pr,self.old=fixtures();self.promotion=p.plan(self.card,self.cr,self.pr)
        self.host=FakeHost(self.root,self.card,self.promotion);self.receipt=self.root/'servers/.direct-web-promotion/own.json'
    def run_promotion(self):return p.perform(self.host,self.receipt,'card-hash',self.promotion)
    def test_default_plan_does_not_call_docker(self):
        with patch.object(p.subprocess,'run',side_effect=AssertionError('Docker called')):
            self.assertFalse(p.plan(self.card,self.cr,self.pr)['automaticLeave'])
    def test_cli_plan_or_missing_A02_never_issues_Docker(self):
        paths=[]
        for name,raw in [('card',json.dumps(self.card).encode()),('candidate',self.cr),('probe',self.pr),('old',self.old)]:
            path=self.root/name;path.write_bytes(raw);paths.append(str(path))
        argv=['direct_web_promotion',*paths[:3],'--old-registry',paths[3]]
        with patch.object(sys,'argv',argv),patch.object(p.subprocess,'run',side_effect=AssertionError('Docker')),redirect_stdout(StringIO()):
            self.assertEqual(0,p.main())
        with patch.object(sys,'argv',argv+['--execute']),patch.object(p.subprocess,'run',side_effect=AssertionError('Docker')),redirect_stdout(StringIO()):
            self.assertEqual(1,p.main())
    def test_byte_source_platform_and_native_proof_pins_fail_closed(self):
        for key,value in [('sourceSha','9'*40),('platformDigest',CONFIG),('configDigest',MANIFEST),
                          ('probeSha256','9'*64),('executorSha256','9'*64),('oldRegistryVerified',False),('operations',[])]:
            card=dict(self.card);card[key]=value
            with self.subTest(key=key),self.assertRaises(p.Halt):p.plan(card,self.cr,self.pr)
        probe=json.loads(self.pr);probe['status']='PLAN_ONLY_NOT_EXECUTED';raw=json.dumps(probe).encode()
        card=dict(self.card,probeSha256=p.digest(raw))
        with self.assertRaises(p.Halt):p.plan(card,self.cr,raw)
    def test_patch_preserves_every_other_byte_and_metadata(self):
        before=self.env.stat();p.patch_web_pin(self.env,p.selected_env(self.env),self.promotion['newPin'],p.file_identity(self.env))
        self.assertEqual(self.original.replace(('WEB_GAME_TAG='+OLD).encode(),('WEB_GAME_TAG='+self.promotion['newPin']).encode()),self.env.read_bytes())
        after=self.env.stat();self.assertEqual((before.st_uid,before.st_gid,before.st_mode),(after.st_uid,after.st_gid,after.st_mode))
    def test_duplicate_or_concurrent_config_change_rejects_before_patch(self):
        expected=p.selected_env(self.env);identity=p.file_identity(self.env)
        self.env.write_bytes(self.original+b'WEB_GAME_TAG=duplicate\n')
        with self.assertRaises(p.Halt):p.patch_web_pin(self.env,expected,self.promotion['newPin'],identity)
        with self.assertRaises(p.Halt):p.selected_env(self.env)
    def test_success_changes_web_only_and_stays_drained(self):
        self.assertEqual('CANDIDATE_VERIFIED_DRAINED',self.run_promotion())
        receipt=json.loads(self.receipt.read_text())
        self.assertEqual('old-web',receipt['baseline']['spep-web-game']['id'])
        self.assertEqual('engine-original',self.host.other['id']);self.assertTrue(self.host.marker.exists())
        self.assertNotIn(('POST','/maintenance/leave'),self.host.calls)
        self.assertEqual(0o600,self.receipt.stat().st_mode & 0o777)
        self.assertIn(('up','-d','--no-deps','--pull','never','--force-recreate','web-game'),self.host.calls)
        self.assertEqual(1,self.host.recreate_count)
    def test_preexisting_other_window_never_enters_or_leaves(self):
        self.host.marker.write_text('other')
        with self.assertRaises(p.Halt):self.run_promotion()
        self.assertFalse(self.host.calls);self.assertEqual('other',self.host.marker.read_text())
    def test_pull_failure_verifies_old_but_does_not_leave(self):
        self.host.fail='pull'
        with self.assertRaises(p.Halt):self.run_promotion()
        self.assertEqual('OLD_VERIFIED_DRAINED',json.loads(self.receipt.read_text())['stage'])
        self.assertEqual(self.original,self.env.read_bytes());self.assertTrue(self.host.marker.exists())
        self.assertEqual(0,self.host.recreate_count)
    def test_candidate_up_failure_restores_original_pin_and_local_old_image(self):
        self.host.fail='up-once'
        with self.assertRaises(p.Halt):self.run_promotion()
        self.assertEqual('OLD_VERIFIED_DRAINED',json.loads(self.receipt.read_text())['stage'])
        self.assertEqual(self.original,self.env.read_bytes());self.assertEqual('old-local-id',self.host.web['imageId'])
        self.assertEqual(2,self.host.recreate_count)
        self.assertNotIn(('POST','/maintenance/leave'),self.host.calls)
    def test_restart_or_other_service_change_retains_window_without_rollback(self):
        for fault in ['control-after-pull','other-after-pull']:
            with self.subTest(fault=fault):
                self.host.fail=fault
                with self.assertRaises(p.Halt):self.run_promotion()
                self.assertTrue(self.host.marker.exists());self.assertEqual(0,self.host.recreate_count)
                self.assertNotIn(('POST','/maintenance/leave'),self.host.calls)
                self.receipt.unlink();self.host.marker.unlink();self.host.control_change=False;self.host.other_change=False;self.host.state='open'
    def test_resume_with_existing_receipt_cannot_reenter(self):
        self.run_promotion();calls=list(self.host.calls)
        with self.assertRaises(p.Halt):self.run_promotion()
        self.assertEqual(calls,self.host.calls)
    def recovery_approval(self):
        return {'schema':'direct-web-recovery/v1','approved':True,'approvalId':'fixture-recovery',
                'receiptSha256':p.digest(self.receipt.read_bytes()),'cardSha256':'card-hash',
                'expectedSelectedEnv':p.selected_env(self.env),'envIdentity':p.file_identity(self.env)}
    def test_crash_after_pin_before_receipt_update_restores_only_web_under_separate_approval(self):
        original_patch=p.patch_web_pin
        def interrupted(*args):
            original_patch(*args)
            raise KeyboardInterrupt('fixture crash')
        with patch.object(p,'patch_web_pin',side_effect=interrupted),self.assertRaises(KeyboardInterrupt):self.run_promotion()
        self.assertEqual('PIN_PENDING',json.loads(self.receipt.read_text())['stage'])
        self.assertEqual(self.promotion['newPin'],p.selected_env(self.env)['WEB_GAME_TAG'])
        self.assertEqual('OLD_VERIFIED_DRAINED',p.recover(self.host,self.receipt,'card-hash',self.recovery_approval()))
        self.assertEqual(self.original,self.env.read_bytes());self.assertTrue(self.host.marker.exists())
        self.assertNotIn(('POST','/maintenance/leave'),self.host.calls)
    def test_recovery_after_control_restart_cannot_mutate_or_reenter(self):
        self.run_promotion();approval=self.recovery_approval();self.host.control_change=True
        calls=list(self.host.calls)
        with self.assertRaises(p.Halt):p.recover(self.host,self.receipt,'card-hash',approval)
        self.assertEqual(calls,self.host.calls);self.assertTrue(self.host.marker.exists())
    def test_finish_rejects_persistent_pin_drift(self):
        self.run_promotion();self.env.write_bytes(self.original)
        with self.assertRaises(p.Halt):p.finish(self.host,self.receipt,'card-hash',self.finish_approval())
        self.assertNotIn(('POST','/maintenance/leave'),self.host.calls)
    def finish_approval(self):
        return {'schema':'direct-web-finish/v1','approved':True,'approvalId':'fixture-A02-finish',
                'receiptSha256':p.digest(self.receipt.read_bytes()),'cardSha256':'card-hash',
                'acknowledgeLeaveWithoutServerLeaseCAS':True}
    def test_finish_requires_separate_byte_pinned_approval(self):
        self.run_promotion()
        for approval in [{},dict(self.finish_approval(),receiptSha256='9'*64),dict(self.finish_approval(),acknowledgeLeaveWithoutServerLeaseCAS=False)]:
            with self.assertRaises(p.Halt):p.finish(self.host,self.receipt,'card-hash',approval)
        self.assertTrue(self.host.marker.exists())
        self.assertEqual('VERIFIED_OPEN',p.finish(self.host,self.receipt,'card-hash',self.finish_approval()))
        self.assertFalse(self.host.marker.exists())
    def test_finish_after_restart_or_marker_replacement_never_leaves(self):
        self.run_promotion();approval=self.finish_approval();self.host.control_change=True
        with self.assertRaises(p.Halt):p.finish(self.host,self.receipt,'card-hash',approval)
        self.host.control_change=False;self.host.marker.unlink();self.host.marker.write_text('other window')
        with self.assertRaises(p.Halt):p.finish(self.host,self.receipt,'card-hash',approval)
        self.assertNotIn(('POST','/maintenance/leave'),self.host.calls)

if __name__=='__main__':unittest.main()
