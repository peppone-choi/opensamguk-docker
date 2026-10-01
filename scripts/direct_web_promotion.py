#!/usr/bin/env python3
"""승인 카드에 고정한 웹 한 서비스만 승격한다. 기본은 Docker 호출 없는 계획이다.

기존 maintenance-v1에는 서버 측 lease CAS가 없다. 성공/롤백 뒤에도 창을
유지하며, 별도 finish 승인의 지문 검사 없이는 leave를 호출하지 않는다.
"""
from __future__ import annotations
import argparse
from collections import Counter
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time

REPO = 'ghcr.io/peppone-choi/opensamguk'
DIGEST = r'sha256:[0-9a-f]{64}'
SHA = r'[0-9a-f]{64}'
SOURCE = r'[0-9a-f]{40}'
OPS = ['maintenance-enter-if-idle', 'pull-approved-web', 'cas-web-pin',
       'recreate-web-only', 'verify-web', 'rollback-local-old-web-if-owned']
FMT = ('{"id":{{json .Id}},"imageId":{{json .Image}},"configuredImage":{{json .Config.Image}},'
       '"startedAt":{{json .State.StartedAt}},"running":{{json .State.Running}}}')
IMAGE_FMT = ('{"id":{{json .Id}},"repoDigests":{{json .RepoDigests}},'
             '"os":{{json .Os}},"architecture":{{json .Architecture}}}')
KEYS = ('SERVER_ID', 'OPENSAMGUK_WORLD_ID', 'SERVER_GENERATION', 'IMAGE_TAG', 'WEB_GAME_TAG')

class Halt(RuntimeError):
    pass

def require(ok, reason):
    if not ok:
        raise Halt(reason)

def digest(data):
    return hashlib.sha256(data).hexdigest()

def read_json(path):
    with Path(path).open('rb') as stream:
        raw = stream.read(1024 * 1024 + 1)
    require(len(raw) <= 1024 * 1024, '입력 크기 제한')
    return raw, json.loads(raw)

def plan(card, candidate_raw, probe_raw):
    candidate = json.loads(candidate_raw)
    probe = json.loads(probe_raw)
    require(card.get('schema') == 'direct-web-promotion/v1', '카드 schema')
    require(card.get('vmInstanceId') == '2561415917368202513' and card.get('gcpProject') == 'opensamguk'
            and card.get('gcpZone') == 'asia-northeast3-c', '승인된 VM identity')
    require(card.get('serverId') == 'pep' and card.get('worldId') == 1 and card.get('generation') == 1,
            '승인된 pep world/generation 범위')
    require(card.get('operations') == OPS, '웹 단독 작업 범위')
    require(card.get('executorSha256') == digest(Path(__file__).read_bytes()), 'executor 바이트 핀')
    require(card.get('candidateSha256') == digest(candidate_raw) and card.get('probeSha256') == digest(probe_raw),
            '후보/실제 검사 artifact 바이트 핀')
    require(candidate.get('status') == 'VERIFIED_CANDIDATE' and candidate.get('deployment_approved') is False,
            '후보 발급과 적용 승인 분리')
    require(candidate.get('repository') == REPO and candidate.get('platform') == 'linux/amd64', '저장소/platform')
    source = candidate.get('source_sha', '')
    manifest = candidate.get('platform_manifest_digest', '')
    config = candidate.get('config_digest', '')
    require(re.fullmatch(SOURCE, source) and re.fullmatch(DIGEST, manifest) and re.fullmatch(DIGEST, config)
            and manifest != config, 'source/platform/config 구별')
    require(probe.get('status') == 'PASS' and probe.get('owned_created_container_removed') is True,
            '실제 후보 검사와 자체 생성 컨테이너 정리 완료')
    pp = probe.get('plan', {})
    require(pp.get('candidate_sha256') == digest(candidate_raw) and pp.get('source_sha') == source
            and pp.get('platform_manifest_digest') == manifest and pp.get('config_digest') == config,
            'native probe 동일 후보')
    require(card.get('sourceSha') == source and card.get('platformDigest') == manifest
            and card.get('configDigest') == config, '대상 승인 source/image')
    require(re.fullmatch(DIGEST, card.get('oldPlatformDigest', '')) and re.fullmatch(DIGEST, card.get('oldConfigDigest', ''))
            and card['oldPlatformDigest'] != card['oldConfigDigest'], 'old manifest/config 별도 증거')
    require(card.get('oldRegistryVerified') is True and card.get('oldLocalImageVerified') is True
            and re.fullmatch(SHA, card.get('oldRegistrySha256', '')),
            '레지스트리와 로컬 old 증거')
    require(re.fullmatch(SOURCE, card.get('oldSourceSha', '')) and source != card['oldSourceSha'], '서로 다른 old/new 태그')
    require(card.get('controlBinarySha256') and re.fullmatch(SHA, card['controlBinarySha256']), 'control binary 핀')
    require(re.fullmatch(SHA, card.get('composeSha256', '')), 'Compose 소스 핀')
    return {'sourceSha': source, 'newPin': source + '@' + manifest,
            'newReference': REPO + ':web-game-' + source + '@' + manifest,
            'oldReference': REPO + ':web-game-' + card['oldSourceSha'],
            'oldRepoDigest': REPO + '@' + card['oldPlatformDigest'], 'platform': 'linux/amd64',
            'automaticLeave': False, 'APIEngineDBOtherMutations': 0}

def file_identity(path):
    require(not path.is_symlink(), 'symlink 거절')
    stat = path.stat()
    return [stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns]

def selected_env(path):
    require(not path.is_symlink(), 'env symlink 거절')
    values = {}
    # 선택 키 외의 값은 해석하거나 결과에 넣지 않는다.
    with path.open('rb') as stream:
        for line in stream:
            key, separator, value = line.rstrip(b'\r\n').partition(b'=')
            if separator and key.decode('ascii', errors='ignore') in KEYS:
                name = key.decode('ascii')
                require(name not in values, '대상 키 중복')
                values[name] = value.decode('ascii')
    require(set(values) == set(KEYS), '명시된 대상 키 필요')
    return values

def atomic_private_json(path, value):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(not path.is_symlink() and not path.parent.is_symlink(), 'receipt symlink 거절')
    fd, temp = tempfile.mkstemp(prefix='.receipt-', dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream); stream.flush(); os.fsync(stream.fileno())
        os.replace(temp, path)
        sync_dir(path.parent)
    finally:
        if os.path.exists(temp): os.unlink(temp)

def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)

def patch_web_pin(path, expected, new_pin, expected_identity):
    require(file_identity(path) == expected_identity and selected_env(path) == expected, 'env CAS 불일치')
    original = path.stat()
    fd, temp = tempfile.mkstemp(prefix='.web-pin-', dir=path.parent)
    try:
        os.fchmod(fd, original.st_mode & 0o777)
        os.fchown(fd, original.st_uid, original.st_gid)
        hits = 0
        # 비대상 행은 해석/노출 없이 그대로 복사한다. 전체 환경을 메모리에 로드하지 않는다.
        with path.open('rb') as source, os.fdopen(fd, 'wb') as target:
            for line in source:
                if line.startswith(b'WEB_GAME_TAG='):
                    hits += 1
                    ending = b'\r\n' if line.endswith(b'\r\n') else b'\n' if line.endswith(b'\n') else b''
                    target.write(b'WEB_GAME_TAG=' + new_pin.encode('ascii') + ending)
                else: target.write(line)
            target.flush(); os.fsync(target.fileno())
        require(hits == 1 and file_identity(path) == expected_identity and selected_env(path) == expected, 'env CAS 재검사')
        os.replace(temp, path); sync_dir(path.parent)
    finally:
        if os.path.exists(temp): os.unlink(temp)

class Host:
    def __init__(self, root, card, promotion):
        self.root, self.card, self.promotion = root, card, promotion
        self.env = root / 'servers/spep.env'
        self.marker = root / 'servers/.deployer-maintenance'
        self.lifecycle = root / 'servers/.deployer-lifecycle-journal'
        self.deadline = time.monotonic() + 1200
        self.command_env = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/root',
                            'DOCKER_HOST': 'unix:///var/run/docker.sock', 'LANG': 'C.UTF-8'}

    def run(self, args, timeout=30):
        remaining = self.deadline - time.monotonic()
        require(remaining > 0, '실행 전체 deadline')
        try:
            p = subprocess.run(args, env=self.command_env, cwd=self.root, input=b'', capture_output=True,
                               timeout=min(timeout, remaining))
        except (subprocess.TimeoutExpired, OSError):
            raise Halt('명령 결과 UNKNOWN: 창 유지') from None
        require(p.returncode == 0, '명령 실패: 원문 출력 생략')
        return p.stdout.decode()

    def docker(self, *args, timeout=30):
        return self.run(['/usr/bin/docker', *args], timeout)

    def verify_instance(self):
        fields={'instance/id':'vmInstanceId','project/project-id':'gcpProject','instance/zone':'gcpZone'}
        for path,key in fields.items():
            value=self.run(['/usr/bin/curl','--fail','--silent','--noproxy','*','--max-time','3',
                            '-H','Metadata-Flavor: Google','http://169.254.169.254/computeMetadata/v1/'+path],timeout=5).strip()
            if key=='gcpZone':value=value.rsplit('/',1)[-1]
            require(value==self.card[key], 'VM metadata identity 불일치')

    def maintenance(self, method='GET', path='/maintenance'):
        raw = self.docker('exec', 'opensamguk-deployer', '/usr/local/bin/deployer', '--authenticated-http', method, path, '10')
        obj = json.loads(raw)
        require(obj.get('capability') == 'maintenance-v1' and obj.get('state') in ('open', 'draining', 'drained'), 'maintenance 계약')
        return obj

    def containers(self):
        ids = self.docker('ps', '-aq').splitlines()
        require(ids, '컨테이너 목록 없음')
        result = {}
        for cid in ids:
            record = json.loads(self.docker('inspect', '--format', FMT, cid))
            name = self.docker('inspect', '--format', '{{.Name}}', cid).strip().lstrip('/')
            result[name] = record
        return result

    def image(self, ref):
        return json.loads(self.docker('image', 'inspect', '--format', IMAGE_FMT, ref))

    def compose(self, *args, timeout=30):
        return self.docker('compose', '--project-directory', str(self.root), '-p', 'opensamguk-spep',
                           '--env-file', str(self.env), '-f', str(self.root/'docker-compose.server.yml'), *args, timeout=timeout)

    def control(self):
        record = json.loads(self.docker('inspect', '--format', FMT, 'opensamguk-deployer'))
        record['binarySha256'] = self.docker('exec', 'opensamguk-deployer', 'sha256sum', '/usr/local/bin/deployer').split()[0]
        return record

    def owned(self, receipt):
        require(self.control() == receipt['control'], 'control 재시작/변경: 창 유지')
        require(not self.lifecycle.exists() and file_identity(self.marker) == receipt['marker'], 'marker/journal 소유 확인 실패')
        require(self.maintenance()['state'] == 'drained', 'drained 창 확인 실패')
        baseline = {name: record for name, record in receipt['baseline'].items() if name != 'spep-web-game'}
        current = {name: record for name, record in self.containers().items() if name != 'spep-web-game'}
        require(current == baseline, 'web 외 컨테이너 변화: 창 유지')

    def verify_web(self, reference, expected_image_id=None):
        record = json.loads(self.docker('inspect', '--format', FMT, 'spep-web-game'))
        image = self.image(reference)
        repo_digest = self.promotion['oldRepoDigest'] if reference == self.promotion['oldReference'] else REPO+'@'+self.card['platformDigest']
        require(repo_digest in image['repoDigests'] and image['os'] == 'linux' and image['architecture'] == 'amd64', 'manifest/platform 검증')
        require(record['configuredImage'] == reference and record['running'] and record['imageId'] == image['id'], '웹 런타임 exact reference')
        if expected_image_id: require(record['imageId'] == expected_image_id, 'old local image 불일치')
        health_deadline = min(self.deadline, time.monotonic()+60)
        while True:
            try:
                self.docker('exec', 'spep-web-game', 'node', '-e',
                    "const q=require('http').get('http://127.0.0.1:3001/api/health',r=>{r.resume();process.exit(r.statusCode===200?0:1)});q.setTimeout(3000,()=>{q.destroy();process.exit(1)});q.on('error',()=>process.exit(1))", timeout=10)
                break
            except Halt:
                require(time.monotonic()+3 < health_deadline, '웹 health deadline: 창 유지')
                time.sleep(3)
        require(json.loads(self.docker('inspect','--format',FMT,'spep-web-game'))==record, 'health 대기 중 웹 변경')
        return record

def perform(host, receipt_path, card_hash, promotion):
    host.verify_instance()
    require(not receipt_path.exists(), '기존 receipt: 재진입 금지, 복구 카드 필요')
    require(not host.marker.exists() and not host.lifecycle.exists(), '기존 maintenance/journal')
    require(host.maintenance()['state'] == 'open', '기존 창 소유 금지')
    control = host.control()
    require(control['id'] == host.card['controlContainerId'] and control['startedAt'] == host.card['controlStartedAt']
            and control['binarySha256'] == host.card['controlBinarySha256'], 'control 대상 핀')
    require(digest((host.root/'docker-compose.server.yml').read_bytes()) == host.card['composeSha256'], 'Compose 소스 변경')
    env = selected_env(host.env)
    require(env == host.card['expectedSelectedEnv'], '선택 config identity/pin 변경')
    require(env['SERVER_ID']=='pep' and env['OPENSAMGUK_WORLD_ID']=='1' and env['SERVER_GENERATION']=='1', '세계 identity')
    baseline = host.containers()
    require(baseline.get('spep-web-game') == host.card['oldWebContainer'], 'old web container 변경')
    old = host.image(promotion['oldReference'])
    require(promotion['oldRepoDigest'] in old['repoDigests'] and old['id'] == baseline['spep-web-game']['imageId']
            and old['os']=='linux' and old['architecture']=='amd64', 'old rollback local image')
    configured = host.compose('config', '--images').splitlines()
    require(Counter(configured) == Counter(host.card['expectedComposeImages']), 'Compose 이미지 구성 변경')
    receipt = {'schema':'direct-web-receipt/v1', 'cardSha256':card_hash, 'stage':'ENTER_PENDING',
               'control':control, 'baseline':baseline, 'selectedEnv':env, 'envIdentity':file_identity(host.env),
               'oldLocalImageId':old['id'], 'promotion':promotion}
    atomic_private_json(receipt_path, receipt)
    admission = host.maintenance('POST', '/maintenance/enter-if-idle')
    require(admission['state']=='drained' and re.fullmatch(r'[0-9a-f]{32}', admission.get('lease','')), '입장 결과 UNKNOWN: 창 유지')
    receipt.update(stage='OWNED_DRAINED', lease=admission['lease'], marker=file_identity(host.marker))
    atomic_private_json(receipt_path, receipt)
    host.owned(receipt)
    try:
        host.docker('pull', '--platform', promotion['platform'], promotion['newReference'], timeout=300)
        host.owned(receipt)
        new = host.image(promotion['newReference'])
        require(REPO+'@'+host.card['platformDigest'] in new['repoDigests'], 'candidate RepoDigest')
        # image id는 런타임 대조에만 사용하며 registry/config digest로 치환하지 않는다.
        receipt['stage']='PIN_PENDING'; atomic_private_json(receipt_path, receipt)
        patch_web_pin(host.env, env, promotion['newPin'], receipt['envIdentity'])
        receipt['currentSelectedEnv'] = dict(env, WEB_GAME_TAG=promotion['newPin'])
        receipt['currentEnvIdentity'] = file_identity(host.env)
        receipt['stage']='WEB_RECREATE_PENDING'; atomic_private_json(receipt_path, receipt)
        changed = host.compose('config', '--images').splitlines()
        expected = [promotion['newReference'] if image == promotion['oldReference'] else image for image in configured]
        require(expected.count(promotion['newReference'])==1 and Counter(changed) == Counter(expected), 'web 외 Compose 이미지 변화')
        host.owned(receipt)
        host.compose('up', '-d', '--no-deps', '--pull', 'never', '--force-recreate', 'web-game', timeout=180)
        host.owned(receipt)
        receipt['verifiedWeb']=host.verify_web(promotion['newReference'])
        host.owned(receipt)
        receipt['stage']='CANDIDATE_VERIFIED_DRAINED'; atomic_private_json(receipt_path, receipt)
    except Exception:
        # 소유·현재 env CAS를 확인할 수 있는 같은 프로세스에서만 old local image를 복원한다.
        host.owned(receipt)
        if 'currentSelectedEnv' in receipt:
            patch_web_pin(host.env, receipt['currentSelectedEnv'], env['WEB_GAME_TAG'], receipt['currentEnvIdentity'])
            receipt['stage']='ROLLBACK_PENDING'; atomic_private_json(receipt_path, receipt)
            host.compose('up', '-d', '--no-deps', '--pull', 'never', '--force-recreate', 'web-game', timeout=180)
            host.owned(receipt)
            receipt['verifiedWeb']=host.verify_web(promotion['oldReference'], receipt['oldLocalImageId'])
            host.owned(receipt)
            receipt['stage']='OLD_VERIFIED_DRAINED'; atomic_private_json(receipt_path, receipt)
        else:
            require(selected_env(host.env)==env and file_identity(host.env)==receipt['envIdentity'], 'pin 결과 UNKNOWN: 창 유지')
            receipt['verifiedWeb']=host.verify_web(promotion['oldReference'], receipt['oldLocalImageId'])
            host.owned(receipt)
            receipt['stage']='OLD_VERIFIED_DRAINED'; atomic_private_json(receipt_path, receipt)
        raise Halt('승격 실패: 창 유지, private receipt 단계로 복구 판단') from None
    return receipt['stage']

def recover(host, receipt_path, card_hash, approval):
    host.verify_instance()
    raw, receipt = read_json(receipt_path)
    require(approval.get('schema')=='direct-web-recovery/v1' and approval.get('approved') is True
            and approval.get('approvalId') and approval.get('receiptSha256')==digest(raw)
            and approval.get('cardSha256')==card_hash, '동일 창의 웹 롤백 대상 승인 필요')
    require(receipt.get('cardSha256')==card_hash and re.fullmatch(r'[0-9a-f]{32}',receipt.get('lease',''))
            and receipt.get('stage') in ('OWNED_DRAINED','PIN_PENDING','WEB_RECREATE_PENDING','ROLLBACK_PENDING',
                                        'CANDIDATE_VERIFIED_DRAINED','OLD_VERIFIED_DRAINED'), '자기 admission이 확인된 미완료 단계만 복구')
    host.owned(receipt)
    require(digest((host.root/'docker-compose.server.yml').read_bytes())==host.card['composeSha256'], '복구 Compose 소스 변경')
    current = selected_env(host.env)
    expected = dict(receipt['selectedEnv'], WEB_GAME_TAG=current['WEB_GAME_TAG'])
    require(current==expected and current['WEB_GAME_TAG'] in (receipt['selectedEnv']['WEB_GAME_TAG'],receipt['promotion']['newPin'])
            and current==approval.get('expectedSelectedEnv') and file_identity(host.env)==approval.get('envIdentity'), '복구 env CAS')
    old = host.image(receipt['promotion']['oldReference'])
    require(old['id']==receipt['oldLocalImageId'] and receipt['promotion']['oldRepoDigest'] in old['repoDigests'], '복구 old local image')
    receipt['stage']='ROLLBACK_PENDING'; atomic_private_json(receipt_path,receipt)
    if current['WEB_GAME_TAG']!=receipt['selectedEnv']['WEB_GAME_TAG']:
        patch_web_pin(host.env,current,receipt['selectedEnv']['WEB_GAME_TAG'],approval['envIdentity'])
    host.owned(receipt)
    host.compose('up','-d','--no-deps','--pull','never','--force-recreate','web-game',timeout=180)
    host.owned(receipt)
    receipt['verifiedWeb']=host.verify_web(receipt['promotion']['oldReference'],receipt['oldLocalImageId'])
    host.owned(receipt)
    receipt['stage']='OLD_VERIFIED_DRAINED'; atomic_private_json(receipt_path,receipt)
    return receipt['stage']

def finish(host, receipt_path, card_hash, approval):
    host.verify_instance()
    raw, receipt = read_json(receipt_path)
    require(approval.get('schema')=='direct-web-finish/v1' and approval.get('approved') is True
            and approval.get('approvalId') and approval.get('receiptSha256')==digest(raw)
            and approval.get('cardSha256')==card_hash and approval.get('acknowledgeLeaveWithoutServerLeaseCAS') is True,
            '별도 대상 finish 승인: 기존 서버의 non-CAS 위험 확인 필요')
    require(receipt.get('cardSha256')==card_hash and receipt.get('stage') in ('CANDIDATE_VERIFIED_DRAINED','OLD_VERIFIED_DRAINED'),
            '검증 완료 자기 receipt만 해제')
    require(re.fullmatch(r'[0-9a-f]{32}',receipt.get('lease','')), '자기 최초 admission 증거')
    host.owned(receipt)
    expected_env = receipt.get('currentSelectedEnv') if receipt['stage']=='CANDIDATE_VERIFIED_DRAINED' else receipt['selectedEnv']
    require(selected_env(host.env)==expected_env and digest((host.root/'docker-compose.server.yml').read_bytes())==host.card['composeSha256'], 'finish config CAS')
    reference = receipt['promotion']['newReference'] if receipt['stage']=='CANDIDATE_VERIFIED_DRAINED' else receipt['promotion']['oldReference']
    require(host.verify_web(reference) == receipt['verifiedWeb'], '검증 후 웹 변경')
    host.owned(receipt)
    receipt['stage']='LEAVE_PENDING'; atomic_private_json(receipt_path, receipt)
    response=host.maintenance('POST','/maintenance/leave')
    require(response['state']=='open' and not host.marker.exists() and host.control()==receipt['control'], 'leave 결과 UNKNOWN')
    receipt['stage']='VERIFIED_OPEN'; atomic_private_json(receipt_path,receipt)
    return receipt['stage']

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('card'); parser.add_argument('candidate'); parser.add_argument('probe')
    parser.add_argument('--old-registry',required=True)
    parser.add_argument('--execute',action='store_true'); parser.add_argument('--finish-approval'); parser.add_argument('--recovery-approval')
    parser.add_argument('--root'); parser.add_argument('--receipt')
    args=parser.parse_args()
    try:
        card_raw,card=read_json(args.card); candidate_raw,_=read_json(args.candidate); probe_raw,_=read_json(args.probe)
        promotion=plan(card,candidate_raw,probe_raw)
        old_raw,old_registry=read_json(args.old_registry)
        require(digest(old_raw)==card['oldRegistrySha256'], 'old registry 증거 바이트 핀')
        old_refs=old_registry.get('references',[])
        matches=[r for r in old_refs if r.get('reference') in (card['oldPlatformDigest'],'web-game-'+card['oldSourceSha'])]
        require(len(matches)==2 and all(r.get('status')==200 and r.get('registryDigest')==card['oldPlatformDigest']
                and r.get('rawManifestDigest')==card['oldPlatformDigest'] and r.get('configDigest')==card['oldConfigDigest']
                and r.get('os')=='linux' and r.get('architecture')=='amd64' and r.get('metadataAndBlobAccess') is True for r in matches),
                'old tag/manifest/config/blobs 실측 일치')
        if not args.execute and not args.finish_approval and not args.recovery_approval:
            print(json.dumps({'status':'PLAN_ONLY_NOT_EXECUTED','dockerCalls':0,'plan':promotion},indent=2)); return 0
        require(card.get('maintenanceApproval')=={'approved':True,'approvalId':card.get('approvalId'),'scope':OPS}
                and card.get('approvalId'), 'A02 대상 승인 필요')
        require(args.root and args.receipt and os.geteuid()==0, '명시 host root/receipt 및 root 권한 필요')
        root=Path(args.root).resolve(); receipt=Path(args.receipt).absolute()
        require(str(root)=='/home/peppone_choi/opensamguk-docker', '승인된 VM stack 경로')
        require(str(receipt.parent)==str(root/'servers/.direct-web-promotion'), 'private receipt 경로')
        require(sum([bool(args.execute),bool(args.finish_approval),bool(args.recovery_approval)])==1, '실행/finish/복구 동시 금지')
        with open('/tmp/opensamguk-production.lock','a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            host=Host(root,card,promotion)
            if args.finish_approval: result=finish(host,receipt,digest(card_raw),read_json(args.finish_approval)[1])
            elif args.recovery_approval: result=recover(host,receipt,digest(card_raw),read_json(args.recovery_approval)[1])
            else: result=perform(host,receipt,digest(card_raw),promotion)
        print(result); return 0
    except (Halt,ValueError,OSError,KeyError,TypeError):
        # 원격 명령/환경/lease가 포함된 원문 예외를 출력하지 않는다.
        print('HALTED_CLOSED_OR_NOT_ENTERED: 승인 카드와 private receipt를 확인하세요.'); return 1

if __name__=='__main__': raise SystemExit(main())
