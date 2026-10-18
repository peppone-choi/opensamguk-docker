"""Contract tests using a stateful fake Docker CLI. Never contacts a Docker daemon."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import recovery as r
from storage import Refused, need, newdir, put, write, read, seal, archive_root, verify_bundle, digest

SESSION = '01a14ccf-2778-7a60-92f3-213692884c2a'
RID = '12345678-1234-1234-1234-123456789abc'


def image_id(name):
    return 'sha256:' + hashlib.sha256(name.encode()).hexdigest()


def tar_bytes(name='payload', content=b'opaque durable state', kind=None):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w') as archive:
        item = tarfile.TarInfo(name)
        item.mode = 0o600
        if kind:
            item.type = kind
            item.linkname = '/outside'
        else:
            item.size = len(content)
        archive.addfile(item, None if kind else io.BytesIO(content))
    return stream.getvalue()


class FakeCLI:
    def __init__(self):
        self.calls = []
        self.containers, self.volumes, self.networks, self.image_data, self.tags = {}, {}, {}, {}, {}
        self.clean = True
        self.fail_export = False
        self.fail_start = False
        self.corrupt_restore = False
        self.probe_ok = True
        self.nonempty = False
        self.cp = {'generalId': 2, 'userId': '7', 'nationId': 1, 'requestId': RID, 'appliedCount': 1,
                   'terminalVersion': 40, 'logCount': 1}

    def install(self, record, model, running=True):
        project = record['project']
        net = project + '_local'
        labels = {**r.fresh.labels(record), r.fresh.PROJECT_LABEL: project}
        self.networks[net] = {'Id': image_id(net)[7:], 'Name': net, 'Labels': labels,
                              'Driver': 'bridge', 'Containers': {}}
        for key, spec in model['volumes'].items():
            if spec['name'] not in self.volumes:
                self.volumes[spec['name']] = {'Name': spec['name'], 'Labels': labels,
                    'Driver': 'local', 'Options': None, 'content': tar_bytes(key, ('DB/AOF/icons:'+key).encode())}
        pins = r.images(record, model)
        for svc, spec in model['services'].items():
            cid = hashlib.sha256((project + svc).encode()).hexdigest()
            mounts = []
            for mount in spec.get('volumes', []):
                a = {'Type': mount['type'], 'Destination': mount['target'], 'RW': not mount.get('read_only', False)}
                a['Name' if mount['type'] == 'volume' else 'Source'] = (
                    model['volumes'][mount['source']]['name'] if mount['type'] == 'volume' else mount['source'])
                mounts.append(a)
            row = {'Id': cid, 'Name': project + '-' + svc + '-1', 'Image': pins[svc],
                'Config': {'Labels': {**labels, 'com.docker.compose.service': svc}},
                'State': {'Running': running, 'Health': {'Status': 'healthy'}},
                'HostConfig': {'PortBindings': {'443/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '443'}]} if svc == 'nginx' else {}},
                'Mounts': mounts, 'NetworkSettings': {'Networks': {net: {}}}, 'ExitCode': 0}
            self.containers[cid] = row
            self.networks[net]['Containers'][cid] = {}

    def local(self): pass

    def port_free(self):
        need(not any(c['State']['Running'] and c['Config']['Labels'].get('com.docker.compose.service') == 'nginx'
                     for c in self.containers.values()), 'TLS_PORT_BUSY')

    def user_probe(self, custody, identity, gid, rid):
        return {'login': self.probe_ok, 'resolved': self.probe_ok, 'generalId': gid, 'requestId': rid}

    def log_summary(self,cid,rid):
        return {'lines':2,'errorLines':0,'requestLines':1,'tailLimit':500}

    def run(self, args, **kwargs):
        self.calls.append(list(args))
        if args[0] == 'git': return b'canonical nginx'
        need(args[0] == 'docker', 'UNEXPECTED_FAKE_CLI')
        a = args[1:]
        if a[:2] == ['image', 'inspect']:
            ident = self.tags.get(a[-1], a[-1])
            if a[a.index('--format')+1] == '{{json .Config.StopSignal}}': return b'"SIGTERM"'
            need(ident in self.image_data, 'IMAGE_MISSING')
            return json.dumps(self.image_data[ident]).encode()
        if a[:2] == ['image', 'ls']:
            return self.tags.get(a[-1].removeprefix('reference='),'').encode()
        if a[:2] == ['volume', 'create']:
            name = a[-1]
            need(name not in self.volumes, 'VOLUME_EXISTS')
            labels = dict(a[i+1].split('=', 1) for i, v in enumerate(a) if v == '--label')
            self.volumes[name] = {'Name': name, 'Labels': labels, 'Driver': 'local', 'Options': None, 'content': None}
            return name.encode()
        if a[0] in ('ps', 'network', 'volume') and '--filter' in a:
            kind = 'container' if a[0] == 'ps' else a[0]
            rows = {'container': self.containers, 'volume': self.volumes, 'network': self.networks}[kind]
            filt = a[a.index('--filter')+1]
            ids = []
            for key, row in rows.items():
                labels = row.get('Config', {}).get('Labels', row.get('Labels', {}))
                match = (labels.get(filt[6:].split('=',1)[0]) == filt[6:].split('=',1)[1] if filt.startswith('label=')
                         else filt[5:] in row.get('Name', '') if filt.startswith('name=') else False)
                if match: ids.append(key if kind == 'container' else row.get('Name', key))
            # Consumer checks are separately projected and never inspect env.
            if filt.startswith('volume='):
                return '\n'.join(c['Id'] for c in self.containers.values()
                    if any(m.get('Name') == filt[7:] for m in c['Mounts'])).encode()
            return '\n'.join(ids).encode()
        if a[0] == 'inspect':
            row = self.containers[a[-1]]
            if a[a.index('--format')+1] == r.STATE:
                return json.dumps({'Running': row['State']['Running'], 'ExitCode': row['ExitCode'], 'OOMKilled': False}).encode()
            return json.dumps(row).encode()
        if a[:2] == ['volume', 'inspect']:
            row = self.volumes[a[-1]]
            return json.dumps({k:v for k,v in row.items() if k != 'content'}).encode()
        if a[:2] == ['network', 'inspect']:
            row = next(n for n in self.networks.values() if a[-1] in (n['Id'], n['Name']))
            return json.dumps(row).encode()
        if a[0] == 'kill':
            row = self.containers[a[-1]]
            row['State']['Running'] = False
            row['ExitCode'] = 0 if self.clean else 137
            return b''
        if a[0] == 'start':
            need(not self.fail_start, 'START_FAILED')
            self.containers[a[-1]]['State']['Running'] = True
            return b''
        if a[0] == 'run': return b'existing file' if self.nonempty else b''
        if a[0] == 'compose':
            path = Path(a[a.index('-f')+1]); model = read(path)
            if 'exec' in a:
                query = a[-1]
                if 'json_build_object' in query:
                    # All application writers must already be stopped at backup cut.
                    return json.dumps(self.cp).encode()
                if 'string_agg' in query: return b'160'
                return b'1'
            t = read(path.parent/'target.json')
            self.install(t['record'], model)
            return b''
        raise AssertionError('Unexpected fake CLI shape: ' + ' '.join(a[:3]))

    def stream(self, args, path, incoming=False):
        self.calls.append(list(args))
        if args[1:3] == ['image', 'save']:
            need(not self.fail_export, 'ENOSPC')
            put(path, tar_bytes('manifest.json', b'[]'))
        elif args[1:3] == ['image', 'load']:
            return
        else:
            mount = args[args.index('--mount')+1]
            name = mount.split('source=')[1].split(',')[0]
            if incoming:
                self.volumes[name]['content'] = b'corrupt' if self.corrupt_restore else Path(path).read_bytes()
            else:
                need(not self.fail_export, 'ENOSPC')
                put(path, self.volumes[name]['content'])


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.source = newdir(self.root/'source')
        self.io = FakeCLI()
        self.engine = r.Recovery(self.io)
        self.env = patch.dict(os.environ, OPENSAMGUK_TASK_OWNER_SESSION=SESSION)
        self.env.start(); self.addCleanup(self.env.stop)
        self.record = {'schema':1, 'nonce':'a'*16, 'project':'osglha'+'a'*16, 'serverId':'lha'+'a'*16,
            'session':SESSION, 'custody':str(self.source), 'origin':'https://localhost', 'worldId':160,
            'generation':0, 'appSha':'a'*40, 'dockerSha':'b91efebfa63e7dcf16a1fa44e17aa0f73d3e710a',
            'status':'SMOKE_PASSED', 'images':{}, 'supportImages':{tag:image_id(tag) for tag in r.fresh.SUPPORT_IMAGES}}
        newdir(self.source/'source'); newdir(self.source/'source/docker')
        for svc in r.fresh.SERVICES: put(self.source/'source/docker'/f'{svc}.Dockerfile', b'FROM fixture')
        newdir(self.source/'certs'); newdir(self.source/'battle-ws')
        put(self.source/'certs/opensamguk.crt',b'FAKE CERT'); put(self.source/'certs/opensamguk.key', b'FAKE PRIVATE SENTINEL')
        put(self.source/'nginx.conf', b'canonical nginx')
        template = (r.ROOT/'docker-compose.localhost-acceptance.yml').read_text()
        fixtures = {k:'FAKE-'+k for k in re_find(template)}
        write(self.source/'runtime.json', fixtures)
        write(self.source/'fixture.json', {'user':{'username':'fake','password':'fake'}})
        self.record.update(sourceTreeSha256=r.fresh.tree_hash(self.source/'source'),
            certsSha256=r.fresh.tree_hash(self.source/'certs'), nginxSha256=digest(self.source/'nginx.conf'),
            templateSha256=hashlib.sha256(template.encode()).hexdigest())
        for svc in r.fresh.SERVICES:
            iid=image_id('A-'+svc); tag=r.fresh.image_ref(self.record,svc)
            self.io.tags[tag]=iid
            self.io.image_data[iid]={'Id':iid,'RepoTags':[tag], 'Config':{'Labels':r.fresh.image_metadata(self.record,svc,{})}}
            self.record['images'][svc]={'imageId':iid,'dockerfileSha256':hashlib.sha256(b'FROM fixture').hexdigest(),
                                       'buildArgs':r.fresh.build_args(self.record,svc)}
        for tag,iid in self.record['supportImages'].items():
            self.io.tags[tag]=iid;self.io.image_data[iid]={'Id':iid,'RepoTags':[tag],'Config':{'Labels':{}}}
        self.model=r.fresh.model_for(self.record,fixtures)
        write(self.source/'compose.json',self.model)
        self.record['configSha256']=digest(self.source/'compose.json')
        write(self.source/'contract.json',self.record)
        self.io.install(self.record,self.model)
        self.bundle=self.root/'backup'

    def backup(self):
        return self.engine.backup(self.source,self.bundle,2,RID)

    def version(self):
        pins={s:image_id('B-'+s) for s in r.fresh.SERVICES}
        for svc,iid in pins.items():
            labels=r.fresh.image_metadata(self.record,svc,{})
            labels['org.opencontainers.image.revision']='b'*40
            labels['org.opensamguk.local.source-tree']='f'*64
            self.io.image_data[iid]={'Id':iid,'RepoTags':[], 'Config':{'Labels':labels}}
        out=self.root/'B.json'
        with patch.object(r.fresh,'source_archive',return_value=b'fake public archive'), patch.object(r.fresh,'archive_tree_hash',return_value='f'*64), patch.object(r.fresh,'git',return_value=b'FROM fixture'):
            self.engine.version(self.bundle,'b'*40,pins,out,self.root)
        return out

    def test_full_A_backup_B_observation_A_rollback_and_original_return(self):
        original=copy.deepcopy(self.io.volumes)
        self.backup();version=self.version()
        b=self.root/'B';a=self.root/'A-return'
        self.engine.restore(self.bundle,b,version)
        self.engine.observe(b);self.engine.stop_target(b)
        self.engine.rollback(self.bundle,b,a)
        self.engine.observe(a);self.engine.stop_target(a)
        result=self.engine.resume(self.bundle)
        self.assertTrue(result['fullFlowObserved'])
        self.assertEqual(len(read(a/'target.json')['observation']['logs']),11)
        for name,old in original.items():self.assertEqual(self.io.volumes[name]['content'],old['content'])
        self.assertEqual(read(a/'runtime/runtime.json'),read(self.source/'runtime.json'))
        self.assertNotEqual(read(a/'target.json')['record']['nonce'],self.record['nonce'])
        self.assertEqual(read(a/'target.json')['record']['serverId'],self.record['serverId'])
        self.assertFalse(any('rm' in c and c[1:2] != ['run'] for c in self.io.calls))

    def test_backup_covers_full_AOF_two_DB_icons_private_files(self):
        self.backup();m=verify_bundle(self.bundle)
        self.assertEqual(set(m['volumes']),set(r.VOLUMES))
        self.assertEqual((self.bundle/'custody/certs/opensamguk.key').stat().st_mode & 0o777,0o600)
        kills=[c[-1] for c in self.io.calls if c[1:2]==['kill']]
        rows=self.io.containers
        services=[rows[c]['Config']['Labels']['com.docker.compose.service'] for c in kills]
        self.assertEqual(services,list(r.STOP))
        sql_index=next(i for i,c in enumerate(self.io.calls) if 'psql' in c)
        engine_kill=next(i for i,c in enumerate(self.io.calls) if c[1:2]==['kill'] and rows[c[-1]]['Config']['Labels']['com.docker.compose.service']=='game-engine')
        data_kill=next(i for i,c in enumerate(self.io.calls) if c[1:2]==['kill'] and rows[c[-1]]['Config']['Labels']['com.docker.compose.service']=='gateway-postgres')
        self.assertLess(engine_kill,sql_index);self.assertLess(sql_index,data_kill)

    def test_ENOSPC_preserves_partial_bundle_and_resumes_only_original(self):
        self.io.fail_export=True
        with self.assertRaises(Refused):self.backup()
        self.assertEqual(read(self.bundle/'journal.json')['phase'],'ORIGINAL_RESUMED')
        self.assertTrue(all(c['State']['Running'] for c in self.io.containers.values()))
        self.assertFalse((self.bundle/'manifest.json').exists())

    def test_dirty_data_exit_never_copies_or_completes(self):
        self.io.clean=False
        with self.assertRaisesRegex(Refused,'UNCLEAN_DATA_STOP'):self.backup()
        self.assertFalse(any(c[1:3]==['image','save'] for c in self.io.calls))

    def test_foreign_volume_consumer_refused_before_stop(self):
        row=copy.deepcopy(next(iter(self.io.containers.values())))
        row['Id']='f'*64;row['Name']='foreign';row['Config']['Labels']={}
        row['Mounts']=[{'Type':'volume','Name':self.model['volumes']['game-pgdata']['name']}]
        self.io.containers[row['Id']]=row
        with self.assertRaisesRegex(Refused,'FOREIGN_VOLUME_CONSUMER'):self.backup()
        self.assertFalse(any(c[1:2]==['kill'] for c in self.io.calls))

    def test_corruption_rejected_before_any_restore_resource(self):
        self.backup();put(self.bundle/'data/game-pgdata.tar',b'bad',replace=True)
        before=len(self.io.volumes)
        with self.assertRaises(Refused):self.engine.restore(self.bundle,self.root/'target')
        self.assertEqual(len(self.io.volumes),before)

    def test_modified_identity_cannot_hide_behind_resealed_bundle(self):
        self.backup();m=read(self.bundle/'manifest.json');m['source']['nonce']='b'*16
        write(self.bundle/'manifest.json',m,replace=True)
        with self.assertRaisesRegex(Refused,'BUNDLE_SOURCE_BINDING'):self.engine.restore(self.bundle,self.root/'target')

    def test_missing_version_and_same_images_are_not_rollback(self):
        self.backup();a=self.root/'a';self.engine.restore(self.bundle,a)
        self.engine.observe(a);self.engine.stop_target(a)
        with self.assertRaisesRegex(Refused,'B_NOT_OBSERVED'):self.engine.rollback(self.bundle,a,self.root/'bad')
        self.assertFalse(self.engine.resume(self.bundle)['fullFlowObserved'])

    def test_unobserved_B_cannot_rollback_and_login_failure_never_accepts(self):
        self.backup();b=self.root/'b';self.engine.restore(self.bundle,b,self.version())
        self.io.probe_ok=False
        with self.assertRaisesRegex(Refused,'USER_PROBE'):self.engine.observe(b)
        self.engine.stop_target(b)
        with self.assertRaisesRegex(Refused,'B_NOT_OBSERVED'):self.engine.rollback(self.bundle,b,self.root/'bad')

    def test_partial_restore_corruption_preserved_then_original_can_return(self):
        self.backup();self.io.corrupt_restore=True;t=self.root/'broken'
        with self.assertRaises(tarfile.TarError):self.engine.restore(self.bundle,t)
        self.engine.stop_target(t)
        self.assertEqual(self.engine.resume(self.bundle)['phase'],'ORIGINAL_RESUMED')
        self.assertTrue(t.exists());self.assertGreater(len(self.io.volumes),5)

    def test_live_target_blocks_original_resume(self):
        self.backup();self.engine.restore(self.bundle,self.root/'t')
        with self.assertRaisesRegex(Refused,'TARGET_STILL_RUNNING'):self.engine.resume(self.bundle)

    def test_two_applied_rows_fail_checkpoint_without_mutating_data(self):
        self.io.cp['appliedCount']=2
        with self.assertRaisesRegex(Refused,'CHECKPOINT_REQUEST'):self.backup()
        self.assertFalse((self.bundle/'manifest.json').exists())

    def test_unsafe_archives_and_special_files_are_refused(self):
        for name,kind in [('../escape',None),('/abs',None),('link',tarfile.SYMTYPE),('hard',tarfile.LNKTYPE),('fifo',tarfile.FIFOTYPE)]:
            p=self.root/('tar-'+str(len(list(self.root.iterdir()))))
            put(p,tar_bytes(name,kind=kind))
            with self.assertRaises(Refused):archive_root(p)

    def test_private_mode_symlink_and_foreign_heavy_lock(self):
        from storage import private
        p=self.root/'public';put(p,b'x');p.chmod(0o644)
        with self.assertRaises(Refused):private(p)
        q=self.root/'link';q.symlink_to(self.source)
        with self.assertRaises(Refused):private(q,True)
        meta=newdir(self.root/'meta');newdir(meta/'.locks');lock=newdir(meta/'.locks/heavy-run')
        put(lock/'owner',b'foreign')
        with patch('recovery.time.sleep',side_effect=Refused('WAITING_FOREIGN_LOCK')) as sleeper:
            with self.assertRaisesRegex(Refused,'WAITING_FOREIGN_LOCK'):
                with r.heavy(meta,SESSION):pass
            sleeper.assert_called_once_with(1)
        self.assertEqual((lock/'owner').read_bytes(),b'foreign')

    def test_handoff_binding_expiry_and_wrong_fixture_rejected_before_cli(self):
        hand=self.root/'handoff.json'
        base={'schema':1,'sourceCustody':str(self.source),'ownerSession':SESSION,'scope':'F_FULL_RECOVERY',
              'windowId':'C0-window','sourceContractSha256':digest(self.source/'contract.json'),'expiresAt':'2000-01-01T00:00:00Z'}
        write(hand,base)
        with self.assertRaisesRegex(Refused,'HANDOFF_EXPIRED'):r.permission(hand,self.source)
        base['expiresAt']='2099-01-01T00:00:00Z';write(hand,base,replace=True)
        self.assertEqual(r.permission(hand,self.source)['windowId'],'C0-window')
        with self.assertRaisesRegex(Refused,'HANDOFF_TARGET'):r.permission(hand,self.root/'another')

    def test_target_environment_cannot_be_resealed_into_a_valid_copy(self):
        self.backup();t=self.root/'target';self.engine.restore(self.bundle,t)
        model=read(t/'compose.json');model['services']['game-api']['environment']['INJECTED']='foreign'
        write(t/'compose.json',model,replace=True)
        state=read(t/'target.json');state['composeSha256']=digest(t/'compose.json')
        write(t/'target.json',state,replace=True)
        with self.assertRaisesRegex(Refused,'TARGET_CONFIG_CHANGED'):self.engine.observe(t)

    def test_nonempty_target_is_preserved_without_overwriting_or_starting(self):
        self.backup();self.io.nonempty=True;t=self.root/'target'
        with self.assertRaisesRegex(Refused,'TARGET_VOLUME_NOT_EMPTY'):self.engine.restore(self.bundle,t)
        self.assertTrue(t.exists())
        self.assertFalse(any(c[1:2]==['compose'] and 'up' in c for c in self.io.calls))
        self.engine.stop_target(t);self.engine.resume(self.bundle)

    def test_original_container_identity_change_refuses_resume(self):
        self.backup();cid=next(iter(self.io.containers));row=self.io.containers.pop(cid)
        row['Id']='e'*64;self.io.containers[row['Id']]=row
        for n in self.io.networks.values():
            n['Containers'].pop(cid,None);n['Containers'][row['Id']]={}
        with self.assertRaisesRegex(Refused,'ORIGINAL_IDS_CHANGED'):self.engine.resume(self.bundle)
        self.assertFalse(any(c[1:2]==['start'] for c in self.io.calls))

    def test_missing_volume_and_missing_B_images_never_become_complete(self):
        self.backup();m=read(self.bundle/'manifest.json');m['volumes'].pop('game-redisdata')
        write(self.bundle/'manifest.json',m,replace=True)
        with self.assertRaisesRegex(Refused,'MISSING_VOLUME'):self.engine.restore(self.bundle,self.root/'target')
        m['volumes']['game-redisdata']=archive_root(self.bundle/'data/game-redisdata.tar')
        write(self.bundle/'manifest.json',m,replace=True)
        with self.assertRaisesRegex(Refused,'SIX_VERSION_IMAGES'):
            self.engine.version(self.bundle,'b'*40,{},self.root/'v',self.root)

    def test_foreign_network_member_refused_before_stop(self):
        next(iter(self.io.networks.values()))['Containers']['foreign']={}
        with self.assertRaisesRegex(Refused,'FOREIGN_NETWORK'):self.backup()
        self.assertFalse(any(c[1:2]==['kill'] for c in self.io.calls))

    def test_backup_binds_checkpoint_to_handoff_source_before_any_cli(self):
        from argparse import Namespace
        self.backup()
        token={'sourceContractSha256':'f'*64}
        args=Namespace(action='restore',bundle=self.bundle,target=self.root/'target',source_custody=self.source,logs=self.root/'logs')
        count=len(self.io.calls)
        with self.assertRaisesRegex(Refused,'HANDOFF_BUNDLE'):r.authorize_inputs(args,token)
        self.assertEqual(len(self.io.calls),count)

    def test_atomic_journal_failure_keeps_last_recoverable_record(self):
        p=self.root/'journal.json';write(p,{'phase':'PREPARED'})
        with patch('storage.os.replace',side_effect=OSError('disk failure')):
            with self.assertRaises(OSError):write(p,{'phase':'STOPPED'},replace=True)
        self.assertEqual(read(p),{'phase':'PREPARED'})

    def test_AOF_manifest_and_incremental_segments_survive_restore(self):
        stream=io.BytesIO()
        with tarfile.open(fileobj=stream,mode='w') as archive:
            for name,data in [('appendonlydir/appendonly.aof.manifest',b'file base.aof seq 1 type b'),
                              ('appendonlydir/base.aof',b'durable pending queue'),('dump.rdb',b'old snapshot')]:
                item=tarfile.TarInfo(name);item.size=len(data);item.mode=0o600
                archive.addfile(item,io.BytesIO(data))
        original=stream.getvalue();name=self.model['volumes']['game-redisdata']['name']
        self.io.volumes[name]['content']=original
        self.backup();target=self.root/'target';self.engine.restore(self.bundle,target)
        model=read(target/'compose.json')
        self.assertEqual(self.io.volumes[model['volumes']['game-redisdata']['name']]['content'],original)

    def test_C_and_E_resources_are_not_stopped_or_copied(self):
        for letter in ('c','e'):
            record=copy.deepcopy(self.record);record.update(nonce=letter*16,project='osglha'+letter*16)
            model=copy.deepcopy(self.model)
            for key,spec in model['volumes'].items():spec['name']=record['project']+'_'+key
            self.io.install(record,model,running=False)
        foreign={cid:copy.deepcopy(c) for cid,c in self.io.containers.items()
                 if c['Config']['Labels'][r.fresh.NONCE_LABEL] != self.record['nonce']}
        self.backup()
        self.assertEqual({cid:self.io.containers[cid] for cid in foreign},foreign)

    def test_image_import_never_replaces_another_stacks_support_tag(self):
        self.backup();self.io.tags['redis:7-alpine']=image_id('foreign-redis')
        with self.assertRaisesRegex(Refused,'IMAGE_IMPORT_TAG_COLLISION'):
            self.engine.restore(self.bundle,self.root/'target')
        self.assertFalse(any(c[1:3]==['image','load'] for c in self.io.calls))


def re_find(text):
    import re
    return re.findall(r'@([A-Z_]+)@',text)


if __name__ == '__main__':
    unittest.main()
