import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('lha_harness', Path(__file__).with_name('harness.py'))
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)


class HarnessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name).resolve()
        self.directory.chmod(0o700)
        self.record = {'nonce': '0123456789abcdef', 'session': '01a14994-f8a1-7282-9f45-f9d3c5390cee',
                       'project': 'osglha0123456789abcdef', 'serverId': 'lha0123456789abcdef',
                       'origin': h.ORIGIN, 'worldId': 160, 'generation': 0, 'custody': str(self.directory),
                       'appSha': 'a'*40, 'dockerSha': 'b'*40, 'sourceTreeSha256': 'c'*64, 'images': {}}
        self.fixture = {k: 'testvalue' for k in ('DB_PASSWORD', 'JWT_PRIVATE_KEY', 'JWT_PUBLIC_KEY',
                        'INTERNAL_TOKEN', 'DEPLOYER_TOKEN', 'ADMIN_USERNAME', 'ADMIN_PASSWORD')}
        (self.directory / 'source/docker').mkdir(parents=True)
        for svc in h.SERVICES:
            (self.directory / 'source/docker' / (svc + '.Dockerfile')).write_text('FROM scratch\n')
        self.model = h.model_for(self.record, self.fixture)

    def rejects(self, change):
        model = copy.deepcopy(self.model)
        change(model)
        with self.assertRaises(h.Refused):
            h.validate_model(model, self.record)

    def test_privileged_port_probe_handles_mac_denial_without_ignoring_listener(self):
        from unittest.mock import MagicMock
        import errno
        primary, probe = MagicMock(), MagicMock()
        primary.bind.side_effect = OSError(errno.EACCES,'denied')
        probe.connect_ex.return_value = errno.ECONNREFUSED
        primary.__enter__.return_value = primary
        probe.__enter__.return_value = probe
        with patch.object(h.socket,'socket',side_effect=[primary,probe]):
            h.port_free()
        probe.connect_ex.return_value = 0
        with patch.object(h.socket,'socket',side_effect=[primary,probe]):
            with self.assertRaises(h.Refused): h.port_free()
        primary.bind.side_effect = OSError(errno.EADDRINUSE,'occupied')
        with patch.object(h.socket,'socket',return_value=primary):
            with self.assertRaises(h.Refused): h.port_free()

    def test_valid_model_is_separate_auth_world_and_no_private_key_in_verifiers(self):
        h.validate_model(self.model, self.record)
        services = self.model['services']
        self.assertIn('gateway-postgres', services['board-api']['environment']['GAME_DATABASE_URL'])
        self.assertIn('game-postgres', services['game-api']['environment']['GAME_DATABASE_URL'])
        self.assertNotIn('JWT_PRIVATE_KEY', services['game-api']['environment'])
        self.assertNotIn('JWT_PRIVATE_KEY', services['board-api']['environment'])
        self.assertEqual('160', services['game-engine']['environment']['OPENSAMGUK_WORLD_ID'])
        self.assertEqual('false', str(services['game-engine'].get('privileged', False)).lower())

    def test_non_loopback_or_extra_port_is_refused(self):
        for host in ('0.0.0.0', '::', '127.0.0.2', ''):
            self.rejects(lambda m: m['services']['nginx']['ports'][0].update(host_ip=host))
        self.rejects(lambda m: m['services']['game-api'].update(ports=[{'target': 8081, 'published': '8081'}]))
        self.rejects(lambda m: m['services']['nginx']['ports'][0].update(published='19443'))

    def test_external_network_and_volume_refused(self):
        self.rejects(lambda m: m['networks']['local'].update(external=True))
        self.rejects(lambda m: m['volumes']['game-pgdata'].update(external=True))
        self.rejects(lambda m: m['volumes']['game-pgdata'].update(name='qa160'))
        self.rejects(lambda m: m['services']['game-api'].update(network_mode='host'))
        self.rejects(lambda m: m['networks']['local'].update(driver='host'))

    def test_bind_socket_or_existing_db_refused(self):
        for source in ('/var/run/docker.sock', '/tmp/qa160', '/etc/nginx/nginx.conf'):
            self.rejects(lambda m: m['services']['nginx']['volumes'][0].update(source=source))
        self.rejects(lambda m: m['services']['nginx']['volumes'][0].update(read_only=False))
        self.rejects(lambda m: m['services']['game-api'].update(env_file=['.env']))
        self.rejects(lambda m: m['services']['game-api'].update(privileged=True))

    def test_foreign_image_service_alias_and_owner_refused(self):
        self.rejects(lambda m: m['services']['game-api'].update(image='ghcr.io/example:main'))
        self.rejects(lambda m: m['services']['game-api'].update(container_name='opensamguk-qa160-game-api'))
        self.rejects(lambda m: m['services']['game-api']['labels'].update({h.NONCE_LABEL: 'other'}))
        self.rejects(lambda m: m['services']['game-api'].update(build='.'))

    def resource(self, kind, **changes):
        own = {**h.labels(self.record), h.PROJECT_LABEL: self.record['project']}
        row = {'Name': self.record['project'] + ('-game-api-1' if kind=='container' else '_local'), 'Labels': own}
        if kind == 'container':
            row['Config'] = {'Labels': own}
        row.update(changes)
        return row

    def test_name_alone_or_nonce_alone_does_not_authorize_cleanup(self):
        for kind in ('container', 'network', 'volume'):
            row = self.resource(kind)
            h.assert_owned(self.record, {kind: [row]})
            own = row['Config']['Labels'] if kind=='container' else row['Labels']
            for key in (h.NONCE_LABEL, h.SESSION_LABEL, h.PROJECT_LABEL):
                bad = copy.deepcopy(row)
                target = bad['Config']['Labels'] if kind=='container' else bad['Labels']
                target[key] = 'foreign'
                with self.assertRaises(h.Refused):
                    h.assert_owned(self.record, {kind: [bad]})
            with self.assertRaises(h.Refused):
                h.assert_owned(self.record, {kind: [row]}, empty=True)
        h.assert_owned(self.record, {'container': [], 'network': [], 'volume': []}, empty=True)

    def test_nonce_identity_session_and_world_are_bound(self):
        with patch.dict(os.environ, OPENSAMGUK_TASK_OWNER_SESSION=self.record['session']):
            h.identity(self.record)
            for key, value in [('project','opensamguk-qa160'), ('serverId','qa160'), ('worldId',1),
                               ('generation',1), ('origin','http://localhost'), ('session','other')]:
                bad = {**self.record, key: value}
                with self.assertRaises(h.Refused):
                    h.identity(bad)

    def test_source_digest_detects_bytes_mode_and_symlink_changes(self):
        source = self.directory / 'source'
        expected = h.tree_hash(source)
        p = source / 'docker/game-api.Dockerfile'
        p.write_text('FROM changed')
        self.assertNotEqual(expected, h.tree_hash(source))
        expected = h.tree_hash(source)
        p.chmod(0o755)
        self.assertNotEqual(expected, h.tree_hash(source))
        p.unlink()
        p.symlink_to('/etc/passwd')
        with self.assertRaises(h.Refused):
            h.tree_hash(source)

    def test_archive_refuses_path_traversal_symlink_and_tracked_key(self):
        for name, kind in [('../escape', tarfile.REGTYPE), ('key.pem', tarfile.REGTYPE),
                           ('.env',tarfile.REGTYPE), ('link',tarfile.SYMTYPE)]:
            data = io.BytesIO()
            with tarfile.open(fileobj=data, mode='w') as tar:
                member = tarfile.TarInfo(name)
                member.type = kind
                member.linkname = '/etc/passwd' if kind == tarfile.SYMTYPE else ''
                tar.addfile(member)
            with self.assertRaises(h.Refused):
                h.unpack_archive(data.getvalue(), self.directory / ('bad' + str(len(list(self.directory.iterdir())))))

    def test_private_write_refuses_existing_file_and_symlink(self):
        path = self.directory / 'fixture.json'
        h.private_write(path, b'new-local-fixture')
        self.assertEqual(0o600, path.stat().st_mode & 0o777)
        with self.assertRaises(FileExistsError):
            h.private_write(path, b'changed')
        path.unlink()
        path.symlink_to(self.directory / 'source/docker/game-api.Dockerfile')
        with self.assertRaises(OSError):
            h.private_write(path, b'changed', replace=True)
        self.assertEqual('FROM scratch\n', (self.directory / 'source/docker/game-api.Dockerfile').read_text())

    def image(self, svc='game-api'):
        image = {'Id': 'sha256:' + 'd'*64, 'RepoTags': [h.image_ref(self.record, svc)],
                 'Config': {'Labels': h.image_metadata(self.record, svc, {})}}
        self.record['images'][svc] = {'imageId': image['Id'], 'dockerfileSha256': image['Config']['Labels']['org.opensamguk.local.dockerfile'],
                                       'buildArgs': h.build_args(self.record, svc)}
        return image

    def test_image_id_revision_dockerfile_and_public_build_args_are_verified(self):
        image = self.image()
        h.check_image(self.record, 'game-api', image)
        for key in h.image_metadata(self.record, 'game-api', {}):
            bad = copy.deepcopy(image)
            bad['Config']['Labels'][key] = 'changed'
            with self.assertRaises(h.Refused):
                h.check_image(self.record, 'game-api', bad)
        image['Id'] = 'sha256:' + 'e'*64
        with self.assertRaises(h.Refused):
            h.check_image(self.record, 'game-api', image)
        image = self.image()
        self.record['images']['game-api']['buildArgs']['IMAGE_TAG'] = 'other'
        with self.assertRaises(h.Refused):
            h.check_image(self.record, 'game-api', image)

    def test_build_args_registry_and_aliases_share_nonce_origin(self):
        sid = self.record['serverId']
        self.assertEqual(h.ORIGIN + '/game/' + sid, h.build_args(self.record, 'web-gateway')['NEXT_PUBLIC_GAME_URL'])
        registry = h.registry(self.record)[0]
        self.assertEqual('http://s'+sid+'-game-api:8081', registry['gameApiUrl'])
        for svc in ('game-api', 'game-engine', 'web-game'):
            self.assertEqual(['s'+sid+'-'+svc], self.model['services'][svc]['networks']['local']['aliases'])
        self.assertNotIn('qa160', json.dumps(self.model))

    def test_run_suppresses_arbitrary_child_output_and_drops_inherited_secrets(self):
        canary = 'NEVER_PRINT_NEW_FIXTURE_123'
        with patch.dict(os.environ, LHA_TEST_SECRET=canary, COMPOSE_FILE='/tmp/foreign.yml'):
            output = h.run([sys.executable, '-c', 'import os;print(os.getenv("LHA_TEST_SECRET"));print(os.getenv("COMPOSE_FILE"))'])
            self.assertEqual(b'None\nNone\n', output)
            with self.assertRaises(h.Refused) as caught:
                h.run([sys.executable, '-c', 'import sys;print(sys.argv[1]);sys.exit(1)', canary])
            self.assertNotIn(canary, str(caught.exception))
        logfile = self.directory / 'private.log'
        with self.assertRaises(h.Refused):
            h.run([sys.executable, '-c', 'import sys;print(sys.argv[1]);sys.exit(1)', canary], log_path=logfile)
        self.assertIn(canary, logfile.read_text())
        self.assertEqual(0o600, logfile.stat().st_mode & 0o777)

    def test_foreign_heavy_lock_is_never_deleted(self):
        meta = self.directory / 'meta'
        (meta / 'bin').mkdir(parents=True)
        (meta / 'bin/start-task').touch()
        (meta / '.locks/heavy-run').mkdir(parents=True)
        owner = meta / '.locks/heavy-run/owner'
        owner.write_text('FOREIGN')
        with patch.object(h.time, 'sleep', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                with h.heavy(meta, self.record):
                    self.fail('Must not enter')
        self.assertEqual('FOREIGN', owner.read_text())

    def test_heavy_release_checks_own_nonce_and_cleanup_works_under_pressure(self):
        meta = self.directory / 'meta'
        (meta / 'bin').mkdir(parents=True)
        (meta / 'bin/start-task').touch()
        with patch.object(h, 'resource_gate', side_effect=h.Refused('low disk')):
            with self.assertRaises(h.Refused):
                with h.heavy(meta, self.record):
                    self.fail('Gate must run')
            self.assertFalse((meta / '.locks/heavy-run').exists())
            with h.heavy(meta, self.record, cleanup=True):
                self.assertTrue((meta / '.locks/heavy-run/owner').is_file())
            self.assertFalse((meta / '.locks/heavy-run').exists())

    def test_cleanup_foreign_volume_consumer_refuses_before_any_delete(self):
        self.record['images'] = {}
        rows = {'container': [], 'network': [], 'volume': [self.resource('volume', Name=self.record['project']+'_game-pgdata')]}
        with patch.object(h, 'load', return_value=(self.directory, self.record)), patch.object(h, 'verify_files'), \
             patch.object(h, 'heavy', return_value=__import__('contextlib').nullcontext()), \
             patch.object(h, 'inventory', return_value=rows), patch.object(h, 'run', return_value=b'foreign-container\n') as run:
            with self.assertRaises(h.Refused):
                h.down(type('Args', (), {'custody':self.directory, 'meta':self.directory})())
            self.assertEqual(1, run.call_count)
            self.assertNotIn('rm', run.call_args.args[0])

    def owned_files(self):
        h.private_write(self.directory/'nginx.conf',b'canonical nginx bytes')
        (self.directory/'certs').mkdir()
        h.private_write(self.directory/'certs/opensamguk.crt',b'new local cert')
        (self.directory/'battle-ws').mkdir()
        h.write_json(self.directory/'runtime.json',self.fixture)
        h.write_json(self.directory/'compose.json',self.model)
        self.record.update(nginxSha256=h.sha(b'canonical nginx bytes'),
            templateSha256=h.sha((h.ROOT/'docker-compose.localhost-acceptance.yml').read_bytes()),
            sourceTreeSha256=h.tree_hash(self.directory/'source'),certsSha256=h.tree_hash(self.directory/'certs'),
            configSha256=h.sha((self.directory/'compose.json').read_bytes()))

    def test_canonical_nginx_config_fixture_and_source_changes_refuse_before_up(self):
        self.owned_files()
        with patch.object(h,'git',return_value=b'canonical nginx bytes'):
            h.verify_files(self.directory,self.record)
            (self.directory/'nginx.conf').write_text('synthetic nginx')
            with self.assertRaises(h.Refused):
                h.verify_files(self.directory,self.record)
            (self.directory/'nginx.conf').write_bytes(b'canonical nginx bytes')
            (self.directory/'compose.json').write_text('{}')
            with self.assertRaises(h.Refused):
                h.verify_files(self.directory,self.record)
            h.write_json(self.directory/'compose.json',self.model,replace=True)
            h.private_write(self.directory/'runtime.json',b'{}',replace=True)
            with self.assertRaises((h.Refused,KeyError)):
                h.verify_files(self.directory,self.record)
        with patch.object(h,'git',return_value=b'other Docker nginx'):
            with self.assertRaises(h.Refused):
                h.verify_files(self.directory,self.record)

    def test_real_git_archive_removes_worktree_state_and_preserves_tracked_modes(self):
        repo=self.directory/'git-source'
        repo.mkdir()
        subprocess.run(['git','init','-q',str(repo)],check=True)
        for key,value in [('user.name','Local Fixture'),('user.email','fixture@localhost')]:
            subprocess.run(['git','-C',str(repo),'config',key,value],check=True)
        (repo/'tracked').write_text('source fixture')
        (repo/'tracked').chmod(0o755)
        subprocess.run(['git','-C',str(repo),'add','tracked'],check=True)
        subprocess.run(['git','-C',str(repo),'commit','-qm','fixture'],check=True)
        revision=h.git(repo,'rev-parse','HEAD').decode().strip()
        archive=h.source_archive(repo,revision)
        export=self.directory/'export'
        h.unpack_archive(archive,export)
        self.assertEqual(['tracked'],[p.name for p in export.iterdir()])
        self.assertEqual(0o755,(export/'tracked').stat().st_mode & 0o777)
        (repo/'untracked').write_text('ignored by archive but fail closed')
        with self.assertRaises(h.Refused):
            h.source_archive(repo,revision)

    def test_snapshot_rejects_sql_input_before_any_docker_command(self):
        for gid, request in [('0', None), ('1;DELETE',None), ('1', "x' OR true")]:
            args = type('Args', (), {'general_id':gid, 'request_id':request, 'custody':self.directory})()
            with patch.object(h, 'load') as load:
                with self.assertRaises(h.Refused):
                    h.snapshot(args)
                load.assert_not_called()

    def test_snapshot_is_fixed_read_only_projection_and_suppresses_log_body(self):
        h.write_json(self.directory / 'compose.json', self.model)
        self.record['configSha256'] = h.sha((self.directory / 'compose.json').read_bytes())
        result = {'generalId': 123, 'cityId': 1, 'userId': 2, 'nationId': 0, 'npcState': 0,
                  'experience': 5, 'dedication': 5, 'turnTime': '2026-10-17T01:00:00Z',
                  'world': {'tickSeconds': 120}, 'personal': None}
        args = type('Args', (), {'general_id':'123', 'request_id':'12345678-1234-1234-1234-123456789abc',
                                'custody':self.directory})()
        with patch.object(h, 'load', return_value=(self.directory,self.record)), \
             patch.object(h, 'inventory', return_value={}), patch.object(h, 'verify_running'), \
             patch.object(h, 'sql', return_value=json.dumps(result)) as sql, patch('sys.stdout', new_callable=io.StringIO) as out:
            h.snapshot(args)
            self.assertEqual(result, json.loads(out.getvalue()))
            query = sql.call_args.args[-1]
            self.assertIn('BEGIN READ ONLY', query)
            self.assertIn('g.id=123', query)
            self.assertIn('g.world_id=160', query)
            self.assertNotIn('log_entry.body', query)
            self.assertNotIn('password', query)
            self.assertNotIn('UPDATE', query)

    def running_resources(self):
        for svc in h.SERVICES: self.image(svc)
        self.record['supportImages']={ref:'sha256:'+str(i)*64 for i,ref in enumerate(h.SUPPORT_IMAGES)}
        rows=[]
        for index,(svc,model) in enumerate(self.model['services'].items()):
            own={**h.labels(self.record),h.PROJECT_LABEL:self.record['project'],'com.docker.compose.service':svc}
            image=(self.record['images'][svc]['imageId'] if svc in h.SERVICES else self.record['supportImages'][model['image']])
            row={'Id':'container-'+str(index),'Name':self.record['project']+'-'+svc+'-1',
                 'Config':{'Labels':own},'State':{'Running':True,'Health':{'Status':'healthy'}},'Image':image,
                 'NetworkSettings':{'Networks':{self.record['project']+'_local':{}}},
                 'HostConfig':{'PortBindings':({'443/tcp':[{'HostIp':'127.0.0.1','HostPort':'443'}]} if svc=='nginx' else {})},
                 'Mounts':[]}
            for mount in model.get('volumes',[]):
                if mount['type']=='bind': row['Mounts'].append({'Type':'bind','Source':mount['source'],'RW':False})
                else: row['Mounts'].append({'Type':'volume','Name':self.model['volumes'][mount['source']]['name']})
            rows.append(row)
        network=self.resource('network',Driver='bridge',Containers={r['Id']:{} for r in rows})
        return {'container':rows,'network':[network],'volume':[]}

    def test_actual_runtime_ports_images_mounts_health_and_network_members_are_checked(self):
        resources=self.running_resources()
        h.verify_running(self.record,resources,self.model)
        for mutate in [lambda r:r['container'][0]['NetworkSettings']['Networks'].update(foreign={}),
                       lambda r:r['container'][0]['HostConfig'].update(PortBindings={'5432/tcp':[{'HostIp':'0.0.0.0','HostPort':'5432'}]}),
                       lambda r:r['container'][0].update(Image='different'),
                       lambda r:r['container'][0]['State']['Health'].update(Status='unhealthy'),
                       lambda r:r['container'][0]['Mounts'].append({'Type':'volume','Name':'qa160'}),
                       lambda r:r['network'][0]['Containers'].update(foreign={})]:
            bad=copy.deepcopy(resources)
            mutate(bad)
            with self.assertRaises(h.Refused):h.verify_running(self.record,bad,self.model)

    def test_source_requires_clean_head_and_rejects_ignored_data_without_reading_it(self):
        with patch.object(h, 'git', side_effect=[('a'*40+'\n').encode(),b'',b'.env\n']) as git:
            with self.assertRaises(h.Refused):
                h.source_archive(self.directory, 'a'*40)
            self.assertEqual('ls-files', git.call_args.args[1])
        with patch.object(h, 'git', return_value=('b'*40+'\n').encode()) as git:
            with self.assertRaises(h.Refused):
                h.source_archive(self.directory, 'a'*40)
            self.assertEqual(1,git.call_count)

    def test_cleanup_removes_only_preinspected_owned_ids_and_preserves_custody(self):
        rows = {'container':[self.resource('container', Id='own-id')],
                'network':[self.resource('network',Id='own-net',Containers={'own-id':{}})],
                'volume':[self.resource('volume',Name=self.record['project']+'_game-pgdata')]}
        with patch.object(h,'load',return_value=(self.directory,self.record)), patch.object(h,'verify_files'), \
             patch.object(h,'heavy',return_value=__import__('contextlib').nullcontext()), \
             patch.object(h,'inventory',return_value=rows), patch.object(h,'run',return_value=b'own-id\n') as run:
            h.down(type('Args',(),{'custody':self.directory,'meta':self.directory})())
            commands = [call.args[0] for call in run.call_args_list]
            self.assertEqual(['docker','container','rm','-f','own-id'],commands[1])
            self.assertEqual(['docker','network','rm','own-net'],commands[2])
            self.assertEqual(['docker','volume','rm',self.record['project']+'_game-pgdata'],commands[3])
            self.assertEqual('REMOVED',json.loads((self.directory/'contract.json').read_text())['status'])
            self.assertTrue((self.directory/'source').exists())

    def test_compose_round_trip_with_real_cli_does_not_read_dotenv(self):
        if not __import__('shutil').which('docker'):
            self.skipTest('docker compose CLI absent')
        (self.directory / '.env').write_text('COMPOSE_PROJECT_NAME=FOREIGN\n')
        h.write_json(self.directory / 'compose.json', self.model)
        normalized = json.loads(h.compose(self.directory, self.record, 'config', '--format', 'json'))
        self.assertEqual(self.record['project'], normalized['name'])
        self.assertEqual({'127.0.0.1'}, {p['host_ip'] for s in normalized['services'].values() for p in s.get('ports',[])})
        self.assertEqual(set(self.model['services']), set(normalized['services']))
        self.assertEqual(self.fixture['ADMIN_PASSWORD'], normalized['services']['gateway-api']['environment']['ADMIN_PASSWORD'])


if __name__ == '__main__':
    unittest.main()
