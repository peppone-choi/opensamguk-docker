"""Preserve reviewed route provenance without claiming a copied inode is the source inode."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import unicodedata

from storage import need, private, read, digest

VERIFIER_HEAD = 'b1ad1f956105a6bdc6e8a3378ea8de81bcd224cb'
VERIFIER_HARNESS_SHA256 = 'c2a7c501a68fed8c7f54fb7049bf668d95807e7558ba063a52d2b96f25065520'
BUILD_HEAD = 'd35b3815e4f3edea119c4eff3b9678766be756b7'
PROOF_FILES = ('tactical-route-original-contract.json', 'tactical-route-original-nginx.conf',
               'tactical-route-recovery.json')
ROUTE_FILE = 'localhost-allowlist.map'


def active(record):
    return any(k.startswith('runtimeNginx') or k == 'runtimeVerifierHarnessSha256' or
               k == 'battleRouting' for k in record)


def file_identity(path):
    value = private(path).stat()
    need(stat.S_IMODE(value.st_mode) == 0o600, 'ROUTE_PRIVATE_MODE')
    return {'device': value.st_dev, 'inode': value.st_ino}


def verifier(record, base):
    need(record.get('runtimeVerifierHead') == VERIFIER_HEAD and
         record.get('runtimeVerifierHarnessSha256') == VERIFIER_HARNESS_SHA256, 'ROUTE_VERIFIER_PIN')
    value = record.get('runtimeVerifierPath')
    need(isinstance(value, str) and Path(value).is_absolute() and '..' not in Path(value).parts,
         'ROUTE_VERIFIER_PATH')
    root = Path(value)
    need(not any(p.is_symlink() for p in (root, *root.parents)), 'ROUTE_VERIFIER_SYMLINK')
    top = base.git(root, 'rev-parse', '--show-toplevel').decode().strip()
    need(os.path.samefile(root, top) and unicodedata.normalize('NFC', value) ==
         unicodedata.normalize('NFC', top), 'ROUTE_VERIFIER_ROOT')
    need(base.git(root, 'rev-parse', 'HEAD').decode().strip() == VERIFIER_HEAD and
         not base.git(root, 'status', '--porcelain', '--untracked-files=all').strip() and
         not base.git(root, 'ls-files', '--others', '--ignored', '--exclude-standard').strip(),
         'ROUTE_VERIFIER_DIRTY_OR_HEAD')
    source = base.git(root, 'show', VERIFIER_HEAD + ':tools/localhost-acceptance/harness.py')
    need(source == (root / 'tools/localhost-acceptance/harness.py').read_bytes() and
         hashlib.sha256(source).hexdigest() == VERIFIER_HARNESS_SHA256, 'ROUTE_VERIFIER_BYTES')
    return root


def route_bytes(record):
    sid = record.get('serverId', '')
    need(re.fullmatch('lha[a-f0-9]{16}', sid), 'ROUTE_SERVER_ID')
    return ('"' + sid + '" "http://s' + sid + '-game-api:8081";\n').encode()


def snapshot(directory, record, base, live=False):
    if not active(record):
        return None
    need({k for k in record if 'battlerout' in re.sub('[^a-z]', '', k.lower())} <=
         {'battleRouting'}, 'ROUTE_UNKNOWN_BINDING')
    root = verifier(record, base)
    original_raw = private(Path(directory) / PROOF_FILES[0]).read_bytes()
    original = json.loads(original_raw)
    need(original.get('dockerSha') == BUILD_HEAD and original.get('profile') == 'tactical' and
         original.get('status') == 'RUNNING' and 'battleRouting' not in original and
         not any(k.startswith('runtimeVerifier') or k.startswith('runtimeNginx') for k in original),
         'ROUTE_ORIGINAL_CONTRACT')
    old = base.git(root, 'show', BUILD_HEAD + ':infra/nginx/nginx.conf')
    pattern = b'location ~ "^/api/battle-ws/'
    block = b'        location /api/battle-ws/ {\n            access_log off;\n            return 404;\n        }\n'
    alias = b'        location = /ws/battles {\n            access_log off;\n            return 404;\n        }\n        location /ws/battles/ {\n            access_log off;\n            return 404;\n        }\n'
    need(old.count(pattern) == 2 and old.count(block) == 2 and
         hashlib.sha256(old).hexdigest() == original['nginxSha256'], 'ROUTE_ORIGINAL_NGINX')
    new = old.replace(pattern, b'location ~ "^/(?:api/battle-ws|ws/battles)/').replace(block, block + alias)
    need(new == base.git(root, 'show', VERIFIER_HEAD + ':infra/nginx/nginx.conf') and
         private(Path(directory) / PROOF_FILES[1]).read_bytes() == old and
         private(Path(directory) / 'nginx.conf').read_bytes() == new, 'ROUTE_CANONICAL_NGINX')
    inode = record.get('runtimeNginxFileIdentity')
    need(type(inode) is dict and set(inode) == {'device', 'inode'} and
         all(type(v) is int and v >= 0 for v in inode.values()), 'ROUTE_SOURCE_INODE')
    current_inode = file_identity(Path(directory) / 'nginx.conf')
    need(not live or current_inode == inode, 'ROUTE_LIVE_INODE')
    binding = {'schema': 1, 'file': ROUTE_FILE, 'sha256': hashlib.sha256(route_bytes(original)).hexdigest()}
    fields = {'runtimeVerifierHead': VERIFIER_HEAD, 'runtimeVerifierPath': str(root),
              'runtimeVerifierHarnessSha256': VERIFIER_HARNESS_SHA256,
              'runtimeNginxSha256': hashlib.sha256(new).hexdigest(), 'runtimeNginxFileIdentity': inode}
    expected = {**original, **fields, 'battleRouting': binding}
    need(record.get('status') == 'SMOKE_PASSED' and {**record, 'status': 'RUNNING'} == expected and
         read(Path(directory) / PROOF_FILES[2]) == {'schema': 1,
             'originalContractSha256': hashlib.sha256(original_raw).hexdigest(), **fields,
             'battleRouting': binding}, 'ROUTE_SOURCE_PROOF')
    route = private(Path(directory) / 'battle-ws', True)
    need({p.name for p in route.iterdir()} == {ROUTE_FILE} and
         private(route / ROUTE_FILE).read_bytes() == route_bytes(original), 'ROUTE_BYTES')
    return {'schema': 1, 'verifierHead': VERIFIER_HEAD,
            'sourceContractSha256': hashlib.sha256(json.dumps(record, sort_keys=True).encode()).hexdigest(),
            'proofFiles': {name: digest(Path(directory) / name) for name in PROOF_FILES},
            'nginxSha256': hashlib.sha256(new).hexdigest(), 'routeSha256': binding['sha256']}


def copied_binding(directory, source_directory, record, base):
    source = snapshot(source_directory, record, base)
    if source is None:
        return None
    copied = snapshot(directory, record, base)
    need(copied == source, 'ROUTE_COPY_BYTES')
    return {**source, 'copiedNginxFileIdentity': file_identity(Path(directory) / 'nginx.conf')}


def live_model(directory, record, base):
    snapshot(directory, record, base, live=True)
    need(digest(Path(directory) / 'compose.json') == record['configSha256'] and
         base.tree_hash(Path(directory) / 'source') == record['sourceTreeSha256'] and
         base.tree_hash(Path(directory) / 'certs') == record['certsSha256'] and
         digest(base.ROOT / 'docker-compose.localhost-acceptance.yml') == record['templateSha256'],
         'ROUTE_CUSTODY_FILES')
    model = read(Path(directory) / 'compose.json')
    need(model == base.model_for(record, read(Path(directory) / 'runtime.json')), 'ROUTE_APP_CONFIG')
    need(model['services']['game-api']['networks']['local']['aliases'] ==
         ['s' + record['serverId'] + '-game-api'], 'ROUTE_API_ALIAS')
    return model


def runtime_aliases(record, containers):
    alias = 's' + record['serverId'] + '-game-api'
    found = 0
    for row in containers:
        aliases = row['NetworkSettings']['Networks'][record['project'] + '_local'].get('Aliases') or []
        if row['Config']['Labels'].get('com.docker.compose.service') == 'game-api':
            found += 1
            need(len(aliases) == 3 and set(aliases) == {row['Name'].lstrip('/'), 'game-api', alias},
                 'ROUTE_RUNTIME_ALIAS')
        else:
            need(alias not in aliases, 'ROUTE_FOREIGN_ALIAS')
    need(found == 1, 'ROUTE_UNIQUE_API')


def boundaries(record):
    if not active(record):
        return [('/api/battle-ws/' + record['serverId'] + '/160/probe', 404)]
    need(record.get('profile') == 'tactical', 'ROUTE_PROFILE')
    route_bytes(record)
    return [(prefix + suffix, status)
            for prefix in ('/api/battle-ws', '/ws/battles')
            for suffix, status in (('/' + record['serverId'] + '/160/probe', 403),
                                   ('/foreign/160/probe', 404),
                                   ('/' + record['serverId'] + '/0/probe', 404),
                                   ('/' + record['serverId'] + '/160/bad.dot', 404))]
