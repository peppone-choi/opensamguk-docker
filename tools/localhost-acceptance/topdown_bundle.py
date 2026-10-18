"""Validate and copy an explicitly pinned, already approved public map bundle. Never bake or activate it."""
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat

RELEASE = 'province-world-20261003'
CATALOG = 'data/map/' + RELEASE + '-artifacts/catalog.json'
KIT = 'data/map/waryong/273d596'
TARGET = '/app/data/map/topdown'
SHA = re.compile(r'[a-f0-9]{64}\Z')
FILE = re.compile(r'(?:grid/L0/[0-9]+_[0-9]+\.bin\.gz|grid/L2\.bin\.gz|places\.json\.gz|defects\.json)\Z')
LIMIT = 16 * 1024**2
INPUTS = {'tilesSha256': 'data/map/province-tiles.json',
          'worldJsonSha256': 'infra/src/main/resources/map/han-world-v3.json',
          'roadsSha256': 'data/map/han-land-roads-v1.json'}


class Refused(ValueError):
    pass


def need(ok, code):
    if not ok:
        raise Refused('TOPDOWN_' + code)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def decode(data):
    def pairs(items):
        result = {}
        for k, v in items:
            need(k not in result, 'DUPLICATE_KEY')
            result[k] = v
        return result
    return json.loads(data, object_pairs_hook=pairs)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def path_checked(path, directory=False):
    path = Path(path).absolute()
    need('..' not in path.parts, 'PATH_TRAVERSAL')
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'SYMLINK')
    info = path.stat()
    need(info.st_uid == os.getuid() and not info.st_mode & 0o022, 'OWNER_MODE')
    need(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'FILE_TYPE')
    return path


def read_file(path, limit=LIMIT):
    path = path_checked(path)
    with path.open('rb') as handle:
        data = handle.read(limit + 1)
    need(len(data) <= limit, 'FILE_SIZE')
    return data


def source_pins(read):
    """The fresh scenario_3190 selects this immutable province-world catalog; no stored-world guessing."""
    catalog_bytes = read(CATALOG)
    catalog = decode(catalog_bytes)
    need(catalog.get('artifactId') == RELEASE and catalog.get('cityCount') == 1428, 'SOURCE_RELEASE')
    files = {item['path']: item for item in catalog['files']}
    pins = {'artifactCatalogSha256': sha(catalog_bytes)}
    for key, name in INPUTS.items():
        entry = files[name]
        data = read(name)
        need(sha(data) == entry['sha256'], 'SOURCE_PIN')
        need(entry['blob'] == 'blobs/' + entry['sha256'] + '.json.gz' and
             SHA.fullmatch(entry['sha256']), 'SOURCE_BLOB_PATH')
        compressed = read('data/map/' + RELEASE + '-artifacts/' + entry['blob'])
        need(sha(compressed) == entry['compressedSha256'] and gzip.decompress(compressed) == data,
             'SOURCE_BLOB')
        pins[key] = sha(data)
    export_bytes = read(KIT + '/export.json')
    export = decode(export_bytes)
    need(export.get('kitId') == '273d596' and export.get('schemaVersion') == 1 and
         export['source']['repository'] == 'peppone-choi/opensamguk-images', 'KIT_EXPORT')
    mirrors = {'web/game/public/map/waryong/273d596', 'web/gateway/public/map/waryong/273d596'}
    need(set(export.get('mirrors', [])) == mirrors, 'KIT_MIRRORS')
    kit = {'kit/export.json': sha(export_bytes), 'kit/sourceMergeCommit': export['source']['mergeCommit']}
    for name, entry in export['files'].items():
        need(any(name.startswith(p) for p in (KIT + '/', 'web/game/public/map/waryong/273d596/')) and
             '..' not in Path(name).parts, 'KIT_PATH')
        data = read(name)
        need(len(data) == entry['bytes'] and sha(data) == entry['sha256'], 'KIT_BYTES')
        if name.startswith('web/game/'):
            need(all(read(mirror + '/' + Path(name).name) == data for mirror in mirrors), 'KIT_MIRROR_BYTES')
        if name.startswith(KIT + '/') or name.endswith('/kit-index.png'):
            kit['kit/' + Path(name).name] = sha(data)
    return {'mapRelease': RELEASE, 'inputFingerprint': pins, 'kitInputs': kit}


def validate(root, bake_id, manifest_sha, pins, public_modes=False):
    root = path_checked(root, True)
    need(isinstance(bake_id, str) and SHA.fullmatch(bake_id) and root.name == bake_id and
         isinstance(manifest_sha, str) and SHA.fullmatch(manifest_sha), 'EXPLICIT_PIN')
    raw = read_file(root / 'manifest.json', 2 * 1024**2)
    need(sha(raw) == manifest_sha, 'MANIFEST_HASH')
    m = decode(raw)
    need(m.get('schemaVersion') == 1 and m.get('formatVersion') == 1 and
         m.get('artifactId') == 'topdown-bake' and m.get('bakeId') == bake_id and
         m.get('partial') is False and m['inputFingerprint'].get('region', 'missing') is None,
         'FULL_BUNDLE')
    identity = {k: m[k] for k in ('inputFingerprint', 'mapRelease', 'kitVersion', 'formatVersion')}
    need(sha(canonical(identity)) == bake_id and m['mapRelease'] == pins['mapRelease'], 'BAKE_IDENTITY')
    need(all(m['inputFingerprint'].get(k) == v for k, v in pins['inputFingerprint'].items()) and
         all(m['inputFingerprint']['bakeInputs'].get(k) == v for k, v in pins['kitInputs'].items()),
         'ACTIVE_INPUTS')
    cols, rows = m['shape']['cols'], m['shape']['rows']
    need(type(cols) is int and type(rows) is int and 0 < cols <= 16384 and 0 < rows <= 16384 and
         m.get('chunkSize') == 256 and m.get('undrawnTile') == 65535, 'SHAPE')
    chunks = m['chunks']
    expected = {(x, y) for y in range((rows + 255) // 256) for x in range((cols + 255) // 256)}
    need(isinstance(chunks, list) and len(chunks) == len(expected) and
         all(type(c['cx']) is int and type(c['cy']) is int for c in chunks) and
         {(c['cx'], c['cy']) for c in chunks} == expected, 'CHUNKS')
    for chunk in chunks:
        if 'file' in chunk:
            need(chunk['file'] == 'grid/L0/' + str(chunk['cx']) + '_' + str(chunk['cy']) + '.bin.gz', 'CHUNK_PATH')
        else:
            uniform = chunk.get('uniform', {})
            need(set(uniform) == {'tile', 'province'} and
                 all(type(uniform[k]) is int and 0 <= uniform[k] <= 65535 for k in uniform), 'UNIFORM')
            raw = b''.join(uniform[k].to_bytes(2, 'little') * 65536 for k in ('tile', 'province'))
            need(sha(raw) == chunk.get('rawSha256'), 'UNIFORM_HASH')
    entries = {}
    need(isinstance(m['files'], list) and 0 < len(m['files']) <= 4099 and
         sum(e['bytes'] for e in m['files']) <= 128 * 1024**2, 'BUNDLE_SIZE')
    for entry in m['files']:
        name = entry['file']
        need(isinstance(name, str) and FILE.fullmatch(name) and name not in entries and
             type(entry['bytes']) is int and 0 <= entry['bytes'] <= LIMIT and
             all(isinstance(entry[k], str) and SHA.fullmatch(entry[k]) for k in ('sha256', 'rawSha256')),
             'FILE_ENTRY')
        data = read_file(root / name)
        need(len(data) == entry['bytes'] and sha(data) == entry['sha256'], 'TRANSPORT_HASH')
        compressed = name.endswith('.gz')
        need(entry.get('compression') == ('gzip' if compressed else 'none'), 'COMPRESSION')
        raw = gzip.GzipFile(fileobj=io.BytesIO(data)).read(LIMIT + 1) if compressed else data
        need(len(raw) <= LIMIT and sha(raw) == entry['rawSha256'], 'RAW_HASH')
        if name.startswith('grid/L0/'):
            need(len(raw) == 4 * 256 * 256, 'L0_SIZE')
        if name == 'grid/L2.bin.gz':
            need(len(raw) == 4 * m['overview']['cols'] * m['overview']['rows'], 'L2_SIZE')
        entries[name] = entry
    public = [c for c in chunks if 'file' in c] + [m[k] for k in ('overview', 'places', 'defects')]
    need(len(public) == len(entries) and {p['file'] for p in public} == entries.keys() and
         all(all(p[k] == entries[p['file']][k] for k in ('bytes', 'sha256', 'rawSha256')) for p in public),
         'PUBLIC_INVENTORY')
    allowed = {'manifest.json', *entries}
    allowed_dirs = {p.as_posix() for name in allowed for p in Path(name).parents if p != Path('.')}
    observed = set()
    for path in root.rglob('*'):
        path_checked(path, path.is_dir())
        relative = path.relative_to(root).as_posix()
        need(relative in (allowed_dirs if path.is_dir() else allowed), 'EXTRA_ENTRY')
        observed.add(relative)
        if public_modes:
            need(stat.S_IMODE(path.stat().st_mode) == (0o755 if path.is_dir() else 0o644), 'PUBLIC_MODE')
    need(observed == allowed | allowed_dirs, 'MISSING_ENTRY')
    if public_modes:
        need(stat.S_IMODE(root.stat().st_mode) == 0o755, 'PUBLIC_MODE')
    return {'bakeId': bake_id, 'manifestSha256': manifest_sha, 'sourcePins': pins}


def overlap(a, b):
    a, b = a.resolve(), b.resolve()
    return (a.is_relative_to(b) or b.is_relative_to(a) or
            any(x.exists() and y.exists() and os.path.samefile(x, y)
                for x, y in [(p, b) for p in (a, *a.parents)] + [(a, p) for p in b.parents]))


def copy_bundle(source, directory, record):
    target = directory / 'topdown' / record['bakeId']
    need(not overlap(source, directory) and not target.parent.exists(), 'OUTPUT_OVERLAP')
    validate(source, record['bakeId'], record['manifestSha256'], record['sourcePins'])
    target.mkdir(parents=True)
    target.parent.chmod(0o755)
    target.chmod(0o755)
    for path in source.rglob('*'):
        destination = target / path.relative_to(source)
        if path.is_dir():
            destination.mkdir(exist_ok=True)
            destination.chmod(0o755)
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
            with destination.open('xb') as handle:
                handle.write(read_file(path))
            destination.chmod(0o644)
    validate(source, record['bakeId'], record['manifestSha256'], record['sourcePins'])
    validate(target, record['bakeId'], record['manifestSha256'], record['sourcePins'], True)


def settings(record):
    selected = record.get('topdown')
    if selected is None:
        return {}, []
    need(set(selected) == {'bakeId', 'manifestSha256', 'sourcePins'} and
         SHA.fullmatch(selected['bakeId']) and SHA.fullmatch(selected['manifestSha256']), 'RECORD')
    return {'TOPDOWN_MAP_ROOT': TARGET, 'TOPDOWN_BAKE_ID': selected['bakeId']}, [
        {'type': 'bind', 'source': record['custody'] + '/topdown', 'target': TARGET,
         'read_only': True, 'bind': {'create_host_path': False}}]


def smoke(record, read):
    selected = record.get('topdown')
    if selected is None:
        return
    need(decode(read('/api/map/preview')).get('topdownBakeId') == selected['bakeId'], 'PREVIEW_BINDING')
    need(sha(read('/api/map/topdown/' + selected['bakeId'] + '/manifest.json')) == selected['manifestSha256'],
         'SERVED_MANIFEST')
