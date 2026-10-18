"""Fresh-custody native writer selection and read-only lease proof. Never acquire a grant here."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid

FILE = 'native-writer.properties'
TARGET = '/app/' + FILE
CONFIG = b'opensamguk.native-writer.enabled=true\n'
LOCATION = 'SPRING_CONFIG_ADDITIONAL_LOCATION'
HELPER = 'tools/localhost-acceptance/native_writer.py'
ENGINE = 'app/game-engine/src/main/kotlin/opensamguk/engine/'
INFRA = 'infra/src/main/kotlin/opensamguk/infra/'
SOURCE = {
    ENGINE + 'config/NativeWriterConfiguration.kt': ('@DependsOnDatabaseInitialization',
        'opensamguk.native-writer.enabled:false', 'NativeWriterRuntime(source,processWorld.worldId.value,enabled)'),
    ENGINE + 'config/WorldIdConfig.kt': ('OPENSAMGUK_WORLD_ID', 'EngineProcessWorld(rawWorldId.toIntOrNull()'),
    ENGINE + 'config/BootstrapConfig.kt': ('nativeWriter?.load(loader,requireNotNull(seedBootstrap)',),
    ENGINE + 'flush/NativeWriterRuntime.kt': ('seed.ensureSeeded(seedJdbc)', 'val grant=owner.acquire()',
        'loader.buildSnapshot()', 'it.state.writerEpoch==grant.epoch', 'lease?.verify(worldId,epoch)'),
    ENGINE + 'run/TurnRunService.kt': ('nativeWriter.verify(world.worldId.value,world.getState().writerEpoch)',
        'worldState["native_writer_grant"]=it.requestId', 'Leased native writer requires the bound execution transaction fence'),
    ENGINE + 'flush/FlushRecoveryHealthIndicator.kt': ('nativeWriter?.isReady()==false', 'NATIVE_FENCE_UNAVAILABLE'),
    INFRA + 'persistence/writer/JdbcNativeWriterLease.kt': ('pg_try_advisory_lock(?,?)', 'Math.addExact(previous,1L)',
        'INSERT INTO native_writer_current(world_id,grant_id)', "set_config('opensamguk.native_writer_grant',?,true)",
        'UPDATE world_state SET writer_epoch=? WHERE id=? AND writer_epoch=?', 'native_writer_lease_alive(?,?,?)'),
    INFRA + 'persistence/JdbcFlushExecutor.kt': ('payload.worldStateUpdate["native_writer_grant"]',
        "set_config('opensamguk.native_writer_grant',?,true)"),
    INFRA + 'battle/realtime/NativeWriterBindingReader.kt': ('native_writer_binding_valid(?,?,?,?)',
        'require(grant.epoch==currentEpoch)', 'NativeWriterBinding(world,originEpoch,grant)'),
    'infra/src/main/resources/db/migration/V86__native_world_writer_grant.sql': (
        'CREATE TABLE native_writer_grant', 'CREATE TABLE native_writer_current',
        'CREATE FUNCTION native_writer_lease_alive', 'CREATE FUNCTION native_writer_binding_valid',
        'CREATE CONSTRAINT TRIGGER native_writer_commit_guard', 'DEFERRABLE INITIALLY DEFERRED',
        'grant cannot advance gameplay version'),
}
PROOF_FIELDS = {'worldCount', 'worldId', 'writerEpoch', 'grantEpoch', 'previousEpoch', 'originEpoch',
                'grantId', 'requestId', 'leaseAlive', 'handoverValid'}


class Refused(ValueError):
    pass


def need(ok, message):
    if not ok:
        raise Refused('Native writer: ' + message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def decode(raw):
    need(isinstance(raw, (bytes, str)) and len(raw) <= 8192, 'invalid proof size/type')
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate proof field')
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs)
    except (ValueError, UnicodeDecodeError):
        raise Refused('Native writer: invalid proof JSON') from None


def source_pins(read):
    pins = {}
    for path, markers in SOURCE.items():
        data = read(path)
        need(isinstance(data, bytes) and all(marker.encode() in data for marker in markers), 'app source lacks native contract')
        pins[path] = sha(data)
    return pins


def selection(read_app, read_verifier):
    canonical = read_verifier(HELPER)
    need(canonical == Path(__file__).read_bytes(), 'prepare requires a canonical native-capable Docker revision')
    return {'schema': 1, 'sourcePins': source_pins(read_app), 'harnessSha256': sha(canonical),
            'configSha256': sha(CONFIG), 'proof': None}


def selected(record):
    keys = {key for key in record if 'nativewriter' in re.sub('[^a-z0-9]', '', key.lower())}
    need(keys <= {'nativeWriter'}, 'unknown native selection alias')
    if 'nativeWriter' not in record:
        return None
    value = record['nativeWriter']
    need(isinstance(value, dict) and set(value) == {'schema', 'sourcePins', 'harnessSha256', 'configSha256', 'proof'},
         'invalid selection fields')
    need(type(value['schema']) is int and value['schema'] == 1 and value['configSha256'] == sha(CONFIG), 'selection schema/config differs')
    need(type(record.get('worldId')) is int and record['worldId'] == 160 and
         type(record.get('generation')) is int and record['generation'] == 0, 'fresh world identity differs')
    need(isinstance(value['harnessSha256'], str) and re.fullmatch('[a-f0-9]{64}', value['harnessSha256']), 'verifier pin unavailable')
    pins = value['sourcePins']
    need(isinstance(pins, dict) and set(pins) == set(SOURCE) and
         all(isinstance(pin, str) and re.fullmatch('[a-f0-9]{64}', pin) for pin in pins.values()), 'app source pins differ')
    if value['proof'] is not None:
        validate_proof(value['proof'], record)
    return value


def settings(record):
    if selected(record) is None:
        return {}, []
    return {LOCATION: 'file:' + TARGET}, [{'type': 'bind', 'source': record['custody'] + '/' + FILE,
        'target': TARGET, 'read_only': True, 'bind': {'create_host_path': False}}]


def reserved(key):
    key = re.sub('[^a-z0-9]', '', key.lower())
    return 'nativewriter' in key or key.startswith('springconfig')


def validate_model(model, record):
    env, mounts = settings(record)
    need(model['services']['game-engine'].get('volumes', []) == mounts, 'engine config mount differs')
    for service, spec in model['services'].items():
        actual = {key: value for key, value in spec.get('environment', {}).items() if reserved(key)}
        need(actual == (env if service == 'game-engine' else {}), 'configuration escaped selection/service')
        for key, value in spec.get('environment', {}).items():
            if key not in env and isinstance(value, str):
                need('native-writer' not in value.lower() and 'native_writer' not in value.lower(), 'unowned native property override')
    if not env:
        return
    engine = model['services']['game-engine']['environment']
    need(engine.get('OPENSAMGUK_WORLD_ID') == '160' and engine.get('SERVER_ID') == record['serverId'] and
         engine.get('GAME_DATABASE_URL') == 'jdbc:postgresql://game-postgres:5432/game', 'engine world/database differs')
    need(model['services']['game-engine'].get('depends_on') ==
         {s: {'condition': 'service_healthy'} for s in ('game-postgres', 'game-redis')}, 'native bootstrap dependencies differ')


def verify_custody(directory, record, read_app, read_verifier):
    option = selected(record)
    path = directory / FILE
    if option is None:
        need(not path.exists() and not path.is_symlink(), 'unselected native config exists')
        return
    # Older custody revisions do not contain this helper. Refuse before any native SQL or service action.
    canonical = read_verifier(HELPER)
    need(sha(canonical) == option['harnessSha256'] and canonical == Path(__file__).read_bytes(), 'old/foreign native verifier')
    need(option['sourcePins'] == source_pins(read_app), 'native app source pins changed')
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'native config symlink')
    info = path.stat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid() and
         stat.S_IMODE(info.st_mode) == 0o644 and info.st_size == len(CONFIG), 'native config owner/mode/type differs')
    need(path.read_bytes() == CONFIG, 'native config bytes differ')


def validate_proof(payload, record):
    need(isinstance(payload, dict) and set(payload) == PROOF_FIELDS, 'proof fields differ')
    need(type(payload['worldCount']) is int and payload['worldCount'] == 1 and
         type(payload['worldId']) is int and payload['worldId'] == record['worldId'] == 160, 'proof world differs')
    epoch, previous, origin = (payload[key] for key in ('grantEpoch', 'previousEpoch', 'originEpoch'))
    need(all(type(value) is int for value in (epoch, previous, origin, payload['writerEpoch'])) and
         0 <= origin <= previous and epoch == previous + 1 and payload['writerEpoch'] == epoch, 'proof epoch/chain differs')
    grant = payload['grantId']
    try:
        need(isinstance(grant, str) and str(uuid.UUID(grant)) == grant and payload['requestId'] == grant, 'grant request identity differs')
    except (ValueError, AttributeError):
        raise Refused('Native writer: invalid grant identity') from None
    need(payload['leaseAlive'] is True and payload['handoverValid'] is True, 'lease or handover is unavailable')
    return dict(payload)


def verify_proof(payload, record, *, initial=False):
    option = selected(record)
    need(option is not None, 'unselected proof read')
    proof = validate_proof(payload, record)
    if initial:
        need(record.get('status') == 'STARTING' and option['proof'] is None, 'only an unbound fresh bootstrap may bind')
    else:
        need(option['proof'] is not None and proof == option['proof'], 'owned grant changed; preserve failure')
    return proof


def query(record):
    need(selected(record) is not None and type(record['worldId']) is int and record['worldId'] == 160, 'unselected proof query')
    # Stable read-only SQL functions validate the product's live lease and every adjacent handover edge.
    return """BEGIN READ ONLY;
      SELECT json_build_object('worldCount',(SELECT count(*) FROM world_state),
        'worldId',w.id,'writerEpoch',w.writer_epoch,'grantEpoch',g.epoch,'previousEpoch',g.previous_epoch,
        'originEpoch',h.origin_epoch,'grantId',g.grant_id::text,'requestId',g.request_id::text,
        'leaseAlive',native_writer_lease_alive(w.id,g.grant_id,g.epoch),
        'handoverValid',native_writer_binding_valid(w.id,h.origin_epoch,g.epoch,g.grant_id))
      FROM world_state w JOIN native_writer_current c ON c.world_id=w.id
      JOIN native_writer_grant g ON g.world_id=c.world_id AND g.grant_id=c.grant_id
      JOIN (SELECT world_id,min(previous_epoch) AS origin_epoch FROM native_writer_grant WHERE world_id=160 GROUP BY world_id) h ON h.world_id=w.id
      WHERE w.id=160; COMMIT;"""
