"""Fresh-stack collector contract. Pure validation; runtime I/O belongs to the harness."""
import datetime
import hashlib
import json
import re

ORIGIN = 'http://game-engine:8082'
BOOTSTRAP = ('game-postgres', 'game-redis', 'game-engine')
TIMING = {'poll-millis': 2000, 'deadline-millis': 1000, 'max-age-millis': 5000}
API = 'app/game-api/src/main/kotlin/opensamguk/gameapi/'
ENGINE = 'app/game-engine/src/main/kotlin/opensamguk/engine/'
# Pin the complete participating files and refuse sources without this explicit contract.
SOURCE = {
    API + 'config/EnginePauseObservationConfiguration.kt': (
        'prefix = "turn-daemon-observation", name = ["enabled"], havingValue = "true"',
        'worldId == processWorld.worldId.value',
        *('turn-daemon-observation.' + key for key in ('origin', 'server-id', 'world-id', 'tick-seconds', *TIMING))),
    API + 'read/EnginePauseObservationCollector.kt': (
        'rest.get().uri("/admin/turn-daemon/status")', 'HttpClient.Redirect.NEVER',
        'TurnDaemonProjection.observe(settings.serverId, settings.worldId',
        'val serverId = sourceClock?.get("serverId")', 'val tickSeconds = sourceClock?.get("tickSeconds")'),
    API + 'health/TurnLoopHealth.kt': ('collector.matchesWorld(world.id)', 'collector.project(now, executed, next, world.tickSeconds'),
    API + 'controller/ServerBasicInfoController.kt': ('world.findProcessWorld()', 'TurnLoopHealth.observe(w, observedAt, pauseCollector)'),
    API + 'read/WorldStateReadRepository.kt': ('raw.findById(worldId.value)',),
    API + 'config/GameApiProcessWorldIdConfiguration.kt': ('WorldId(configuredWorldId)', 'opensamguk.world-id'),
    'web/gateway/app/api/server-basic-info/[id]/route.ts': (
        'publicServerAccess(id)', 'resolveGameApiOrigin(id)', '${origin}/api/server-basic-info'),
    'web/gateway/lib/serverRegistry.ts': ('process.env.SERVER_REGISTRY_JSON', 'return getServer(id)?.gameApiUrl'),
    ENGINE + 'boot/WorldSnapshotLoader.kt': ('listOf(meta["serverId"], meta["server_id"])', 'WHERE world_id = ? AND server_id = ?'),
    ENGINE + 'run/TurnRunService.kt': ('worldId = state.id', 'serverId = state.serverId', 'tickSeconds = state.tickSeconds'),
    ENGINE + 'status/StatusController.kt': ('@RequestMapping("/admin/turn-daemon")', 'clock = diagnostics.clock', 'serverTime = observedAt.toString()'),
    'infra/src/main/kotlin/opensamguk/infra/seed/ScenarioImporter.kt': (
        'private val activeServerId = "opensamguk_${scenarioNumber}_${installTime.toEpochSecond()}"',
        "jsonb_build_object('serverId', ?, 'ngGameId', ?)", 'worldId.value, activeServerId'),
    'common/src/main/kotlin/opensamguk/common/turn/TurnDaemonObservation.kt': (
        'observation.serverId != serverId || observation.worldId != worldId',
        'ObservationState.EXPIRED', 'paused == null -> State.UNKNOWN'),
}


class Refused(ValueError):
    pass


def need(ok, message):
    if not ok:
        raise Refused('Engine observation: ' + message)


def decode(raw):
    need(isinstance(raw, (bytes, str)) and len(raw) <= 65536, 'response size/type differs')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, 'duplicate response field')
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=unique)
    except (ValueError, UnicodeDecodeError):
        raise Refused('Engine observation: invalid JSON response') from None


def source_pins(read):
    pins = {}
    for path, markers in SOURCE.items():
        data = read(path)
        need(isinstance(data, bytes) and all(marker.encode() in data for marker in markers), 'source contract unavailable')
        pins[path] = hashlib.sha256(data).hexdigest()
    return pins


def selected(record):
    value = record.get('engineObservation')
    if 'engineObservation' not in record:
        return None
    need(isinstance(value, dict) and set(value) == {'schema', 'sourcePins', 'binding'}, 'invalid selection')
    need(type(value['schema']) is int and value['schema'] == 1, 'schema differs')
    pins = value['sourcePins']
    need(isinstance(pins, dict) and set(pins) == set(SOURCE) and
         all(isinstance(v, str) and re.fullmatch('[a-f0-9]{64}', v) for v in pins.values()), 'source pins differ')
    binding = value['binding']
    if binding is not None:
        need(isinstance(binding, dict) and set(binding) == {'publicServerId', 'nativeServerId', 'worldId', 'tickSeconds'}, 'binding fields differ')
        need(binding['publicServerId'] == record['serverId'] and type(binding['worldId']) is int and
             binding['worldId'] == record['worldId'], 'public/world binding differs')
        need(isinstance(binding['nativeServerId'], str) and
             re.fullmatch('[A-Za-z0-9_-]{1,128}', binding['nativeServerId']), 'native SID unavailable')
        need(type(binding['tickSeconds']) is int and binding['tickSeconds'] > 0 and
             TIMING['max-age-millis'] < binding['tickSeconds'] * 3000, 'tick/freshness budget differs')
    return value


def environment(record):
    option = selected(record)
    if option is None or option['binding'] is None:
        return {}
    binding = option['binding']
    # Exact Spring property names avoid hyphen/underscore environment alias ambiguity.
    settings = {'enabled': True, 'origin': ORIGIN, 'server-id': binding['nativeServerId'],
                'world-id': binding['worldId'], 'tick-seconds': binding['tickSeconds'], **TIMING}
    return {'SPRING_APPLICATION_JSON': json.dumps({'turn-daemon-observation': settings}, sort_keys=True, separators=(',', ':'))}


def reserved(key):
    compact = re.sub('[^a-z0-9]', '', key.lower())
    return compact.startswith('turndaemonobservation') or compact == 'springapplicationjson'


def validate_model(model, record):
    option = selected(record)
    for service, spec in model['services'].items():
        actual = {k: v for k, v in spec.get('environment', {}).items() if reserved(k)}
        need(actual == (environment(record) if service == 'game-api' else {}), 'configuration escaped selection/service')
    if option is None:
        return
    api, engine = (model['services'][s] for s in ('game-api', 'game-engine'))
    for spec in (api, engine):
        env = spec['environment']
        need(env.get('OPENSAMGUK_WORLD_ID') == str(record['worldId']) and
             env.get('SERVER_ID') == record['serverId'] and env.get('SERVER_GENERATION') == str(record['generation']) and
             env.get('GAME_DATABASE_URL') == 'jdbc:postgresql://game-postgres:5432/game', 'process database/world/alias differs')
    need(engine.get('networks') == {'local': {'aliases': ['s' + record['serverId'] + '-game-engine']}} and
         api.get('networks') == {'local': {'aliases': ['s' + record['serverId'] + '-game-api']}}, 'owned endpoint aliases differ')
    need(engine.get('depends_on') == {s: {'condition': 'service_healthy'} for s in BOOTSTRAP[:2]}, 'bootstrap dependencies differ')
    tick = seed_tick(model)
    if option['binding'] is not None:
        need(option['binding']['tickSeconds'] == tick, 'generated tick differs from selected seed')


def seed_tick(model):
    value = model['services']['game-engine']['environment'].get('RESET_TURNTERM')
    need(isinstance(value, str) and re.fullmatch('[1-9][0-9]{0,4}', value), 'seed tick setting unavailable')
    tick = int(value) * 60
    need(TIMING['max-age-millis'] < tick * 3000, 'seed tick/freshness budget differs')
    return tick


def metadata(payload, record, tick):
    need(isinstance(payload, dict) and set(payload) == {'worldCount', 'worldId', 'tickSeconds', 'serverId', 'serverIdAlias', 'games'}, 'metadata fields differ')
    need(type(payload['worldCount']) is int and payload['worldCount'] == 1 and
         type(payload['worldId']) is int and payload['worldId'] == record['worldId'] and
         type(payload['tickSeconds']) is int and payload['tickSeconds'] == tick, 'metadata world/tick differs')
    sid = payload['serverId']
    need(isinstance(sid, str) and re.fullmatch('[A-Za-z0-9_-]{1,128}', sid) and
         payload['serverIdAlias'] in (None, sid), 'metadata native SID unavailable/conflicting')
    games = payload['games']
    need(isinstance(games, list) and len(games) == 1 and isinstance(games[0], dict) and
         set(games[0]) == {'worldId', 'serverId'} and type(games[0]['worldId']) is int and
         games[0] == {'worldId': record['worldId'], 'serverId': sid}, 'native ng_games binding differs')
    return {'publicServerId': record['serverId'], 'nativeServerId': sid,
            'worldId': payload['worldId'], 'tickSeconds': payload['tickSeconds']}


def instant(value):
    try:
        need(isinstance(value, str), 'timestamp unavailable')
        parsed = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
        need(parsed.tzinfo is not None, 'timestamp needs timezone')
        return parsed.timestamp()
    except (ValueError, OverflowError):
        raise Refused('Engine observation: invalid timestamp') from None


def validate_status(payload, binding, now):
    need(isinstance(payload, dict) and type(payload.get('paused')) is bool, 'pause gate unavailable')
    clock = payload.get('clock')
    need(isinstance(clock, dict) and clock.get('serverId') == binding['nativeServerId'] and
         type(clock.get('worldId')) is int and clock['worldId'] == binding['worldId'] and
         type(clock.get('tickSeconds')) is int and clock['tickSeconds'] == binding['tickSeconds'], 'clock identity/tick differs')
    age = now - instant(payload.get('serverTime'))
    need(0 <= age <= TIMING['max-age-millis'] / 1000, 'stale/future engine observation')


def bind(record, world, status, now, tick):
    option = selected(record)
    need(option is not None and option['binding'] is None, 'only an unbound fresh stack may bind')
    binding = metadata(world, record, tick)
    validate_status(status, binding, now)
    return {**option, 'binding': binding}


def validate_public(payload, binding, now):
    game = payload.get('game') if isinstance(payload, dict) else None
    need(isinstance(game, dict) and game.get('status') == 'OPEN' and
         type(game.get('turnTerm')) is int and game['turnTerm'] * 60 == binding['tickSeconds'], 'public process world/tick unavailable')
    loop = game.get('turnLoop')
    need(isinstance(loop, dict) and loop.get('observationState') == 'CURRENT' and
         type(loop.get('paused')) is bool and loop.get('state') in ('RUNNING', 'CATCHING_UP', 'WAITING', 'PAUSED', 'STALLED'),
         'public collector is unavailable')
    need((loop['state'] == 'PAUSED') == loop['paused'], 'public pause projection differs')
    source, received, server = (instant(value) for value in
                                (loop.get('sourceObservedAt'), loop.get('receivedAt'), game.get('serverTime')))
    need(source <= received <= server <= now and now - source <= TIMING['max-age-millis'] / 1000,
         'public observation stale/future')
