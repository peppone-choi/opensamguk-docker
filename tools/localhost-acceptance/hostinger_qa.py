"""Fresh-only Hostinger QA policy. No port discovery, deployment or budget overrides."""
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import sys
import time

ORIGIN = 'https://localhost:18443'
PORT = 18443
CGROUP = 'user-999.slice'
CGROOT = Path('/sys/fs/cgroup/user.slice/user-999.slice')
LOCKROOT = Path('/srv/hermes-workspace/projects/opensamguk/locks')
MIB = 1024**2
RESERVE = 256 * MIB
BUILD_MEMORY = 2048 * MIB
HELPER_MEMORY = 32 * MIB
# Keep canonical JVM/RAM settings: this intentionally cannot fit the present 4.23 GiB slice.
MEMORY = {'gateway-postgres': 384, 'game-postgres': 384, 'gateway-redis': 128,
          'game-redis': 128, 'gateway-api': 768, 'board-api': 512,
          'game-api': 1024, 'game-engine': 2048, 'web-gateway': 256,
          'web-game': 256, 'nginx': 128}
CPUS = {name: '0.1' for name in MEMORY}
CPUS.update({'game-engine': '0.3', 'game-api': '0.2'})


class Refused(RuntimeError):
    pass


def need(value, message):
    if not value:
        raise Refused(message)


def source_hash():
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def selection(task):
    need(isinstance(task, str) and re.fullmatch(r't_[a-f0-9]{8}', task), 'Exact Hostinger QA task ID required')
    return {'schema': 1, 'taskId': task, 'origin': ORIGIN, 'port': PORT,
            'cgroupParent': CGROUP, 'policySha256': source_hash()}


def selected(record):
    need({key for key in record if 'hostinger' in key.lower()} <= {'hostingerQA'},
         'Unknown Hostinger QA selection')
    if 'hostingerQA' not in record:
        return False
    option = record['hostingerQA']
    need(isinstance(option, dict) and type(option.get('schema')) is int and type(option.get('port')) is int and
         option == selection(option.get('taskId')),
         'Hostinger QA policy differs; no custody conversion')
    need(record.get('origin') == ORIGIN, 'Hostinger QA origin differs')
    return True


def project(record, recovery=False):
    if selected(record):
        return 'opensamguk-qa-' + record['hostingerQA']['taskId'] + ('-recovery-' if recovery else '-') + record['nonce']
    return ('osgfr' if recovery else 'osglha') + record['nonce']


def origin(record):
    if selected(record):
        return ORIGIN
    return 'https://localhost'


def port(record):
    return PORT if selected(record) else 443


def nginx(record, canonical):
    if not selected(record):
        return canonical
    host = b'    proxy_set_header Host $host;'
    redirect = b'https://$host$request_uri'
    need(canonical.count(host) == 1 and canonical.count(redirect) == 1, 'Canonical QA nginx shape differs')
    return canonical.replace(host, b'    proxy_set_header Host localhost:18443;\n    proxy_set_header X-Forwarded-Port 18443;').replace(redirect, b'https://localhost:18443$request_uri')


def apply(model, record):
    if not selected(record):
        return
    model['services']['nginx']['ports'][0]['published'] = str(PORT)
    for name, service in model['services'].items():
        service.update(cgroup_parent=CGROUP, cpus=CPUS[name], memswap_limit=service['mem_limit'])


def validate(model, record):
    if not selected(record):
        return
    need(set(model['services']) == set(MEMORY), 'Hostinger QA service set differs')
    for name, service in model['services'].items():
        need(service.get('cgroup_parent') == CGROUP and str(service.get('cpus')) == CPUS[name] and
             memory_bytes(service.get('mem_limit')) == MEMORY[name] * MIB and
             memory_bytes(service.get('memswap_limit')) == MEMORY[name] * MIB,
             'Hostinger QA container cap or parent differs')
        need(not set(service) & {'cpu_quota', 'cpu_period', 'cpuset', 'deploy', 'mem_reservation', 'cgroup',
                                'cpu_count', 'cpu_percent', 'cpu_shares', 'oom_kill_disable', 'oom_score_adj'},
             'Hostinger QA alternate resource override refused')
    need(sum(MEMORY.values()) * MIB == 6016 * MIB, 'Canonical aggregate memory changed')


def memory_bytes(value):
    if type(value) is int:
        return value
    if isinstance(value, str) and re.fullmatch(r'[1-9][0-9]*', value):
        return int(value)
    need(isinstance(value, str) and re.fullmatch(r'[1-9][0-9]*[mg]', value), 'Invalid QA memory cap')
    return int(value[:-1]) * {'m': MIB, 'g': 1024**3}[value[-1]]


def normalized(model, expected, record):
    validate(model, record)
    need(model['name'] == expected['name'], 'QA Compose normalized project differs')
    for service, spec in expected['services'].items():
        actual = model['services'][service]
        ports = actual.get('ports', [])
        need(all(p.get('mode', 'ingress') == 'ingress' for p in ports), 'QA Compose publish mode differs')
        ports = [{k: v for k, v in p.items() if k != 'mode'} for p in ports]
        need(actual.get('environment', {}) == spec.get('environment', {}) and ports == spec.get('ports', []),
             'QA Compose normalization changed origin/environment/port binding')


def runtime_cap(row, service):
    cap = row['HostConfig']
    need(cap.get('CgroupParent') == CGROUP and cap.get('Memory') == MEMORY[service] * MIB and
         cap.get('MemorySwap') == MEMORY[service] * MIB and
         cap.get('NanoCpus') == int(float(CPUS[service]) * 10**9), 'Runtime QA caps or cgroup differ')


def free_port():
    # High unprivileged port: permission errors are refusal, never fallback to a connect probe.
    try:
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', PORT))
    except OSError:
        raise Refused('Loopback 18443 unavailable; existing listener preserved; no fallback') from None


def evaluate(cap, cpu_micros, snapshots, host_available):
    need(type(cap) is int and cap > 0 and type(cpu_micros) is int and cpu_micros > 0,
         'Invalid QA admission request')
    need(snapshots and type(host_available) is int and host_available >= 0, 'Missing QA capacity evidence')
    required = cap + RESERVE
    report = {'requestedBytes': cap, 'reserveBytes': RESERVE, 'requiredFreeBytes': required,
              'hostAvailableBytes': host_available, 'cgroups': []}
    for sample in snapshots:
        current, inactive, ceiling, cpu = (sample[k] for k in ('current', 'inactiveFile', 'ceiling', 'cpuMicros'))
        need(all(type(v) is int and v >= 0 for v in (current, inactive, ceiling, cpu)) and inactive <= current,
             'Invalid cgroup capacity evidence')
        nonreclaimable = current - inactive
        free = max(0, ceiling - nonreclaimable)
        minimum = nonreclaimable + required
        report['cgroups'].append({'nonreclaimableBytes': nonreclaimable, 'availableBytes': free,
                                 'ceilingBytes': ceiling, 'minimumCeilingBytes': minimum})
        need(required <= free and cpu_micros + 100000 <= cpu,
             f'QA budget REFUSED: requiredFreeBytes={required}, availableBytes={free}, '
             f'minimumCeilingBytes={minimum}, ceilingBytes={ceiling}, '
             f'requestedCpuMicros={cpu_micros}, cpuReserveMicros=100000, ceilingCpuMicros={cpu}')
    need(required <= host_available,
         f'QA host memory REFUSED: requiredFreeBytes={required}, hostAvailableBytes={host_available}')
    return report


def admission(record, phase):
    need(selected(record) and sys.platform == 'linux', 'Hostinger QA requires Linux cgroup v2')
    need(phase in ('build', 'startup', 'helper'), 'Unknown QA resource phase')
    cap = BUILD_MEMORY if phase == 'build' else sum(MEMORY.values()) * MIB + (HELPER_MEMORY if phase == 'helper' else 0)
    cpu = 1000000 if phase == 'build' else sum(int(float(v) * 1000000) for v in CPUS.values()) + (100000 if phase == 'helper' else 0)
    snapshots = []
    # Every finite ancestor matters, not just Docker host capacity or the immediate slice.
    need(CGROOT.is_dir() and (CGROOT / 'cgroup.controllers').is_file(), 'Managed QA cgroup unavailable')
    roots = (CGROOT, CGROOT.parent, CGROOT.parent.parent)
    quotas = []
    for root in roots:
        if (root / 'cpu.max').exists():
            quota, period = (root / 'cpu.max').read_text().split()
            need(int(period) > 0, 'Invalid managed QA CPU period')
            if quota != 'max':
                quotas.append(int(quota) * 1000000 // int(period))
    need(quotas and (CGROOT / 'cpu.max').read_text().split()[0] != 'max', 'Finite managed QA CPU quota required')
    for root in roots:
        maximum = (root / 'memory.max').read_text().strip() if (root / 'memory.max').exists() else 'max'
        high = (root / 'memory.high').read_text().strip() if (root / 'memory.high').exists() else 'max'
        ceilings = [int(v) for v in (maximum, high) if v != 'max']
        if not ceilings:
            continue
        values = dict(line.split() for line in (root / 'memory.stat').read_text().splitlines())
        snapshots.append({'current': int((root / 'memory.current').read_text()),
                          'inactiveFile': int(values['inactive_file']), 'ceiling': min(ceilings),
                          'cpuMicros': min(quotas)})
    host = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
    return evaluate(cap, cpu, snapshots, int(host['MemAvailable'].split()[0]) * 1024)


@contextlib.contextmanager
def lock(name, timeout=0):
    need(name in ('host-heavy.lock', 'browser.lock'), 'Unknown QA lock')
    fd = os.open(LOCKROOT / name, os.O_RDWR | os.O_NOFOLLOW)
    try:
        need(stat.S_ISREG(os.fstat(fd).st_mode), 'QA shared lock is not a regular file')
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise Refused('Shared QA lock busy; foreign workload preserved') from None
                time.sleep(0.5)
        yield
    finally:
        os.close(fd)


def helper_args(record):
    if not selected(record):
        return []
    admission(record, 'helper')
    return ['--cgroup-parent', CGROUP, '--memory', '32m', '--memory-swap', '32m', '--cpus', '0.1']


@contextlib.contextmanager
def helper(record, run):
    if not selected(record):
        yield []
        return
    token = secrets.token_hex(16)
    name = record['project'] + '-helper-' + token
    label = 'org.opensamguk.qa.helper'
    ownership = {label: token, 'org.opensamguk.local.nonce': record['nonce'],
                 'org.opensamguk.local.session': record['session'], 'com.docker.compose.project': record['project']}
    need(not run(['docker', 'ps', '-aq', '--filter', 'name=^/' + name + '$']).strip(), 'QA helper name already exists')
    args = helper_args(record) + ['--name', name]
    for key, value in ownership.items():
        args += ['--label', key + '=' + value]
    try:
        yield args
    finally:
        query = ['docker', 'ps', '-aq', '--no-trunc', '--filter', 'label=' + label + '=' + token]
        ids = run(query).decode().split()
        for cid in ids:
            need(re.fullmatch('[a-f0-9]{64}', cid), 'Invalid QA helper cleanup identity')
            row = json.loads(run(['docker', 'inspect', '--format',
                '{"Id":{{json .Id}},"Name":{{json .Name}},"Labels":{{json .Config.Labels}}}', cid]))
            need(row.get('Id') == cid and row.get('Name') == '/' + name and
                 all(row.get('Labels', {}).get(k) == v for k, v in ownership.items()),
                 'Foreign helper cleanup candidate preserved')
            run(['docker', 'container', 'rm', '-f', cid])
        need(not run(query).strip(), 'QA helper cleanup incomplete')
