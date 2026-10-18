"""Private, bounded manifests. Archive contents never become public output."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile
import secrets


class Refused(RuntimeError):
    pass


def need(ok, code):
    if not ok:
        raise Refused(code)


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def private(path, directory=False):
    path = Path(path).absolute()
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'SYMLINK')
    s = path.stat()
    need(s.st_uid == os.getuid() and not s.st_mode & 0o077, 'PRIVATE_OWNER_MODE')
    need(stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode), 'FILE_TYPE')
    need(directory or s.st_nlink == 1, 'HARDLINK')
    return path


def newdir(path):
    path = Path(path).absolute()
    need(not path.exists() and not path.is_symlink(), 'OUTPUT_EXISTS')
    need(not any(p.is_symlink() for p in path.parents), 'SYMLINK')
    path.mkdir(mode=0o700)
    return path


def put(path, content, replace=False):
    path = Path(path)
    if replace:
        private(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | (os.O_TRUNC if replace else os.O_EXCL)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(content)
        f.flush()
        os.fsync(f.fileno())


def write(path, value, replace=False):
    path = Path(path)
    content = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    if not replace:
        put(path, content)
        return
    private(path)
    temporary = path.with_name('.' + path.name + '-' + secrets.token_hex(8))
    put(temporary, content)
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def read(path):
    path = private(path)
    need(path.stat().st_size <= 4 * 1024 * 1024, 'JSON_TOO_LARGE')
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'DUPLICATE_KEY')
            result[key] = value
        return result
    return json.loads(path.read_bytes(), object_pairs_hook=pairs)


def safe_name(name):
    need(isinstance(name, str) and name and '\\' not in name, 'ARCHIVE_PATH')
    p = PurePosixPath(name)
    need(not p.is_absolute() and '..' not in p.parts, 'ARCHIVE_PATH')
    return p.as_posix().removeprefix('./')


def archive_root(path):
    """Validate every entry before extraction; compare content/ownership, not tar ordering."""
    entries = {}
    with tarfile.open(private(path), mode='r|*') as archive:
        for item in archive:
            name = safe_name(item.name)
            need(item.isfile() or item.isdir(), 'ARCHIVE_LINK_OR_SPECIAL')
            need(not item.mode & 0o7000, 'ARCHIVE_PRIVILEGED_MODE')
            need(name not in entries, 'ARCHIVE_DUPLICATE')
            h = hashlib.sha256()
            if item.isfile():
                source = archive.extractfile(item)
                need(source is not None, 'ARCHIVE_CONTENT')
                for block in iter(lambda: source.read(1024 * 1024), b''):
                    h.update(block)
            entries[name] = [item.isdir(), item.size, item.mode, item.uid, item.gid, h.hexdigest()]
    need(bool(entries), 'EMPTY_ARCHIVE')
    return hashlib.sha256(json.dumps(entries, sort_keys=True).encode()).hexdigest()


def seal(directory):
    files = {}
    for path in sorted(Path(directory).rglob('*')):
        need(not path.is_symlink(), 'SYMLINK')
        if path.is_file() and path.relative_to(directory).as_posix() not in ('manifest.json', 'journal.json'):
            private(path)
            files[str(path.relative_to(directory))] = {'sha256': digest(path), 'size': path.stat().st_size}
        elif path.is_dir():
            private(path, True)
    return files


def verify_bundle(directory):
    directory = private(directory, True)
    m = read(directory / 'manifest.json')
    need(m.get('schema') == 1 and m.get('status') == 'BACKUP_COMPLETE', 'INCOMPLETE_BACKUP')
    need(m.get('files') == seal(directory), 'BUNDLE_CHANGED')
    need(set(m.get('volumes', {})) == {'gateway-pgdata', 'game-pgdata',
         'gateway-redisdata', 'game-redisdata', 'profile-icons'}, 'MISSING_VOLUME')
    for name, expected in m['volumes'].items():
        need(archive_root(directory / ('data/' + name + '.tar')) == expected, 'VOLUME_CONTENT_CHANGED')
    archive_root(directory / 'images.tar')
    return m
