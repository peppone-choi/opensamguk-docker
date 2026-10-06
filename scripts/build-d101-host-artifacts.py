#!/usr/bin/env python3
"""Controlled local build only. This driver grants no install/operation authority."""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import struct
import subprocess
import tarfile
import time


class BuildUnavailable(Exception):
    pass


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def pin_regular(path, limit=None):
    before = path.lstat()
    if path.is_symlink() or not path.is_file() or before.st_nlink != 1:
        raise BuildUnavailable("input is not a pinned regular file")
    if limit is not None and (before.st_size <= 0 or before.st_size > limit):
        raise BuildUnavailable("input size unavailable")
    sha = digest(path)
    after = path.lstat()
    fields = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    if fields(before) != fields(after):
        raise BuildUnavailable("input changed during capture")
    return {"sha256": sha, "byteLength": after.st_size, "device": after.st_dev,
            "inode": after.st_ino, "modifiedAtNs": after.st_mtime_ns,
            "changedAtNs": after.st_ctime_ns}


def tree_pin(root):
    h = hashlib.sha256()
    count = total = 0
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise BuildUnavailable("toolchain/source tree symlink unavailable")
        if path.is_dir():
            continue
        count += 1
        if count > 100000:
            raise BuildUnavailable("tree file count exceeded")
        pin = pin_regular(path, 64 * 1024 * 1024)
        total += pin["byteLength"]
        if total > 1024 * 1024 * 1024:
            raise BuildUnavailable("tree byte budget exceeded")
        name = path.relative_to(root).as_posix().encode()
        h.update(struct.pack(">Q", len(name)))
        h.update(name)
        h.update(struct.pack(">Q", pin["byteLength"]))
        h.update(bytes.fromhex(pin["sha256"]))
    if count == 0:
        raise BuildUnavailable("empty toolchain/source tree")
    return {"sha256": h.hexdigest(), "files": count, "byteLength": total}


def require_source(value):
    if not re.fullmatch(r"[0-9a-f]{40}", value):
        raise BuildUnavailable("full source SHA required")


def require_hash(value):
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise BuildUnavailable("whole SHA256 required")


def absolute_existing(value, directory=False):
    path = Path(value)
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise BuildUnavailable("canonical absolute input required")
    if directory and not path.is_dir():
        raise BuildUnavailable("input directory unavailable")
    return path


def inspect_elf(path, architecture):
    machines = {"amd64": 62, "arm64": 183}
    if architecture not in machines:
        raise BuildUnavailable("actual approved architecture required")
    with path.open("rb") as stream:
        header = stream.read(64)
    if len(header) != 64 or header[:7] != b"\x7fELF\x02\x01\x01":
        raise BuildUnavailable("expected Linux ELF64 little endian artifact")
    if struct.unpack_from("<H", header, 16)[0] != 2 or struct.unpack_from("<H", header, 18)[0] != machines[architecture]:
        raise BuildUnavailable("artifact machine or executable kind mismatch")
    return {"class": 64, "endian": "little", "machine": machines[architecture]}


def capture_command(argv, cwd, env=None, timeout=30):
    p = subprocess.run(argv, cwd=cwd, env=env, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, timeout=timeout, check=False)
    if p.returncode:
        # Do not put command stderr, credentials, file bodies or host state in errors.
        raise BuildUnavailable("bounded command failed")
    return p.stdout


def safe_extract_module(archive, destination):
    total = 0
    with tarfile.open(archive, "r:") as stream:
        for member in stream.getmembers():
            name = PurePosixPath(member.name)
            if name.is_absolute() or ".." in name.parts:
                raise BuildUnavailable("archive path unavailable")
            if not name.parts or name.parts[0] != "deployer":
                continue
            if not member.isdir() and not member.isfile():
                raise BuildUnavailable("module archive link or special file rejected")
            target = destination.joinpath(*name.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            total += member.size
            if total > 128 * 1024 * 1024:
                raise BuildUnavailable("module source budget exceeded")
            target.parent.mkdir(parents=True, exist_ok=True)
            source = stream.extractfile(member)
            if source is None:
                raise BuildUnavailable("archive source unavailable")
            with source, target.open("xb") as output:
                shutil.copyfileobj(source, output)
            target.chmod(0o644)
    if not (destination / "deployer/go.mod").is_file():
        raise BuildUnavailable("module absent from clean source archive")


def save_new(path, value):
    wire = (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode()
    with path.open("xb") as stream:
        stream.write(wire)
        stream.flush()
        os.fsync(stream.fileno())


def validate_inputs(args):
    require_source(args.source)
    require_source(args.app_source)
    require_hash(args.host_arch_evidence_sha)
    require_hash(args.toolchain_sha)
    require_hash(args.toolchain_tree_sha)
    if args.host_arch not in ("amd64", "arm64") or not args.toolchain_version:
        raise BuildUnavailable("actual host architecture and toolchain version required")
    repo = absolute_existing(args.repo, directory=True)
    toolchain = absolute_existing(args.toolchain)
    evidence = absolute_existing(args.host_arch_evidence)
    tool_root = absolute_existing(args.toolchain_root, directory=True)
    if toolchain != tool_root / "bin/go":
        raise BuildUnavailable("pinned toolchain root must own bin/go")
    tool_pin, evidence_pin = pin_regular(toolchain), pin_regular(evidence, 256 * 1024)
    if tool_pin["sha256"] != args.toolchain_sha or evidence_pin["sha256"] != args.host_arch_evidence_sha:
        raise BuildUnavailable("independent input pin mismatch")
    # Evidence is retained by reference/hash; this driver does not interpret a
    # JSON PASS as host/approval authority or guess architecture from this Mac.
    if capture_command(["git", "rev-parse", "HEAD"], repo).decode().strip() != args.source:
        raise BuildUnavailable("source is not current reviewed head")
    if capture_command(["git", "status", "--porcelain", "--untracked-files=no"], repo).strip():
        raise BuildUnavailable("tracked source is dirty")
    tracked_driver = capture_command(["git", "show", args.source + ":scripts/build-d101-host-artifacts.py"], repo)
    if tracked_driver != Path(__file__).read_bytes():
        raise BuildUnavailable("driver differs from approved whole source")
    output = Path(args.out)
    if not output.is_absolute() or output.parent.resolve(strict=True) != output.parent or output.exists() or output.is_symlink():
        raise BuildUnavailable("new immutable output directory required")
    return repo, toolchain, evidence, output, tool_pin, evidence_pin, tool_root


def build(args):
    repo, toolchain, evidence, output, tool_pin, evidence_pin, tool_root = validate_inputs(args)
    # Exactly one mkdir owns this attempt. Failed outputs are retained; never
    # reuse/remove/overwrite a previous build directory or install artifacts.
    output.mkdir(mode=0o700)
    started = time.monotonic_ns()
    receipt = {"source": args.source, "appSource": args.app_source,
               "actualHostArchitecture": args.host_arch,
               "architectureEvidence": {"path": str(evidence), **evidence_pin},
               "toolchain": {"path": str(toolchain), **tool_pin},
               "driverSHA256": digest(Path(__file__)), "driverPID": os.getpid(),
               "startedMonotonicNs": started, "buildComplete": False,
               "installSignOperations": 0}
    save_new(output / "intent.json", receipt)
    try:
        work = output / "source"
        work.mkdir(mode=0o700)
        archive = output / "source.tar"
        with archive.open("xb") as stream:
            p = subprocess.run(["git", "archive", "--format=tar", args.source],
                               cwd=repo, stdout=stream, stderr=subprocess.PIPE,
                               timeout=30, check=False)
            stream.flush()
            os.fsync(stream.fileno())
        if p.returncode:
            raise BuildUnavailable("clean archive unavailable")
        receipt["archive"] = pin_regular(archive, 256 * 1024 * 1024)
        safe_extract_module(archive, work)
        module = work / "deployer"
        source_tree = tree_pin(module)
        actual_tool_tree = tree_pin(tool_root)
        if actual_tool_tree["sha256"] != args.toolchain_tree_sha:
            raise BuildUnavailable("whole toolchain tree pin mismatch")
        receipt["toolchainTree"] = actual_tool_tree
        receipt["moduleTree"] = source_tree
        env = {"PATH": "/usr/bin:/bin", "HOME": str(output), "LANG": "C",
               "GOOS": "linux", "GOARCH": args.host_arch, "CGO_ENABLED": "0",
               "GOTOOLCHAIN": "local", "GOPROXY": "off", "GOSUMDB": "off",
               "GOWORK": "off", "GOMAXPROCS": "2", "GOFLAGS": "", "GOROOT": str(tool_root),
               "GOCACHE": str(output / "gocache"), "GOMODCACHE": str(output / "gomodcache"),
               "GOTMPDIR": str(output / "tmp")}
        (output / "tmp").mkdir(mode=0o700)
        version = capture_command([str(toolchain), "version"], module, env).decode().strip()
        if version != args.toolchain_version:
            raise BuildUnavailable("toolchain version mismatch")
        receipt["toolchainVersion"] = version
        commands = []
        for name, package, flags in (("deployer", ".", "-s -w -X main.rootBuiltSourceSHA=" + args.source),
                                     ("d101-host-reader", "./cmd/d101-host-reader", "-s -w")):
            binary = output / name
            argv = [str(toolchain), "build", "-p=1", "-mod=readonly", "-trimpath", "-buildvcs=false",
                    "-ldflags=" + flags, "-o", str(binary), package]
            capture_command(argv, module, env, timeout=600)
            metadata = capture_command([str(toolchain), "version", "-m", str(binary)], module, env).decode()
            if "\tvcs." in metadata or "CGO_ENABLED=0" not in metadata or "GOOS=linux" not in metadata or "GOARCH=" + args.host_arch not in metadata:
                raise BuildUnavailable("artifact build metadata mismatch")
            if name == "deployer" and "main.rootBuiltSourceSHA=" + args.source not in metadata:
                raise BuildUnavailable("controlled deployer stamp flag absent")
            binary.chmod(0o500)
            receipt[name] = {**pin_regular(binary, 32 * 1024 * 1024),
                             "elf": inspect_elf(binary, args.host_arch), "goBuildMetadata": metadata,
                             "helperLinkerStampClaimed": False if name == "d101-host-reader" else None}
            commands.append(argv)
        launcher_wire = capture_command(["git", "show", args.source + ":scripts/d101-host-session-launcher.sh"], repo)
        launcher = output / "host-session-launcher"
        with launcher.open("xb") as stream:
            stream.write(launcher_wire)
            stream.flush()
            os.fsync(stream.fileno())
        capture_command(["/bin/bash", "-n", str(launcher)], output)
        launcher.chmod(0o500)
        receipt["launcher"] = pin_regular(launcher, 256 * 1024)
        if tree_pin(module) != source_tree or tree_pin(tool_root) != actual_tool_tree or pin_regular(archive, 256 * 1024 * 1024) != receipt["archive"]:
            raise BuildUnavailable("source archive or whole toolchain changed")
        if pin_regular(toolchain) != tool_pin or pin_regular(evidence, 256 * 1024) != evidence_pin:
            raise BuildUnavailable("actual independent inputs changed")
        if capture_command(["git", "rev-parse", "HEAD"], repo).decode().strip() != args.source or capture_command(["git", "status", "--porcelain", "--untracked-files=no"], repo).strip():
            raise BuildUnavailable("source changed during build")
        receipt.update(commands=commands, buildComplete=True,
                       endedMonotonicNs=time.monotonic_ns())
        save_new(output / "receipt.json", receipt)
        return 0
    except (BuildUnavailable, OSError, subprocess.SubprocessError, tarfile.TarError, UnicodeError):
        receipt.update(buildComplete=False, outcome="HOLD_RETAIN_PARTIAL_NO_RETRY",
                       endedMonotonicNs=time.monotonic_ns())
        save_new(output / "failure.json", receipt)
        return 2


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    for field in ("repo", "source", "app-source", "host-arch-evidence", "host-arch-evidence-sha",
                  "toolchain", "toolchain-sha", "toolchain-version", "toolchain-root", "toolchain-tree-sha", "out"):
        p.add_argument("--" + field, required=True)
    p.add_argument("--host-arch", required=True, choices=("amd64", "arm64"))
    return p


if __name__ == "__main__":
    try:
        raise SystemExit(build(parser().parse_args()))
    except (BuildUnavailable, OSError, subprocess.SubprocessError, UnicodeError):
        raise SystemExit(2)
