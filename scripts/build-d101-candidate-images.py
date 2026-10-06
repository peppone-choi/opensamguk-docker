#!/usr/bin/env python3
"""Package controlled D101 artifacts into candidates; never install or deploy.

The reviewed contract hashes raw JSON, original nonsecret x86_64 observation,
Go binary/tree, existing driver/launcher/Dockerfiles and an immutable runtime
base. BuildKit attests packaging only; the controlled Go receipt attests the
separate binary build. A filesystem-only hosted probe is created, never started
or deleted by this driver. No host launcher/helper mount is installed.
"""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import urllib.parse
import urllib.request

ROOT_REPO = "peppone-choi/opensamguk-docker"
APP_REPO = "peppone-choi/opensamguk"
SOURCE_URL = "https://github.com/" + ROOT_REPO
REGISTRY = "ghcr.io/" + APP_REPO
WORKFLOW = ".github/workflows/build-d101-candidate-images.yml"
TOOL = "scripts/build-d101-candidate-images.py"
HOST_DRIVER = "scripts/build-d101-host-artifacts.py"
LAUNCHER = "scripts/d101-host-session-launcher.sh"
PLATFORM = "linux/amd64"
SHA40 = re.compile(r"[0-9a-f]{40}")
SHA64 = re.compile(r"[0-9a-f]{64}")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
CONTRACT_KEYS = {
    "schema", "go_release", "go_version", "go_binary_sha256", "go_tree_sha256",
    "host_arch", "host_arch_evidence_b64", "host_arch_evidence_sha256",
    "host_driver_sha256", "launcher_sha256", "deployer_dockerfile_sha256",
    "host_reader_dockerfile_sha256", "runtime_base",
}
HASH_KEYS = {key for key in CONTRACT_KEYS if key.endswith("_sha256")}
ARTIFACTS = {
    "deployer": {"receipt": "deployer", "limit": 32 * 1024 * 1024},
    "d101-host-reader": {"receipt": "d101-host-reader", "limit": 32 * 1024 * 1024},
    "host-session-launcher": {"receipt": "launcher", "limit": 256 * 1024},
}
IMAGE_PATHS = {
    "root-deployer": {
        "deployer": "/usr/local/bin/deployer",
        "d101-host-reader": "/opt/opensamguk-candidate-artifacts/d101-host-reader",
        "host-session-launcher": "/opt/opensamguk-candidate-artifacts/host-session-launcher",
    },
    "root-host-artifacts": {name: "/" + name for name in ARTIFACTS},
}
METADATA_KEY = "https://mobyproject.org/buildkit@v1#metadata"


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def file_sha(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def save_new(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def safe_env():
    # The source checkout's .env is never read. Registry login uses the workflow
    # token in its separate action; Docker reads only hosted-runner credentials.
    result = {key: value for key, value in os.environ.items()
              if key not in ("GH_TOKEN", "GITHUB_TOKEN", "DOCKER_HOST", "DOCKER_CONTEXT")}
    result.update(BUILDX_METADATA_PROVENANCE="max", BUILDX_GIT_INFO="false", BUILDX_GIT_CHECK_DIRTY="false")
    return result


def command(argv, cwd=None, timeout=60):
    result = subprocess.run(argv, cwd=cwd, env=safe_env(), stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout)
    require(result.returncode == 0, "bounded candidate command failed: " + argv[0])
    return result.stdout


def git(root, *args):
    return command(["git", "-C", str(root), *args])


def fingerprint(root):
    return sha(git(root, "ls-tree", "-rz", "--full-tree", "--abbrev=40", "HEAD"))


def validate_contract(raw, expected_sha):
    require(isinstance(raw, str) and len(raw.encode()) <= 48000,
            "reviewed contract JSON absent or oversized")
    require(isinstance(expected_sha, str) and bool(SHA64.fullmatch(expected_sha)) and sha(raw.encode()) == expected_sha,
            "reviewed contract raw SHA256 mismatch")
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate contract key")
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=unique_pairs)
    require(isinstance(value, dict) and set(value) == CONTRACT_KEYS,
            "unknown or missing reviewed contract field")
    require(all(isinstance(x, str) for x in value.values()), "contract fields must be strings")
    require(value["schema"] == "d101-candidate-build-contract/v1", "contract version mismatch")
    for key in HASH_KEYS:
        require(bool(SHA64.fullmatch(value[key])), "contract pin must be lowercase full64")
    require(bool(re.fullmatch(r"1\.23\.(0|[1-9][0-9]*)", value["go_release"])),
            "reviewed Go1.23 exact patch required")
    require(value["go_version"] == "go version go" + value["go_release"] + " linux/amd64",
            "reviewed Go version/platform mismatch")
    require(value["host_arch"] == "amd64", "approved host architecture must be amd64")
    evidence = base64.b64decode(value["host_arch_evidence_b64"], validate=True)
    # Accept only the approved original uname architecture observation, never
    # private native leaves, keys, host sessions or an inferred JSON PASS.
    require(evidence in (b"x86_64", b"x86_64\n"), "original nonsecret architecture wire required")
    require(sha(evidence) == value["host_arch_evidence_sha256"], "host observation pin mismatch")
    require(bool(re.fullmatch(r"docker:27-cli@sha256:[0-9a-f]{64}", value["runtime_base"])),
            "reviewed docker27-cli immutable platform digest required")
    return value, evidence


def runtime_contract(source):
    def instructions(path):
        return [line.strip() for line in (source / path).read_text().splitlines()
                if line.strip() and not line.lstrip().startswith("#")]
    runtime = instructions("deployer/Dockerfile")
    index = max(i for i, line in enumerate(runtime) if line.startswith("FROM "))
    require(runtime[index:] == [
        "FROM docker:27-cli", "RUN apk add --no-cache bash curl python3",
        "COPY --from=build /out/deployer /usr/local/bin/deployer", "WORKDIR /workspace",
        "USER 0:0", "EXPOSE 9000", 'ENTRYPOINT ["/usr/local/bin/deployer"]',
    ], "existing runtime contract changed; request exact owner hunk before adapting")
    helper = instructions("deployer/Dockerfile.host-reader")
    index = max(i for i, line in enumerate(helper) if line.startswith("FROM "))
    require(helper[index:] == ["FROM scratch AS host-reader-artifact",
                              "COPY --from=build /out/d101-host-reader /d101-host-reader"],
            "existing helper artifact role changed")
    require(instructions("deployer/go.mod") == ["module opensamguk-deployer", "go 1.23"],
            "controlled Go module is no longer external-dependency-free Go1.23")


def main_sha(repo):
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    token = os.environ.get("GH_TOKEN", "")
    require(bool(token), "readonly main observation token absent")
    req = urllib.request.Request("https://api.github.com/repos/" + repo + "/git/ref/heads/main",
        headers={"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "d101-candidate-issuer"})
    with urllib.request.build_opener(NoRedirect).open(req, timeout=20) as response:
        raw = response.read(65537)
    require(len(raw) <= 65536, "main observation oversized")
    value = json.loads(raw)
    require(value.get("ref") == "refs/heads/main" and value.get("object", {}).get("type") == "commit",
            "main observation is not a commit")
    actual = value["object"]["sha"]
    require(bool(SHA40.fullmatch(actual)), "main observation SHA invalid")
    return actual


def shape(args):
    for value in (args.source_sha, args.issuer_sha, args.app_source_sha):
        require(isinstance(value, str) and bool(SHA40.fullmatch(value)), "sources must be lowercase full40")
    require(isinstance(args.fingerprint, str) and bool(SHA64.fullmatch(args.fingerprint)),
            "reviewed tracked NUL fingerprint must be full64")
    require(os.environ.get("GITHUB_REPOSITORY") == ROOT_REPO and
            os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch", "manual Root repository mismatch")
    require(os.environ.get("ACTUAL_WORKFLOW_SHA") == args.issuer_sha, "workflow issuer mismatch")
    require(isinstance(args.issuer_ref, str) and bool(re.fullmatch(r"refs/(heads|tags)/[A-Za-z0-9][A-Za-z0-9._/-]*", args.issuer_ref)) and
            not any(x in args.issuer_ref for x in ("..", "//")) and not args.issuer_ref.endswith(("/", ".", ".lock")) and
            os.environ.get("GITHUB_REF") == args.issuer_ref, "reviewed issuer ref differs from actual dispatch ref")
    require(os.environ.get("GITHUB_RUN_ATTEMPT") == "1" and
            bool(re.fullmatch(r"[1-9][0-9]*", os.environ.get("GITHUB_RUN_ID", ""))),
            "first attempt and actual run ID required")
    require(os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted" and
            os.environ.get("RUNNER_OS") == "Linux" and os.environ.get("RUNNER_ARCH") == "X64",
            "candidate runner must be hosted Linux x64; no local or production Docker")


def validate_inputs(args):
    shape(args)
    contract, evidence = validate_contract(os.environ.get("APPROVED_BUILD_CONTRACT_JSON", ""),
                                           args.contract_sha256)
    source, issuer = args.source.resolve(strict=True), args.issuer.resolve(strict=True)
    require(source.is_dir() and issuer.is_dir(), "source or issuer checkout absent")
    require(git(source, "rev-parse", "HEAD").decode().strip() == args.source_sha and
            git(issuer, "rev-parse", "HEAD").decode().strip() == args.issuer_sha, "checkout pin mismatch")
    require(Path(__file__).resolve() == issuer / TOOL, "issuer tool path mismatch")
    for path in (TOOL, WORKFLOW):
        require((issuer / path).read_bytes() == git(issuer, "show", args.issuer_sha + ":" + path),
                "issuer bytes differ from immutable source")
    require(not git(source, "status", "--porcelain", "--untracked-files=all"), "source checkout is dirty")
    require(fingerprint(source) == args.fingerprint, "reviewed source fingerprint mismatch")
    for field, path in (("host_driver_sha256", HOST_DRIVER), ("launcher_sha256", LAUNCHER),
                        ("deployer_dockerfile_sha256", "deployer/Dockerfile"),
                        ("host_reader_dockerfile_sha256", "deployer/Dockerfile.host-reader")):
        require(file_sha(source / path) == contract[field], "existing approved input changed")
    runtime_contract(source)
    require(main_sha(ROOT_REPO) == args.source_sha and main_sha(APP_REPO) == args.app_source_sha,
            "current Root/App main differs from approved source")
    return source, issuer, contract, evidence


def plan(args, source, contract):
    run_id, attempt = os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_RUN_ATTEMPT"]
    return {"schema": "d101-candidate-images/v1", "root_source": args.source_sha,
            "issuer_source": args.issuer_sha, "issuer_ref": args.issuer_ref, "app_source": args.app_source_sha,
            "tracked_fingerprint64": args.fingerprint, "build_contract_sha256": args.contract_sha256,
            "run_id": run_id, "attempt": attempt, "platform": PLATFORM,
            "registry": REGISTRY, "runtime_base": contract["runtime_base"],
            "tags": {name: f"{REGISTRY}:{name}-candidate-{args.source_sha}-{run_id}-{attempt}"
                     for name in IMAGE_PATHS},
            "host_installation_authorized": False, "launcher_executed": False,
            "runtime_workflow_or_latest_promotion": False}


def inspect(reference, field, output, filename):
    raw = command(["docker", "buildx", "imagetools", "inspect", reference,
                   "--format", "{{json ." + field + "}}"], timeout=120)
    (output / filename).write_bytes(raw)
    return json.loads(raw)


def regular_pin(path, limit):
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= limit,
            "artifact must be a bounded single-link regular file")
    digest = file_sha(path)
    after = path.lstat()
    fields = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    require(fields(before) == fields(after), "artifact changed during pinning")
    return {"sha256": digest, "byteLength": before.st_size, "mode": stat.S_IMODE(before.st_mode)}


def controlled_artifacts(source, output, contract, arch_wire, args):
    evidence = output / "host-architecture.raw"
    evidence.write_bytes(arch_wire)
    go_root_wire = command(["go", "env", "GOROOT"], timeout=30)
    go_root = Path(go_root_wire.decode().strip()).resolve(strict=True)
    go = go_root / "bin/go"
    require(file_sha(go) == contract["go_binary_sha256"], "actual Go binary differs from reviewed pin")
    require(command([str(go), "version"]).decode().strip() == contract["go_version"],
            "actual Go version differs from reviewed version")
    dest = output / "controlled-artifacts"
    argv = [sys.executable, str(source / HOST_DRIVER), "--repo", str(source),
            "--source", args.source_sha, "--app-source", args.app_source_sha,
            "--host-arch-evidence", str(evidence), "--host-arch-evidence-sha",
            contract["host_arch_evidence_sha256"], "--host-arch", "amd64",
            "--toolchain", str(go), "--toolchain-sha", contract["go_binary_sha256"],
            "--toolchain-version", contract["go_version"], "--toolchain-root", str(go_root),
            "--toolchain-tree-sha", contract["go_tree_sha256"], "--out", str(dest)]
    save_new(output / "controlled-build-invocation.json", {"argv": argv, "driver_sha256": file_sha(source / HOST_DRIVER)})
    command(argv, cwd=source, timeout=1500)
    receipt_path = dest / "receipt.json"
    receipt = json.loads(receipt_path.read_bytes())
    require(receipt.get("buildComplete") is True and receipt.get("source") == args.source_sha and
            receipt.get("appSource") == args.app_source_sha and receipt.get("actualHostArchitecture") == "amd64" and
            receipt.get("driverSHA256") == contract["host_driver_sha256"] and
            receipt.get("toolchain", {}).get("sha256") == contract["go_binary_sha256"] and
            receipt.get("toolchainTree", {}).get("sha256") == contract["go_tree_sha256"] and
            receipt.get("toolchainVersion") == contract["go_version"] and receipt.get("installSignOperations") == 0 and
            receipt.get("architectureEvidence", {}).get("sha256") == contract["host_arch_evidence_sha256"],
            "controlled build receipt differs from reviewed source/toolchain/architecture")
    pins = {}
    for name, spec in ARTIFACTS.items():
        pin = regular_pin(dest / name, spec["limit"])
        claimed = receipt.get(spec["receipt"], {})
        require(pin["sha256"] == claimed.get("sha256") and pin["byteLength"] == claimed.get("byteLength") and
                pin["mode"] == 0o500, "controlled artifact bytes/mode mismatch")
        if name != "host-session-launcher":
            metadata = claimed.get("goBuildMetadata", "")
            require("GOOS=linux" in metadata and "GOARCH=amd64" in metadata and "CGO_ENABLED=0" in metadata and
                    claimed.get("elf", {}).get("machine") == 62, "controlled ELF platform/Go metadata mismatch")
            if name == "deployer":
                require("main.rootBuiltSourceSHA=" + args.source_sha in metadata, "controlled deployer source stamp absent")
        else:
            require(pin["sha256"] == contract["launcher_sha256"], "launcher differs from approved source")
        pins[name] = pin
    return dest, pins, {"path": str(receipt_path), "sha256": file_sha(receipt_path)}, go


def recipe(name, runtime_base):
    require(name in IMAGE_PATHS, "unknown image selector")
    require(bool(re.fullmatch(r"docker:27-cli@sha256:[0-9a-f]{64}", runtime_base)), "runtime base is not immutable")
    if name == "root-deployer":
        return (f"FROM {runtime_base}\n"
                "RUN apk add --no-cache bash curl python3\n"
                "COPY --chmod=0500 deployer /usr/local/bin/deployer\n"
                "COPY --chmod=0500 d101-host-reader /opt/opensamguk-candidate-artifacts/d101-host-reader\n"
                "COPY --chmod=0500 host-session-launcher /opt/opensamguk-candidate-artifacts/host-session-launcher\n"
                "WORKDIR /workspace\nUSER 0:0\nEXPOSE 9000\n"
                'ENTRYPOINT ["/usr/local/bin/deployer"]\n')
    return ("FROM scratch\nCOPY --chmod=0500 deployer /deployer\n"
            "COPY --chmod=0500 d101-host-reader /d101-host-reader\n"
            "COPY --chmod=0500 host-session-launcher /host-session-launcher\n")


def base_readback(contract, output):
    reference = contract["runtime_base"]
    expected = reference.rsplit("@", 1)[1]
    manifest = inspect(reference, "Manifest", output, "runtime-base-manifest.json")
    raw = command(["docker", "buildx", "imagetools", "inspect", reference, "--raw"], timeout=120)
    (output / "runtime-base-manifest.raw.json").write_bytes(raw)
    require("sha256:" + sha(raw) == expected, "runtime base original manifest SHA mismatch")
    require(manifest.get("digest") == expected and manifest.get("mediaType") in
            ("application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"),
            "runtime base must be the approved platform manifest, not an index or config ID")
    image = inspect(reference, "Image", output, "runtime-base-image.json")
    require(image.get("os") == "linux" and image.get("architecture") == "amd64", "runtime base platform mismatch")


def read_registry_config_blob(config_digest, size):
    """Read one immutable GHCR config blob; never pull layers or log auth."""
    require(isinstance(config_digest, str) and bool(DIGEST.fullmatch(config_digest)) and
            type(size) is int and 0 < size <= 16 * 1024 * 1024, "config blob request invalid")
    registry = REGISTRY
    require(registry.startswith("ghcr.io/") and
            bool(re.fullmatch(r"[a-z0-9._-]+/[a-z0-9._-]+", registry[8:])),
            "config registry repository invalid")
    repository = registry[8:]
    actor, credential = os.environ.get("GITHUB_ACTOR", ""), os.environ.get("GH_TOKEN", "")
    require(bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]*", actor)) and bool(credential) and
            "\r" not in credential and "\n" not in credential, "registry read credential absent")

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            raise ValueError("registry token redirect rejected")

    class BlobRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            parsed = urllib.parse.urlsplit(newurl)
            host = parsed.hostname or ""
            hops = getattr(req, "config_redirect_hops", 0) + 1
            require(parsed.scheme == "https" and not parsed.username and not parsed.password and
                    parsed.port in (None, 443) and hops <= 3 and
                    (host == "ghcr.io" or host.endswith(".githubusercontent.com") or
                     host.endswith(".blob.core.windows.net")), "config redirect rejected")
            forwarded = {key: value for key, value in req.header_items()
                         if key.lower() not in ("authorization", "host")}
            if host == "ghcr.io" and urllib.parse.urlsplit(req.full_url).hostname == host:
                authorization = req.get_header("Authorization")
                if authorization:
                    forwarded["Authorization"] = authorization
            redirected = urllib.request.Request(newurl, headers=forwarded, method="GET")
            redirected.config_redirect_hops = hops
            return redirected

    try:
        query = urllib.parse.urlencode({"service": "ghcr.io", "scope": "repository:" + repository + ":pull"})
        basic = base64.b64encode((actor + ":" + credential).encode()).decode()
        request = urllib.request.Request("https://ghcr.io/token?" + query, headers={
            "Authorization": "Basic " + basic, "Accept-Encoding": "identity",
            "User-Agent": "pinned-candidate-config-read"})
        with urllib.request.build_opener(NoRedirect).open(request, timeout=20) as response:
            require(response.status == 200, "registry token response rejected")
            wire = response.read(65537)
        require(len(wire) <= 65536, "registry token response oversized")
        value = json.loads(wire)
        require(isinstance(value, dict), "registry token response malformed")
        token = value.get("token") or value.get("access_token")
        require(isinstance(token, str) and bool(token) and "\r" not in token and "\n" not in token,
                "registry scoped token absent")
        request = urllib.request.Request("https://ghcr.io/v2/" + repository + "/blobs/" + config_digest,
            headers={"Authorization": "Bearer " + token, "Accept": "application/octet-stream",
                     "Accept-Encoding": "identity", "User-Agent": "pinned-candidate-config-read"})
        with urllib.request.build_opener(BlobRedirect).open(request, timeout=120) as response:
            require(response.status == 200, "registry config response rejected")
            return response.read(size + 1)
    except Exception:
        # Do not disclose token endpoint responses, auth headers or signed URLs.
        raise ValueError("bounded registry config read failed") from None


def verified_image_config(metadata, manifest, read_blob=None):
    """Bind original config bytes to the already SHA-verified platform manifest."""
    require(isinstance(manifest, dict) and
            manifest.get("mediaType") == "application/vnd.oci.image.manifest.v1+json",
            "config platform manifest malformed")
    descriptor = manifest.get("config")
    require(isinstance(descriptor, dict), "config descriptor absent")
    config_digest, size = descriptor.get("digest"), descriptor.get("size")
    require(isinstance(config_digest, str) and bool(DIGEST.fullmatch(config_digest)) and
            descriptor.get("mediaType") == "application/vnd.oci.image.config.v1+json" and
            type(size) is int and 0 < size <= 16 * 1024 * 1024, "config descriptor invalid")
    require(isinstance(metadata, dict), "build metadata malformed")
    if "containerimage.config.digest" in metadata:
        supplied = metadata["containerimage.config.digest"]
        require(isinstance(supplied, str) and bool(DIGEST.fullmatch(supplied)) and
                supplied == config_digest, "metadata config binding mismatch")
    raw = (read_blob or read_registry_config_blob)(config_digest, size)
    require(isinstance(raw, bytes) and len(raw) == size and
            "sha256:" + hashlib.sha256(raw).hexdigest() == config_digest, "config raw bytes mismatch")
    config = json.loads(raw)
    require(isinstance(config, dict) and isinstance(config.get("config"), dict), "config payload malformed")
    return config_digest, config, raw


def verify_packaging(name, metadata, record, packaging, output):
    index_digest = metadata.get("containerimage.digest", "")
    require(bool(DIGEST.fullmatch(index_digest)), "candidate index digest missing")
    index_ref = REGISTRY + "@" + index_digest
    index = inspect(index_ref, "Manifest", output, name + "-index.json")
    tag_index = inspect(record["tags"][name], "Manifest", output, name + "-tag-readback.json")
    require(index.get("digest") == index_digest == tag_index.get("digest") and
            index.get("mediaType") == "application/vnd.oci.image.index.v1+json", "tag/index digest mismatch")
    members = index.get("manifests", [])
    images = [x for x in members if x.get("platform") == {"os": "linux", "architecture": "amd64"}]
    require(len(images) == 1 and len(members) == 2, "one image and one packaging attestation required")
    image = images[0]
    platform_digest = image.get("digest", "")
    require(bool(DIGEST.fullmatch(platform_digest)) and
            image.get("mediaType") == "application/vnd.oci.image.manifest.v1+json", "platform descriptor mismatch")
    attestation = next(x for x in members if x is not image)
    attestation_digest = attestation.get("digest", "")
    require(bool(DIGEST.fullmatch(attestation_digest)) and
            attestation.get("platform") == {"os": "unknown", "architecture": "unknown"} and
            attestation.get("annotations", {}).get("vnd.docker.reference.type") == "attestation-manifest" and
            attestation.get("annotations", {}).get("vnd.docker.reference.digest") == platform_digest,
            "packaging attestation is unbound")
    platform_ref = REGISTRY + "@" + platform_digest
    raw = command(["docker", "buildx", "imagetools", "inspect", platform_ref, "--raw"], timeout=120)
    (output / (name + "-platform-manifest.raw.json")).write_bytes(raw)
    require("sha256:" + sha(raw) == platform_digest, "raw platform bytes mismatch")
    config_digest, config, raw_config = verified_image_config(metadata, json.loads(raw))
    require(len({index_digest, platform_digest, config_digest, attestation_digest}) == 4, "digest kinds confused")
    (output / (name + "-config.raw.json")).write_bytes(raw_config)
    require(config.get("os") == "linux" and config.get("architecture") == "amd64", "candidate platform mismatch")
    actual = config.get("config", {})
    expected_labels = packaging["labels"]
    labels = actual.get("Labels", {})
    require(all(labels.get(k) == value for k, value in expected_labels.items()), "artifact/source/tool labels mismatch")
    if name == "root-deployer":
        require(actual.get("Entrypoint") == ["/usr/local/bin/deployer"] and actual.get("WorkingDir") == "/workspace" and
                actual.get("User") == "0:0" and "9000/tcp" in actual.get("ExposedPorts", {}),
                "original deployer runtime contract mismatch")
    else:
        require(not actual.get("Entrypoint") and not actual.get("Cmd"), "artifact image must not start a helper or launcher")
    provenance = inspect(index_ref, "Provenance", output, name + "-packaging-provenance.json")
    slsa = provenance.get("SLSA", {})
    invocation = slsa.get("invocation", {})
    require(slsa.get("buildType") == "https://mobyproject.org/buildkit@v1" and
            invocation.get("configSource", {}).get("entryPoint") == "Dockerfile" and
            invocation.get("environment", {}).get("platform") == PLATFORM, "packaging provenance recipe mismatch")
    args = invocation.get("parameters", {}).get("args", {})
    require(not any(k.startswith("build-arg:") for k in args), "unexpected packaging build argument")
    details = slsa.get("metadata", {}).get(METADATA_KEY, {})
    require(not details.get("vcs"), "generated artifact context must not invent Git revision provenance")
    dockerfiles = [x for x in details.get("source", {}).get("infos", []) if x.get("filename") == "Dockerfile"]
    require(len(dockerfiles) == 1 and sha(base64.b64decode(dockerfiles[0].get("data", ""), validate=True)) ==
            packaging["recipe_sha256"], "generated recipe bytes differ from packaging provenance")
    materials = slsa.get("materials", [])
    require(isinstance(materials, list), "packaging materials malformed")
    if name == "root-deployer":
        base_digest = record["runtime_base"].rsplit("sha256:", 1)[1]
        require(any(x.get("digest", {}).get("sha256") == base_digest for x in materials),
                "immutable runtime base is not in packaging provenance materials")
    return {"tag": record["tags"][name], "index_digest": index_digest,
            "platform_manifest_digest": platform_digest, "config_digest": config_digest,
            "attestation_manifest_digest": attestation_digest, "platform_reference": platform_ref,
            "packaging_recipe_sha256": packaging["recipe_sha256"],
            "controlled_artifacts_manifest_sha256": packaging["artifacts_manifest_sha256"],
            "provenance_scope": "packaging only; separate controlled Go receipt binds source/binary/toolchain"}


def extracted_readback(name, candidate, pins, go, output, source_sha):
    # A GitHub-hosted filesystem probe only, with a deliberately absent entry
    # point. No start/exec/rm, host bind mount, production daemon or Docker API.
    argv = ["docker", "create", "--platform", PLATFORM, "--entrypoint",
            "/__candidate_filesystem_readback_never_started__",
            "--label", "io.opensamguk.candidate.evidence-only=true", candidate["platform_reference"]]
    save_new(output / (name + "-filesystem-probe-intent.json"), {"argv": argv, "started": False})
    wire = command(argv, timeout=300)
    save_new(output / (name + "-filesystem-probe-response.json"), {"stdout": wire.decode(), "started": False})
    container = wire.decode().strip()
    require(bool(re.fullmatch(r"[0-9a-f]{64}", container)), "filesystem probe ID invalid")
    save_new(output / (name + "-filesystem-probe.json"), {"containerID": container,
             "image": candidate["platform_reference"], "started": False, "removed": False,
             "owner": "this GitHub-hosted ephemeral job; platform lifecycle only",
             "host_installation_authority": False})
    extracted = output / (name + "-extracted")
    extracted.mkdir(mode=0o700)
    proof = {}
    for artifact, location in IMAGE_PATHS[name].items():
        path = extracted / artifact
        command(["docker", "cp", container + ":" + location, str(path)], timeout=120)
        pin = regular_pin(path, ARTIFACTS[artifact]["limit"])
        require(pin["sha256"] == pins[artifact]["sha256"] and pin["byteLength"] == pins[artifact]["byteLength"] and
                pin["mode"] == 0o500, "extracted artifact differs from controlled output")
        if artifact != "host-session-launcher":
            info = command([str(go), "version", "-m", str(path)]).decode()
            require("GOOS=linux" in info and "GOARCH=amd64" in info and "CGO_ENABLED=0" in info,
                    "extracted Go metadata platform mismatch")
            if artifact == "deployer":
                require("main.rootBuiltSourceSHA=" + source_sha in info, "extracted source stamp flag absent")
            pin["goBuildMetadata"] = info
        proof[artifact] = dict(pin, imagePath=location)
    save_new(output / (name + "-extracted-artifacts.json"), proof)
    return proof


def issue(args):
    source, issuer, contract, arch_wire = validate_inputs(args)
    output = args.output
    require(output.is_absolute() and output.parent.resolve(strict=True) == output.parent and not output.exists(),
            "new canonical output required; previous attempt must be retained")
    output.mkdir(mode=0o700)
    record = plan(args, source, contract)
    save_new(output / "intent.json", record)
    (output / "approved-build-contract.raw.json").write_text(os.environ["APPROVED_BUILD_CONTRACT_JSON"])
    tree_wire = git(source, "ls-tree", "-rz", "--full-tree", "--abbrev=40", "HEAD")
    (output / "tracked-tree.nul").write_bytes(tree_wire)
    try:
        base_readback(contract, output)
        artifacts, pins, controlled_receipt, go = controlled_artifacts(source, output, contract, arch_wire, args)
        bundle = {"root_source": args.source_sha, "app_source": args.app_source_sha,
                  "issuer_source": args.issuer_sha, "source_fingerprint64": args.fingerprint,
                  "controlled_build_receipt": controlled_receipt, "artifact_pins3": pins,
                  "toolchain_binary_sha256": contract["go_binary_sha256"],
                  "toolchain_tree_sha256": contract["go_tree_sha256"], "host_arch_evidence_sha256": contract["host_arch_evidence_sha256"],
                  "install_or_launcher_execution": False}
        save_new(output / "controlled-artifacts-manifest.json", bundle)
        bundle_hash = file_sha(output / "controlled-artifacts-manifest.json")
        candidates = {}
        for name in IMAGE_PATHS:
            require(main_sha(ROOT_REPO) == args.source_sha and main_sha(APP_REPO) == args.app_source_sha,
                    "Root/App main moved before publication")
            require(not git(source, "status", "--porcelain", "--untracked-files=all") and
                    fingerprint(source) == args.fingerprint, "source changed during artifact build")
            context = output / (name + "-context")
            context.mkdir(mode=0o700)
            for artifact, spec in ARTIFACTS.items():
                require(regular_pin(artifacts / artifact, spec["limit"]) == pins[artifact], "controlled output changed")
                shutil.copyfile(artifacts / artifact, context / artifact)
                (context / artifact).chmod(0o500)
                require(file_sha(context / artifact) == pins[artifact]["sha256"], "packaging input changed")
            recipe_wire = recipe(name, contract["runtime_base"]).encode()
            (context / "Dockerfile").write_bytes(recipe_wire)
            labels = {"org.opencontainers.image.revision": args.source_sha, "org.opencontainers.image.source": SOURCE_URL,
                      "io.opensamguk.app-source": args.app_source_sha,
                      "io.opensamguk.controlled-artifacts-manifest-sha256": bundle_hash,
                      "io.opensamguk.generated-recipe-sha256": sha(recipe_wire),
                      "io.opensamguk.toolchain-tree-sha256": contract["go_tree_sha256"]}
            packaging = {"recipe_sha256": sha(recipe_wire), "artifacts_manifest_sha256": bundle_hash,
                         "labels": labels, "artifact_pins3": pins, "context_files_only": list(ARTIFACTS) + ["Dockerfile"]}
            save_new(output / (name + "-packaging-contract.json"), packaging)
            metadata_file = output / (name + "-build-metadata.json")
            argv = ["docker", "buildx", "build", "--platform", PLATFORM, "--file", "Dockerfile",
                    "--provenance=mode=max,version=v0.2", "--sbom=false", "--output=type=image,oci-mediatypes=true",
                    "--metadata-file", str(metadata_file), "--tag", record["tags"][name]]
            for key, value in labels.items():
                argv.extend(["--label", key + "=" + value])
            argv.extend(["--push", "."])
            save_new(output / (name + "-push-intent.json"), {"argv": argv, "tag": record["tags"][name], "packaging": packaging})
            command(argv, cwd=context, timeout=1800)
            candidate = verify_packaging(name, json.loads(metadata_file.read_bytes()), record, packaging, output)
            candidate["extracted_artifacts3"] = extracted_readback(name, candidate, pins, go, output, args.source_sha)
            candidates[name] = candidate
            save_new(output / (name + "-verified.json"), candidate)
        require(main_sha(ROOT_REPO) == args.source_sha and main_sha(APP_REPO) == args.app_source_sha,
                "main moved after publication; candidates retained unpromoted")
        save_new(output / "candidate.json", dict(record, status="VERIFIED_PACKAGED_CANDIDATES", images=candidates,
                  controlled_build_receipt=controlled_receipt, artifacts_manifest_sha256=bundle_hash,
                  host_installation_authorized=False, launcher_executed=False))
    except (Exception, KeyboardInterrupt):
        save_new(output / "failure.json", {"status": "HOLD_RETAIN_PARTIAL_NO_RETRY", "tags": record["tags"],
                 "preserve_registry_and_hosted_probe_evidence": True, "retry_overwrite_tag_delete": False,
                 "host_installation_or_deployment_authorized": False})
        raise


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("mode", choices=("fingerprint", "admit", "issue"))
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--issuer", type=Path)
    p.add_argument("--source-sha")
    p.add_argument("--issuer-sha")
    p.add_argument("--issuer-ref")
    p.add_argument("--app-source-sha")
    p.add_argument("--fingerprint")
    p.add_argument("--contract-sha256")
    p.add_argument("--output", type=Path)
    return p


def main():
    args = parser().parse_args()
    if args.mode == "fingerprint":
        require(not git(args.source, "status", "--porcelain", "--untracked-files=all"), "clean fingerprint source required")
        print(fingerprint(args.source))
        return
    require(args.issuer and args.output, "issuer checkout and fresh output required")
    if args.mode == "admit":
        source, issuer, contract, evidence = validate_inputs(args)
        save_new(args.output, plan(args, source, contract))
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
            stream.write("go_release=" + contract["go_release"] + "\n")
    else:
        issue(args)


if __name__ == "__main__":
    try:
        main()
    except (Exception, KeyboardInterrupt):
        print("ERROR: pinned Root candidate preparation failed; retain partial evidence and do not retry.", file=sys.stderr)
        raise SystemExit(1)
