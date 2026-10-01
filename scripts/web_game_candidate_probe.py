#!/usr/bin/env python3
"""Prepare or verify one approved web candidate on an ephemeral hosted runner.

No start/run/compose/up, registry publish, VM command, mounts, or env injection.
Default mode makes a plan only. Real Docker requires an explicit hosted approval.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import uuid

SOURCE = "cf7a1968993e41a98940031c60683129e9ae919a"
REPO = "ghcr.io/peppone-choi/opensamguk"
SOURCE_URL = "https://github.com/peppone-choi/opensamguk"
PLATFORM = "linux/amd64"
LABEL = "io.opensamguk.c8-candidate-probe"
DOCKERFILE_SHA = "e122a4e0f079a97ba470c088a8569e29a7ab9a2c67bb941200b5fb17245103bd"
SHA = re.compile(r"[0-9a-f]{64}")
SHA40 = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
IMAGE_FORMAT = ('{"id":{{json .Id}},"os":{{json .Os}},"arch":{{json .Architecture}},'
                '"repoDigests":{{json .RepoDigests}},'
                '"revision":{{json (index .Config.Labels "org.opencontainers.image.revision")}},'
                '"source":{{json (index .Config.Labels "org.opencontainers.image.source")}}}')
CONTAINER_FORMAT = ('{"id":{{json .Id}},"name":{{json .Name}},'
                    '"owner":{{json (index .Config.Labels "' + LABEL + '")}},'
                    '"image":{{json .Image}},"configImage":{{json .Config.Image}},'
                    '"running":{{json .State.Running}},"status":{{json .State.Status}},'
                    '"network":{{json .HostConfig.NetworkMode}},'
                    '"readonly":{{json .HostConfig.ReadonlyRootfs}},"mountCount":{{len .Mounts}}}')


class Rejected(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise Rejected(reason)


def read_bounded(path):
    with path.open("rb") as stream:
        value = stream.read(1024 * 1024 + 1)
    require(len(value) <= 1024 * 1024, "input exceeds limit")
    return value


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def make_plan(candidate_bytes, approval):
    require(isinstance(approval, dict), "approval shape")
    require(approval.get("schema") == "web-game-image-probe-approval/v1", "approval schema")
    require(approval.get("target") == "github-hosted-ephemeral", "probe target")
    require(approval.get("operations") == ["pull", "create-not-start", "inspect-selected", "remove-own-created-container"]
            and approval.get("operating_actions_authorized") is False, "approved probe operation scope")
    require(approval.get("candidate_sha256") == sha256(candidate_bytes), "candidate byte pin")
    require(approval.get("probe_source_sha256") == sha256(Path(__file__).read_bytes()), "probe source pin")
    candidate = json.loads(candidate_bytes)
    require(isinstance(candidate, dict), "candidate shape")
    require(candidate.get("schema") == "web-game-image-candidate/v1"
            and candidate.get("status") == "VERIFIED_CANDIDATE", "unverified candidate")
    require(candidate.get("deployment_approved") is False, "issuance must not grant deployment")
    require(candidate.get("source_sha") == approval.get("source_sha") == SOURCE, "source pin")
    issuer = candidate.get("issuer_sha")
    require(isinstance(issuer, str) and SHA40.fullmatch(issuer)
            and issuer == approval.get("issuer_sha"), "issuer pin")
    for key in ("run_id", "run_attempt"):
        value = candidate.get(key)
        require(isinstance(value, str) and re.fullmatch(r"[1-9][0-9]*", value)
                and value == approval.get(key), "issuance identity pin")
    require(candidate.get("repository") == REPO and candidate.get("platform") == PLATFORM,
            "repository/platform pin")
    require(candidate.get("tag") == f"{REPO}:web-game-candidate-{SOURCE}-{candidate['run_id']}-{candidate['run_attempt']}",
            "candidate tag shape")
    keys = ("index_digest", "platform_manifest_digest", "config_digest", "attestation_manifest_digest")
    digests = [candidate.get(key) for key in keys]
    require(all(isinstance(value, str) and DIGEST.fullmatch(value) for value in digests)
            and len(set(digests)) == 4, "distinct OCI digest kinds")
    for key in ("platform_manifest_digest", "config_digest"):
        require(candidate[key] == approval.get(key), "approved image digest")
    require(candidate.get("index_reference") == REPO + "@" + candidate["index_digest"]
            and candidate.get("platform_reference") == REPO + "@" + candidate["platform_manifest_digest"],
            "canonical reference")
    pins = candidate.get("source_pins_sha256")
    require(isinstance(pins, dict) and pins.get("docker/web-game.Dockerfile") == DOCKERFILE_SHA,
            "Dockerfile source pin")
    require(candidate.get("build_args") == {"ASSET_PREFIX": "/game", "GATEWAY_WEB_URL": "http://web-gateway:3000",
                                            "NEXT_PUBLIC_GATEWAY_URL": ""}, "public build arguments")
    runtime = candidate.get("runtime_check")
    require(isinstance(runtime, dict) and runtime.get("NODE_ENV") == "production", "candidate runtime contract")
    return {"schema": "web-game-image-probe-plan/v1", "source_sha": SOURCE, "issuer_sha": issuer,
            "candidate_sha256": sha256(candidate_bytes), "platform": PLATFORM,
            "platform_reference": candidate["platform_reference"],
            "platform_manifest_digest": candidate["platform_manifest_digest"],
            "config_digest": candidate["config_digest"],
            "control_reference": f"{REPO}:web-game-{SOURCE}@{candidate['platform_manifest_digest']}",
            "rollback_reference": f"{REPO}:web-game-d50177b207897fc6c466095ec9699aab03f57536@sha256:2a927e3633f9285428e55a9fdaed1fce445cd88e445f01fd98f81be11de46a29",
            "rollback_pull_in_this_probe": False, "containers_started": 0,
            "operating_target_verified": False}


def require_hosted(approval, env):
    require(approval.get("execution_authorized") is True, "hosted probe execution is not approved")
    require(env.get("CI") == "true" and env.get("GITHUB_ACTIONS") == "true"
            and env.get("RUNNER_ENVIRONMENT") == "github-hosted", "isolated hosted runner required")


def make_local_runner(config_dir):
    # Fixed Unix socket and fresh CLI config: inherited remote contexts/auth are unused.
    clean_env = {"PATH": os.environ["PATH"], "HOME": str(config_dir), "LANG": "C.UTF-8"}

    def run(argv, timeout):
        result = subprocess.run(["docker", "--host", "unix:///var/run/docker.sock", "--config",
                                 str(config_dir), *argv], env=clean_env, cwd=config_dir,
                                capture_output=True, text=True, timeout=timeout)
        require(result.returncode == 0, "hosted Docker command failed: " + " ".join(argv[:2]))
        require(len(result.stdout) <= 1024 * 1024, "Docker result exceeds limit")
        return result.stdout

    return run


def container_record(run, name):
    return json.loads(run(["container", "inspect", name, "--format", CONTAINER_FORMAT], 30))


def require_owned(record, name, owner):
    require(record.get("name") == "/" + name and record.get("owner") == owner
            and isinstance(record.get("id"), str) and SHA.fullmatch(record["id"]), "probe container ownership")
    require(record.get("running") is False and record.get("status") == "created", "probe container must never start")


def probe(plan, run):
    reference = plan["control_reference"]
    owner = uuid.uuid4().hex
    name = "c8-web-candidate-probe-" + owner
    created = False
    result = {"status": "RUNNING", "scope": "hosted-ephemeral-only", "plan": plan,
              "containers_started": 0, "operating_verified": False}
    try:
        versions = run(["version", "--format", "{{.Client.Version}}|{{.Server.Version}}"], 30).strip()
        require(bool(re.fullmatch(r"[0-9A-Za-z.+_-]+\|[0-9A-Za-z.+_-]+", versions)), "Docker versions")
        result["hosted_docker_versions"] = versions
        compose = run(["compose", "version", "--short"], 30).strip()
        require(bool(re.fullmatch(r"[0-9A-Za-z.+_-]+", compose)), "Compose version")
        result["hosted_compose_version"] = compose
        run(["image", "pull", "--platform", PLATFORM, reference], 300)
        image = json.loads(run(["image", "inspect", reference, "--format", IMAGE_FORMAT], 30))
        require(image.get("os") == "linux" and image.get("arch") == "amd64", "pulled platform")
        require(plan["platform_reference"] in (image.get("repoDigests") or []), "pulled manifest digest")
        require(image.get("revision") == SOURCE and image.get("source") == SOURCE_URL, "pulled OCI source labels")
        # Classic image store uses config IDs; other stores may use manifest IDs.
        # Preserve and identify both; do not conflate Docker ID with registry digest.
        image_id = image.get("id")
        require(image_id in (plan["config_digest"], plan["platform_manifest_digest"]), "unsupported image ID mapping")
        result["pulled_image"] = {key: image[key] for key in ("id", "os", "arch", "revision", "source")}
        result["pulled_image"]["approved_repo_digest"] = plan["platform_reference"]
        result["image_id_kind"] = "config" if image_id == plan["config_digest"] else "platform-manifest"
        run(["container", "create", "--platform", PLATFORM, "--name", name, "--label", LABEL + "=" + owner,
             "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
             "--pids-limit", "16", "--memory", "64m", "--entrypoint", "/bin/true", reference], 30)
        created = True
        record = container_record(run, name)
        require_owned(record, name, owner)
        require(record.get("image") == image_id, "created image differs from pulled ID")
        # This exact comparison mirrors PR61's current verifyWebGamePin behavior.
        # Digest-only normalization is not silently accepted as runtime support.
        require(record.get("configImage") == reference, "Config.Image differs from PR61 expected reference")
        require(record.get("network") == "none" and record.get("readonly") is True
                and record.get("mountCount") == 0, "probe isolation")
        result["created_container"] = {key: record[key] for key in
                                       ("id", "name", "owner", "image", "configImage", "running", "status",
                                        "network", "readonly", "mountCount")}
        result["status"] = "PASS"
    finally:
        # A create error can still leave an object. Inspect only our unique name.
        # Never force-remove, enumerate, prune, or remove someone else's object.
        try:
            record = container_record(run, name)
        except (Rejected, ValueError, subprocess.TimeoutExpired):
            require(not created, "owned container cleanup could not be verified")
        else:
            require_owned(record, name, owner)
            run(["container", "rm", record["id"]], 30)
            result["owned_created_container_removed"] = True
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--approval", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--execute-hosted", action="store_true")
    args = parser.parse_args()
    try:
        require(not args.output.exists(), "output must be fresh")
        approval = json.loads(read_bounded(args.approval))
        plan = make_plan(read_bounded(args.candidate), approval)
        if not args.execute_hosted:
            result = {"status": "PLAN_ONLY_NOT_EXECUTED", "plan": plan, "docker_calls": 0}
        else:
            require_hosted(approval, os.environ)
            with tempfile.TemporaryDirectory(prefix="c8-hosted-candidate-cli-") as directory:
                result = probe(plan, make_local_runner(Path(directory)))
        args.output.write_text(json.dumps(result, indent=2) + "\n")
        print(result["status"])
    except Rejected as error:
        parser.exit(1, "candidate probe rejected: " + str(error) + "; no success evidence was produced\n")
    except (ValueError, OSError, KeyError, TypeError, subprocess.TimeoutExpired):
        # Do not dump arbitrary child output, full inspect, credentials, or env.
        parser.exit(1, "candidate probe rejected; no success evidence was produced\n")


if __name__ == "__main__":
    main()
