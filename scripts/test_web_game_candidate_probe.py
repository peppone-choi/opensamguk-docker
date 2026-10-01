#!/usr/bin/env python3
"""Synthetic command-fixture tests only; no Docker, registry, or VM calls."""
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import web_game_candidate_probe as probe


def fixture():
    candidate = {"schema": "web-game-image-candidate/v1", "status": "VERIFIED_CANDIDATE",
                 "deployment_approved": False, "source_sha": probe.SOURCE, "issuer_sha": "a" * 40,
                 "run_id": "123", "run_attempt": "1", "repository": probe.REPO, "platform": probe.PLATFORM,
                 "tag": f"{probe.REPO}:web-game-candidate-{probe.SOURCE}-123-1",
                 "index_digest": "sha256:" + "b" * 64, "platform_manifest_digest": "sha256:" + "c" * 64,
                 "config_digest": "sha256:" + "d" * 64, "attestation_manifest_digest": "sha256:" + "e" * 64,
                 "source_pins_sha256": {"docker/web-game.Dockerfile": probe.DOCKERFILE_SHA},
                 "build_args": {"ASSET_PREFIX": "/game", "GATEWAY_WEB_URL": "http://web-gateway:3000",
                                "NEXT_PUBLIC_GATEWAY_URL": ""}, "runtime_check": {"NODE_ENV": "production"}}
    candidate["index_reference"] = probe.REPO + "@" + candidate["index_digest"]
    candidate["platform_reference"] = probe.REPO + "@" + candidate["platform_manifest_digest"]
    data = json.dumps(candidate).encode()
    approval = {"schema": "web-game-image-probe-approval/v1", "target": "github-hosted-ephemeral",
                "operations": ["pull", "create-not-start", "inspect-selected", "remove-own-created-container"],
                "operating_actions_authorized": False, "execution_authorized": True,
                "probe_source_sha256": probe.sha256(Path(probe.__file__).read_bytes()),
                "candidate_sha256": probe.sha256(data),
                **{key: candidate[key] for key in ("source_sha", "issuer_sha", "run_id", "run_attempt",
                                                   "platform_manifest_digest", "config_digest")}}
    return candidate, data, approval


class FakeDocker:
    def __init__(self, plan, image_id_kind="config"):
        self.plan = plan
        self.calls = []
        self.created = None
        self.image_change = {}
        self.container_change = {}
        self.fail_pull = False
        self.fail_create = False
        self.fail_rm = False
        self.image_id = plan["config_digest"] if image_id_kind == "config" else plan["platform_manifest_digest"]

    def __call__(self, argv, timeout):
        self.calls.append((argv[:], timeout))
        if argv[0] == "version":
            return "29.0.0|29.0.0\n"
        if argv[:2] == ["compose", "version"]:
            return "2.38.2\n"
        if argv[:2] == ["image", "pull"]:
            if self.fail_pull:
                raise probe.Rejected("hosted Docker command failed: image pull")
            return "synthetic discarded pull output"
        if argv[:2] == ["image", "inspect"]:
            return json.dumps({"id": self.image_id, "os": "linux", "arch": "amd64",
                               "repoDigests": [self.plan["platform_reference"]], "revision": probe.SOURCE,
                               "source": probe.SOURCE_URL, **self.image_change})
        if argv[:2] == ["container", "create"]:
            name = argv[argv.index("--name") + 1]
            owner = argv[argv.index("--label") + 1].split("=", 1)[1]
            self.created = {"id": "f" * 64, "name": "/" + name, "owner": owner, "image": self.image_id,
                            "configImage": self.plan["control_reference"], "running": False, "status": "created",
                            "network": "none", "readonly": True, "mountCount": 0, **self.container_change}
            if self.fail_create:
                raise probe.Rejected("hosted Docker command failed: container create")
            return "f" * 64 + "\n"
        if argv[:2] == ["container", "inspect"]:
            if self.created is None:
                raise probe.Rejected("hosted Docker command failed: container inspect")
            if argv[2] != self.created["name"].removeprefix("/"):
                raise AssertionError("inspect target expanded")
            return json.dumps(self.created)
        if argv[:2] == ["container", "rm"]:
            if self.fail_rm:
                raise probe.Rejected("hosted Docker command failed: container rm")
            if argv[2:] != [self.created["id"]]:
                raise AssertionError("cleanup target expanded")
            self.created = None
            return "removed synthetic owned container"
        raise AssertionError("unexpected command " + repr(argv))


class CandidateProbeTests(unittest.TestCase):
    def setUp(self):
        self.candidate, self.data, self.approval = fixture()
        self.plan = probe.make_plan(self.data, self.approval)

    def altered(self, key, value):
        candidate = copy.deepcopy(self.candidate)
        candidate[key] = value
        data = json.dumps(candidate).encode()
        approval = {**self.approval, "candidate_sha256": probe.sha256(data)}
        return data, approval

    def test_plan_binds_platform_digest_and_preserves_unknown_operating_identity(self):
        self.assertEqual(self.plan["control_reference"], probe.REPO + ":web-game-" + probe.SOURCE + "@" + self.candidate["platform_manifest_digest"])
        self.assertFalse(self.plan["operating_target_verified"])
        self.assertFalse(self.plan["rollback_pull_in_this_probe"])

    def test_candidate_or_probe_byte_pin_mismatch_rejected(self):
        for key in ("candidate_sha256", "probe_source_sha256"):
            with self.subTest(key=key), self.assertRaises(probe.Rejected):
                probe.make_plan(self.data, {**self.approval, key: "0" * 64})

    def test_issuer_source_run_and_approval_target_are_admitted_before_commands(self):
        for key, value in [("issuer_sha", "0" * 40), ("source_sha", "0" * 40), ("run_id", "124"),
                           ("run_attempt", "2"), ("target", "operating-vm"), ("operations", ["pull"]),
                           ("operating_actions_authorized", True)]:
            with self.subTest(key=key), self.assertRaises(probe.Rejected):
                probe.make_plan(self.data, {**self.approval, key: value})

    def test_unverified_foreign_repository_platform_and_deployment_claim_rejected(self):
        for key, value in [("status", "PENDING"), ("deployment_approved", True), ("repository", "other/repo"),
                           ("platform", "linux/arm64"), ("tag", "latest"), ("source_pins_sha256", []),
                           ("runtime_check", None), ("build_args", {"ASSET_PREFIX": "/wrong"})]:
            with self.subTest(key=key), self.assertRaises(probe.Rejected):
                probe.make_plan(*self.altered(key, value))

    def test_digest_kinds_and_canonical_references_rejected(self):
        for key, value in [("platform_manifest_digest", self.candidate["config_digest"]),
                           ("config_digest", "sha256:bad"), ("platform_reference", "other@sha256:" + "c" * 64)]:
            with self.subTest(key=key), self.assertRaises(probe.Rejected):
                probe.make_plan(*self.altered(key, value))

    def test_execute_requires_approval_and_hosted_environment(self):
        env = {"CI": "true", "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}
        probe.require_hosted(self.approval, env)
        for key in env:
            with self.subTest(key=key), self.assertRaises(probe.Rejected):
                probe.require_hosted(self.approval, {**env, key: "self-hosted"})
        with self.assertRaises(probe.Rejected):
            probe.require_hosted({**self.approval, "execution_authorized": False}, env)

    def test_actual_command_plan_pulls_exact_reference_creates_without_start_and_removes_owned_only(self):
        fake = FakeDocker(self.plan)
        result = probe.probe(self.plan, fake)
        self.assertEqual(result["status"], "PASS")
        self.assertTrue(result["owned_created_container_removed"])
        self.assertIsNone(fake.created)
        self.assertEqual([argv for argv, _ in fake.calls if argv[:2] == ["image", "pull"]],
                         [["image", "pull", "--platform", "linux/amd64", self.plan["control_reference"]]])
        commands = [argv[:2] for argv, _ in fake.calls]
        self.assertNotIn(["container", "start"], commands)
        self.assertNotIn(["container", "run"], commands)
        self.assertNotIn(["compose", "up"], commands)
        create = next(argv for argv, _ in fake.calls if argv[:2] == ["container", "create"])
        self.assertNotIn("--env", create)
        self.assertNotIn("--volume", create)
        self.assertEqual(create[-1], self.plan["control_reference"])
        self.assertEqual(result["containers_started"], 0)

    def test_manifest_image_store_id_is_separate_from_config_digest(self):
        result = probe.probe(self.plan, FakeDocker(self.plan, "manifest"))
        self.assertEqual(result["image_id_kind"], "platform-manifest")
        self.assertEqual(result["pulled_image"]["id"], self.plan["platform_manifest_digest"])

    def test_wrong_pulled_digest_platform_source_or_unknown_image_id_never_creates(self):
        for change in [{"repoDigests": []}, {"arch": "arm64"}, {"revision": "0" * 40},
                       {"source": "https://other.example"}, {"id": "sha256:" + "9" * 64}]:
            with self.subTest(change=change):
                fake = FakeDocker(self.plan)
                fake.image_change = change
                with self.assertRaises(probe.Rejected):
                    probe.probe(self.plan, fake)
                self.assertFalse(any(argv[:2] == ["container", "create"] for argv, _ in fake.calls))

    def test_pull_failure_never_creates_and_does_not_dump_child_output(self):
        fake = FakeDocker(self.plan)
        fake.fail_pull = True
        with self.assertRaisesRegex(probe.Rejected, "image pull"):
            probe.probe(self.plan, fake)
        self.assertFalse(any(argv[:2] == ["container", "create"] for argv, _ in fake.calls))

    def test_normalized_Config_Image_is_red_and_owned_cleanup_still_occurs(self):
        fake = FakeDocker(self.plan)
        fake.container_change = {"configImage": self.plan["platform_reference"]}
        with self.assertRaisesRegex(probe.Rejected, "Config.Image"):
            probe.probe(self.plan, fake)
        self.assertIsNone(fake.created)

    def test_created_image_or_isolation_mismatch_is_red_with_cleanup(self):
        for change in [{"image": "sha256:" + "9" * 64}, {"network": "host"}, {"readonly": False}, {"mountCount": 1}]:
            with self.subTest(change=change):
                fake = FakeDocker(self.plan)
                fake.container_change = change
                with self.assertRaises(probe.Rejected):
                    probe.probe(self.plan, fake)
                self.assertIsNone(fake.created)

    def test_different_owner_or_running_container_is_never_removed(self):
        for change in [{"owner": "foreign"}, {"running": True, "status": "running"}]:
            with self.subTest(change=change):
                fake = FakeDocker(self.plan)
                fake.container_change = change
                with self.assertRaises(probe.Rejected):
                    probe.probe(self.plan, fake)
                self.assertFalse(any(argv[:2] == ["container", "rm"] for argv, _ in fake.calls))

    def test_create_error_with_owned_partial_object_is_cleaned(self):
        fake = FakeDocker(self.plan)
        fake.fail_create = True
        with self.assertRaisesRegex(probe.Rejected, "container create"):
            probe.probe(self.plan, fake)
        self.assertIsNone(fake.created)

    def test_cleanup_failure_cannot_be_a_pass(self):
        fake = FakeDocker(self.plan)
        fake.fail_rm = True
        with self.assertRaisesRegex(probe.Rejected, "container rm"):
            probe.probe(self.plan, fake)

    def test_selected_metadata_projection_never_includes_fake_extra_secrets(self):
        fake = FakeDocker(self.plan)
        fake.image_change = {"Env": ["PRIVATE_SENTINEL=value"]}
        fake.container_change = {"Config": {"Env": ["PRIVATE_SENTINEL=value"]}}
        self.assertNotIn("PRIVATE_SENTINEL", json.dumps(probe.probe(self.plan, fake)))

    def test_default_cli_is_plan_only_and_requires_no_execution_approval(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate, approval, output = root / "candidate.json", root / "approval.json", root / "result.json"
            candidate.write_bytes(self.data)
            approval.write_text(json.dumps({**self.approval, "execution_authorized": False}))
            args = ["probe", "--candidate", str(candidate), "--approval", str(approval), "--output", str(output)]
            with patch("sys.argv", args), patch.object(probe, "make_local_runner", side_effect=AssertionError("real Docker forbidden")), patch("sys.stdout", io.StringIO()):
                probe.main()
            result = json.loads(output.read_text())
            self.assertEqual(result["status"], "PLAN_ONLY_NOT_EXECUTED")
            self.assertEqual(result["docker_calls"], 0)

    def test_real_runner_uses_only_local_socket_fresh_cli_config_and_scrubbed_env(self):
        class Result:
            returncode = 0
            stdout = "synthetic"
        with tempfile.TemporaryDirectory() as directory, patch.object(probe.subprocess, "run", return_value=Result()) as call:
            runner = probe.make_local_runner(Path(directory))
            runner(["version"], 30)
            args, kwargs = call.call_args
            self.assertEqual(args[0][:3], ["docker", "--host", "unix:///var/run/docker.sock"])
            self.assertEqual(set(kwargs["env"]), {"PATH", "HOME", "LANG"})
            self.assertNotIn("DOCKER_HOST", kwargs["env"])
            self.assertNotIn("GITHUB_TOKEN", kwargs["env"])


if __name__ == "__main__":
    unittest.main()
