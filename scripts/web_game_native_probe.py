#!/usr/bin/env python3
"""Hosted CI only: actual Go race/mutations and Compose config; no deploy/pull/up."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "deployer/web_game_deploy.go"
TEST_SOURCE = ROOT / "deployer/web_game_deploy_test.go"
PATTERN = r"^(TestWebGameDeploy.*|TestConcurrentWebDeploys.*)$"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run_go(evidence, label, pattern):
    command = ["go", "test", "-race", "-count=1", "-json", "-run", pattern, "."]
    result = subprocess.run(command, cwd=ROOT / "deployer", text=True,
                            capture_output=True, timeout=300)
    (evidence / (label + ".jsonl")).write_text(result.stdout)
    (evidence / (label + ".stderr.log")).write_text(result.stderr)
    events = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
    # Package/compiler failure must never stand in for an actual red test.
    counts = {action: sorted({e["Test"] for e in events
                             if e.get("Action") == action and e.get("Test")})
              for action in ("pass", "fail", "skip")}
    return {"command": command, "exit": result.returncode, **counts}, events


def require_green(result, expected):
    top = {name for name in result["pass"] if "/" not in name}
    if result["exit"] != 0 or result["fail"] or result["skip"] or top != expected:
        raise AssertionError("Native suite did not pass every expected test without skips")


def compose_probe(evidence):
    compose = ROOT / "docker-compose.server.yml"
    before = compose.read_bytes()
    version = subprocess.check_output(["docker", "compose", "version", "--short"],
                                      text=True, timeout=30).strip()
    pin = "a" * 40 + "@sha256:" + "b" * 64
    # Explicit synthetic env file, scrubbed interpolation environment; no host secrets.
    clean_env = {"PATH": os.environ["PATH"], "HOME": str(evidence),
                 "COMPOSE_HOST_DIR": "/tmp/c8-synthetic-compose-root"}
    values = {"SERVER_ID": "pep", "IMAGE_TAG": "c" * 40,
              "GAME_POSTGRES_PASSWORD": "synthetic-password",
              "JWT_PUBLIC_KEY": "synthetic-not-a-key", "INTERNAL_SERVICE_TOKEN": "synthetic-token",
              "GAME_API_PORT": "18081", "WEB_GAME_PORT": "13001",
              "GHCR_REGISTRY": "ghcr.io", "GHCR_OWNER": "peppone-choi"}
    with tempfile.TemporaryDirectory(prefix="c8-compose-config-") as directory:
        env_file = Path(directory) / "synthetic.env"

        def config(web_tag):
            env_file.write_text("".join(k + "=" + v + "\n" for k, v in
                                        {**values, "WEB_GAME_TAG": web_tag}.items()))
            output = subprocess.check_output(
                ["docker", "compose", "-p", "opensamguk-spep", "--env-file", str(env_file),
                 "-f", str(compose), "config", "--format", "json"], cwd=ROOT,
                env=clean_env, text=True, timeout=60)
            return json.loads(output)

        baseline = config("d" * 40)
        pinned = config(pin)
    images = {k: v["image"] for k, v in pinned["services"].items()}
    assert images["web-game"] == "ghcr.io/peppone-choi/opensamguk:web-game-" + pin
    assert images["game-api"] == "ghcr.io/peppone-choi/opensamguk:game-api-" + values["IMAGE_TAG"]
    assert images["game-engine"] == "ghcr.io/peppone-choi/opensamguk:game-engine-" + values["IMAGE_TAG"]
    baseline["services"]["web-game"]["image"] = images["web-game"]
    assert baseline == pinned, "Changing the pin changed another Compose setting"
    assert compose.read_bytes() == before
    result = {"composeVersion": version, "composeSourceSha256": digest(before),
              "images": images, "onlyWebImageChanged": True,
              "containersStarted": 0, "pulls": 0, "environment": "synthetic only"}
    (evidence / "compose-config-summary.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main():
    if os.environ.get("CI") != "true" or os.environ.get("GITHUB_ACTIONS") != "true":
        raise SystemExit("This native probe requires isolated GitHub CI")
    evidence = Path(os.environ["RUNNER_TEMP"]) / "web-game-native"
    evidence.mkdir(parents=True, exist_ok=True)
    original = SOURCE.read_bytes()
    expected = set(re.findall(r"^func (Test(?:WebGameDeploy|ConcurrentWebDeploys)\w*)\(",
                              TEST_SOURCE.read_text(), re.MULTILINE))
    assert len(expected) == 10, "Update the reviewed ten-test contract explicitly"
    summary = {"status": "RUNNING", "sourceSha256": digest(original),
               "testSourceSha256": digest(TEST_SOURCE.read_bytes()),
               "expectedTopLevelTests": sorted(expected), "mutations": []}
    try:
        baseline, _ = run_go(evidence, "baseline", PATTERN)
        require_green(baseline, expected)
        summary["baseline"] = baseline
        # Mutate actual production code used by the production mux and test handlers.
        mutations = [
            ("web-up-selects-api", '"--no-deps", "--no-build", "--pull", "never", "web-game"',
             '"--no-deps", "--no-build", "--pull", "never", "game-api"',
             "TestWebGameDeployPersistsOnlyWebDigestAndVerifiesOneContainer", "scope="),
            ("authentication-removed", "return c.withAuth(c.withLoopback(c.handleWebGameDeploy))",
             "return c.withLoopback(c.handleWebGameDeploy)",
             "TestWebGameDeployPreservesAuthenticationLoopbackAndMaintenanceAdmission",
             "unauthorized call reached Docker"),
            ("loopback-removed", "return c.withAuth(c.withLoopback(c.handleWebGameDeploy))",
             "return c.withAuth(c.handleWebGameDeploy)",
             "TestWebGameDeployPreservesAuthenticationLoopbackAndMaintenanceAdmission",
             "unauthorized call reached Docker"),
        ]
        for label, needle, replacement, test, expected_message in mutations:
            assert original.count(needle.encode()) == 1, label + " mutation marker is not unique"
            try:
                SOURCE.write_bytes(original.replace(needle.encode(), replacement.encode(), 1))
                result, events = run_go(evidence, label, "^" + test + "$")
                output = "".join(e.get("Output", "") for e in events if e.get("Test") == test)
                assert result["exit"] != 0 and test in result["fail"] and not result["skip"]
                assert expected_message in output, "Mutation failed for an unrelated reason"
                summary["mutations"].append({"label": label, **result, "requiredRegressionRed": True})
            finally:
                SOURCE.write_bytes(original)
                assert SOURCE.read_bytes() == original
        restored, _ = run_go(evidence, "restored", PATTERN)
        require_green(restored, expected)
        summary["restored"] = restored
        summary["compose"] = compose_probe(evidence)
        summary["status"] = "PASS"
    finally:
        if summary["status"] != "PASS":
            summary["status"] = "FAIL"
        SOURCE.write_bytes(original)
        summary["restoredSourceSha256"] = digest(SOURCE.read_bytes())
        summary["byteRestored"] = SOURCE.read_bytes() == original
        (evidence / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
