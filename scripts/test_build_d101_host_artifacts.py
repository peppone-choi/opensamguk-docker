"""Pure bounded fixtures: no Go/build/host/network/subprocess calls."""
import argparse
import contextlib
import importlib.util
import io
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("d101_build_driver", Path(__file__).with_name("build-d101-host-artifacts.py"))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


class ControlledHostArtifactBuildTest(unittest.TestCase):
    def test_missing_actual_inputs_never_reach_a_command(self):
        required = ["repo", "source", "app-source", "host-arch-evidence", "host-arch-evidence-sha",
                    "toolchain", "toolchain-sha", "toolchain-version", "toolchain-root", "toolchain-tree-sha", "out", "host-arch",
                    "go-mod-sha256", "go-sum-sha256", "vendor-tree-sha256", "vendor-modules-sha256"]
        for omitted in ("host-arch", "host-arch-evidence", "toolchain-root", "toolchain-tree-sha",
                        "go-mod-sha256", "go-sum-sha256", "vendor-tree-sha256", "vendor-modules-sha256"):
            with self.subTest(omitted=omitted), patch.object(driver, "capture_command", side_effect=AssertionError("command must not run")):
                argv = [value for key in required if key != omitted for value in ("--" + key, "amd64" if key == "host-arch" else "fixture")]
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
                    driver.parser().parse_args(argv)
                self.assertEqual(raised.exception.code, 2)

    def test_elf_must_match_the_actual_architecture(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "artifact"
            for name, machine, kind, architecture, accepted in (
                ("amd64", 62, 2, "amd64", True), ("arm64", 183, 2, "arm64", True),
                ("wrong-machine", 183, 2, "amd64", False), ("dynamic-kind", 62, 3, "amd64", False),
            ):
                with self.subTest(name=name):
                    header = bytearray(64)
                    header[:7] = b"\x7fELF\x02\x01\x01"
                    struct.pack_into("<HH", header, 16, kind, machine)
                    path.write_bytes(header)
                    if accepted:
                        self.assertEqual(driver.inspect_elf(path, architecture)["machine"], machine)
                    else:
                        with self.assertRaises(driver.BuildUnavailable):
                            driver.inspect_elf(path, architecture)

    def test_archive_rejects_traversal_and_links(self):
        for name in ("traversal", "symlink", "hardlink", "regular"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                archive, output = root / "source.tar", root / "out"
                output.mkdir()
                with tarfile.open(archive, "w:") as stream:
                    item = tarfile.TarInfo("deployer/go.mod")
                    wire = b"module synthetic-fixture\n"
                    item.size = len(wire)
                    if name == "traversal":
                        item.name = "deployer/../../escape"
                    elif name in ("symlink", "hardlink"):
                        item.type = tarfile.SYMTYPE if name == "symlink" else tarfile.LNKTYPE
                        item.linkname = "outside"
                        item.size = 0
                    stream.addfile(item, io.BytesIO(wire) if item.isfile() else None)
                if name == "regular":
                    driver.safe_extract_module(archive, output)
                    self.assertEqual((output / "deployer/go.mod").read_bytes(), wire)
                else:
                    with self.assertRaises(driver.BuildUnavailable):
                        driver.safe_extract_module(archive, output)
                    self.assertFalse((root / "escape").exists())

    def test_existing_output_and_symlink_are_never_reused(self):
        for name in ("existing-output", "symlink-output", "new-output"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                repo, tool = root / "repo", root / "tool"
                repo.mkdir()
                (tool / "bin").mkdir(parents=True)
                binary = tool / "bin/go"
                binary.write_bytes(b"synthetic toolchain never executed")
                evidence = root / "actual-observation"
                evidence.write_bytes(b"synthetic bounded architecture observation")
                output = root / "new-output"
                if name == "existing-output":
                    output.mkdir()
                    (output / "preserved").write_bytes(b"existing build")
                elif name == "symlink-output":
                    output.symlink_to(repo, target_is_directory=True)
                args = argparse.Namespace(source="a" * 40, app_source="b" * 40, host_arch="amd64",
                    host_arch_evidence_sha=driver.digest(evidence), host_arch_evidence=str(evidence),
                    toolchain_sha=driver.digest(binary), toolchain_tree_sha="c" * 64,
                    toolchain_version="go version go1.26.8 linux/amd64", toolchain=str(binary), toolchain_root=str(tool),
                    repo=str(repo), out=str(output), **driver.FROZEN_DEPENDENCIES)
                def pure_capture(argv, *_args, **_kwargs):
                    if argv[1:3] == ["rev-parse", "HEAD"]:
                        return (args.source + "\n").encode()
                    if argv[1] == "status":
                        return b""
                    if argv[1] == "show":
                        return Path(driver.__file__).read_bytes()
                    self.fail("fixture tried an unplanned command")
                with patch.object(driver, "capture_command", side_effect=pure_capture), patch.object(driver.subprocess, "run", side_effect=AssertionError("subprocess must not run")):
                    if name == "new-output":
                        self.assertEqual(driver.validate_inputs(args)[3], output)
                        self.assertFalse(output.exists())
                    else:
                        with self.assertRaises(driver.BuildUnavailable):
                            driver.validate_inputs(args)
                        if name == "existing-output":
                            self.assertEqual((output / "preserved").read_bytes(), b"existing build")


class OfflineDependencySourceTest(unittest.TestCase):
    """Disposable data comparators only; never a production input or binary."""

    def test_dependency_comparator_rejects_changed_physical_inputs(self):
        cases = ("intact", "missing-mod", "missing-sum", "truncated-mod", "changed-sum",
                 "extra-vendor", "missing-vendor", "changed-vendor", "changed-modules", "symlink-vendor")
        for name in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                module = Path(temporary).resolve()
                (module / "vendor/fixture").mkdir(parents=True)
                (module / "go.mod").write_bytes(b"synthetic comparator fixture, not enrolled\n")
                (module / "go.sum").write_bytes(b"synthetic sum fixture\n")
                (module / "vendor/modules.txt").write_bytes(b"synthetic modules fixture\n")
                leaf = module / "vendor/fixture/source.go"
                leaf.write_bytes(b"synthetic disposable source\n")
                expected = {"go_mod_sha256": driver.digest(module / "go.mod"),
                            "go_sum_sha256": driver.digest(module / "go.sum"),
                            "vendor_modules_sha256": driver.digest(module / "vendor/modules.txt"),
                            "vendor_tree_sha256": driver.tree_pin(module / "vendor")["sha256"]}
                if name.startswith("missing-"):
                    {"missing-mod": module / "go.mod", "missing-sum": module / "go.sum", "missing-vendor": leaf}[name].unlink()
                elif name == "truncated-mod":
                    (module / "go.mod").write_bytes(b"s")
                elif name == "changed-sum":
                    (module / "go.sum").write_bytes(b"changed")
                elif name == "extra-vendor":
                    (module / "vendor/fixture/extra.go").write_bytes(b"extra")
                elif name == "changed-vendor":
                    leaf.write_bytes(b"changed")
                elif name == "changed-modules":
                    (module / "vendor/modules.txt").write_bytes(b"changed")
                elif name == "symlink-vendor":
                    leaf.unlink()
                    leaf.symlink_to(module / "go.sum")
                with patch.object(driver.subprocess, "run", side_effect=AssertionError("no external command")):
                    if name == "intact":
                        self.assertEqual(driver.check_dependency_tree(module, expected)["pins"], expected)
                    else:
                        with self.assertRaises((driver.BuildUnavailable, OSError)):
                            driver.check_dependency_tree(module, expected)
                    with self.assertRaises(driver.BuildUnavailable):
                        driver.require_frozen_dependencies(module, expected)

    def test_unreviewed_dependency_and_toolchain_pins_refuse_before_commands(self):
        for name in ("module", "sum", "vendor", "modules", "toolchain"):
            with self.subTest(name=name):
                args = argparse.Namespace(source="a" * 40, app_source="b" * 40,
                    host_arch_evidence_sha="c" * 64, toolchain_sha="d" * 64, toolchain_tree_sha="e" * 64,
                    toolchain_version="go version go1.26.8 linux/amd64", **driver.FROZEN_DEPENDENCIES)
                if name == "toolchain":
                    args.toolchain_version = "go version go1.26.5 linux/amd64"
                else:
                    field = {"module": "go_mod_sha256", "sum": "go_sum_sha256", "vendor": "vendor_tree_sha256", "modules": "vendor_modules_sha256"}[name]
                    setattr(args, field, "f" * 64)
                with patch.object(driver, "capture_command", side_effect=AssertionError("no command")), self.assertRaises(driver.BuildUnavailable):
                    driver.validate_inputs(args)

    def test_actual_metadata_shape_requires_exact_artifact_role(self):
        def wire(role):
            suffix = driver.ARTIFACT_ROLES[role].removeprefix("./")
            package = "opensamguk-deployer" + ("/" + suffix if suffix != "." else "")
            stamp = " -X main.rootBuiltSourceSHA=" + "a" * 40 if role == "deployer" else ""
            return ("/synthetic-never-executed:\tgo1.26.8\n\tpath\t" + package + "\n"
                    "\tmod\topensamguk-deployer\t(devel)\t\n"
                    "\tdep\tgolang.org/x/crypto\tv0.57.0\t\n\tdep\tgolang.org/x/sys\tv0.48.0\t\n"
                    "\tbuild\t-ldflags=\"-s -w" + stamp + "\"\n"
                    "\tbuild\tCGO_ENABLED=0\n\tbuild\tGOOS=linux\n\tbuild\tGOARCH=amd64\n")
        for role in driver.ARTIFACT_ROLES:
            with self.subTest(role=role):
                self.assertEqual(driver.validate_artifact_metadata(wire(role), role, "a" * 40, "amd64")["role"], role)
        good = wire("deployer")
        cases = {
            "old-go": good.replace("go1.26.8", "go1.26.5"),
            "wrong-package": good.replace("\tpath\topensamguk-deployer", "\tpath\tother"),
            "missing-root": good.replace("\tmod\topensamguk-deployer\t(devel)\t\n", ""),
            "duplicate-root": good + "\tmod\topensamguk-deployer\t(devel)\t\n",
            "wrong-version": good.replace("v0.57.0", "v0.41.0"),
            "missing-dep": good.replace("\tdep\tgolang.org/x/sys\tv0.48.0\t\n", ""),
            "extra-dep": good + "\tdep\tother/module\tv1.0.0\n",
            "replace": good + "\t=>\tlocal/override\t(devel)\n",
            "invented-vendor-sum": good.replace("v0.57.0\t", "v0.57.0\th1:invented"),
            "wrong-arch": good.replace("GOARCH=amd64", "GOARCH=arm64"),
            "wrong-cgo": good.replace("CGO_ENABLED=0", "CGO_ENABLED=1"),
            "ambient-vcs": good + "\tbuild\tvcs.revision=synthetic\n",
            "missing-stamp": good.replace("main.rootBuiltSourceSHA=", "unrelated.stamp="),
            "duplicate-setting": good + "\tbuild\tGOOS=linux\n",
            "unknown-record": good + "\tunknown\tsynthetic\n",
        }
        for name, metadata in cases.items():
            with self.subTest(name=name), self.assertRaises(driver.BuildUnavailable):
                driver.validate_artifact_metadata(metadata, "deployer", "a" * 40, "amd64")


if __name__ == "__main__":
    unittest.main()
