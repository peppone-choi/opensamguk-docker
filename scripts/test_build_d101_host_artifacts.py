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
                    "toolchain", "toolchain-sha", "toolchain-version", "toolchain-root", "toolchain-tree-sha", "out", "host-arch"]
        for omitted in ("host-arch", "host-arch-evidence", "toolchain-root", "toolchain-tree-sha"):
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
                    toolchain_version="synthetic never executed", toolchain=str(binary), toolchain_root=str(tool),
                    repo=str(repo), out=str(output))
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


if __name__ == "__main__":
    unittest.main()
