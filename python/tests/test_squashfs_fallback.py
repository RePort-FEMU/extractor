#!/usr/bin/env python
"""
Regression tests for the SquashFS root-filesystem recovery fixes in
``femu_extractor.extractor``:

* Fix 1 -- ``_check_rootfs`` no longer aborts when binwalk returns an earlier
  filesystem (e.g. a JFFS2 log/config partition) that is rejected before the
  real SquashFS root.
* Fix 2 -- standard little-endian SquashFS 4.0 / XZ images that sasquatch
  mis-handles fall back to stock ``unsquashfs``.
* Fix 3 -- SquashFS variants whose superblock binwalk's parser rejects
  (big-endian ``sqsh``, LZMA ``sqlz``/``tqsh``, byte-swapped ``shsq``/``qshs``)
  are recovered by a raw magic scan + carve.

RAR and EXT filesystems are NOT handled in Python: the bundled binwalk engine
extracts them natively via ``unrar`` and ``tsk_recover`` respectively. The
RAR/EXT cases here are regression coverage that those native paths still reach
a valid rootfs through the pipeline; they skip when the tools are absent.

The superblock-validation tests are pure logic and run anywhere. The
end-to-end extraction tests need the (large, gitignored) firmware corpus and
the external extractors (sasquatch/unsquashfs/jefferson); they skip
themselves when those are unavailable, so they exercise the real pipeline
inside the ``femu:test`` image while staying inert in CI.

Run with: ``python -m unittest femu_extractor`` is importable, e.g.
``PYTHONPATH=python python -m unittest discover -s python/tests``
"""

import os
import shutil
import tarfile
import tempfile
import unittest

from femu_extractor import extract
from femu_extractor.extractor import Extractor, ExtractionItem

# Firmware corpus location: override with FEMU_FW_DIR, else repo-local failed_fw/.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FW_DIR = os.environ.get("FEMU_FW_DIR", os.path.join(_REPO_ROOT, "failed_fw"))

# Representative firmwares, one per fixed class. Each must go from
# rootfs-not-found to a valid Linux root tree. The value is (filename, tools)
# where `tools` lists the external extractors that must be on PATH for the
# case to run (the test skips otherwise).
#
# RAR and EXT are extracted natively by the bundled binwalk engine (unrar and
# tsk_recover respectively); only Fixes 1-3 (SquashFS) live in the Python layer.
FIRMWARES = {
    "fix1_jffs2_then_squashfs": ("TEG-082WS_1.00.010.zip", ("sasquatch",)),
    "fix2_le_squashfs4_xz": ("R7900-V1.0.1.8_10.0.14.zip", ("unsquashfs",)),
    "fix3_be_sqsh": ("dir300_v1.03_7c.bin", ("sasquatch",)),
    "fix3_lzma_sqlz": ("DM111Pv2_Firmware_Version_2.00.25.zip", ("sasquatch",)),
    "rar_native_unrar": ("TEW-712BR_v1.0R.rar", ("unrar", "sasquatch")),
    "ext_native_tsk": ("FW_WAP610N_v1.0.05.002_20140321.bin", ("tsk_recover",)),
}


class TestSquashfsSuperblock(unittest.TestCase):
    """Pure-logic checks for the version-agnostic superblock validator."""

    @staticmethod
    def _superblock(magic, s_major, s_minor, endian):
        # Lay the version field at byte +28 like a real SquashFS superblock.
        import struct
        buf = bytearray(96)
        buf[0:4] = magic
        struct.pack_into(endian + "HH", buf, 28, s_major, s_minor)
        return bytes(buf)

    def test_accepts_little_endian_v4(self):
        # Standard hsqs 4.0 (Netgear R7900 class).
        data = self._superblock(b"hsqs", 4, 0, "<")
        self.assertTrue(ExtractionItem._valid_squashfs_superblock(data, 0))

    def test_accepts_big_endian_sqsh_v2(self):
        # Realtek big-endian sqsh, version 2.0 (D-Link dir300 class).
        data = self._superblock(b"sqsh", 2, 0, ">")
        self.assertTrue(ExtractionItem._valid_squashfs_superblock(data, 0))

    def test_accepts_lzma_sqlz_v2_1(self):
        # LZMA sqlz, version 2.1 with non-zero minor (DM111Pv2 class).
        data = self._superblock(b"sqlz", 2, 1, ">")
        self.assertTrue(ExtractionItem._valid_squashfs_superblock(data, 0))

    def test_rejects_bogus_version(self):
        # A random 4-byte magic collision inside compressed data: implausible
        # version field in both endiannesses.
        import struct
        buf = bytearray(96)
        buf[0:4] = b"hsqs"
        struct.pack_into("<HH", buf, 28, 9999, 9999)
        self.assertFalse(ExtractionItem._valid_squashfs_superblock(bytes(buf), 0))

    def test_rejects_truncated(self):
        self.assertFalse(ExtractionItem._valid_squashfs_superblock(b"hsqs", 0))


class TestFirmwareExtraction(unittest.TestCase):
    """
    End-to-end: extract each representative firmware and assert io_find_rootfs
    accepts the resulting tree. Skips when the corpus or extractors are absent.
    """

    @classmethod
    def setUpClass(cls):
        cls._tmp = []

    @classmethod
    def tearDownClass(cls):
        for d in getattr(cls, "_tmp", []):
            shutil.rmtree(d, ignore_errors=True)

    def _extract_and_validate(self, key):
        filename, tools = FIRMWARES[key]
        missing = [t for t in tools if not shutil.which(t)]
        if missing:
            self.skipTest("required tools not on PATH: %s" % ", ".join(missing))

        path = os.path.join(FW_DIR, filename)
        if not os.path.isfile(path):
            self.skipTest("firmware not present: %s" % path)

        out = tempfile.mkdtemp()
        self._tmp.append(out)
        results = extract(path, output_dir=out, kernel=False, numproc=False)

        tarball = next((r["rootfsPath"] for r in results
                        if r["rootfsDone"] and r["rootfsPath"]), None)
        self.assertIsNotNone(tarball, "no rootfs extracted from %s" % filename)
        self.assertTrue(os.path.isfile(tarball))

        extracted = tempfile.mkdtemp()
        self._tmp.append(extracted)
        with tarfile.open(tarball) as tf:
            tf.extractall(extracted, filter="fully_trusted")

        valid, root = Extractor.io_find_rootfs(extracted)
        self.assertTrue(valid, "io_find_rootfs rejected tree from %s" % filename)
        unix_dirs = [d for d in os.listdir(root) if d in Extractor.UNIX_DIRS]
        self.assertGreaterEqual(len(unix_dirs), Extractor.UNIX_THRESHOLD,
                                "too few UNIX dirs in %s: %s" % (filename, unix_dirs))

    def test_fix1_jffs2_then_squashfs(self):
        self._extract_and_validate("fix1_jffs2_then_squashfs")

    def test_fix2_le_squashfs4_xz(self):
        self._extract_and_validate("fix2_le_squashfs4_xz")

    def test_fix3_be_sqsh(self):
        self._extract_and_validate("fix3_be_sqsh")

    def test_fix3_lzma_sqlz(self):
        self._extract_and_validate("fix3_lzma_sqlz")

    def test_rar_native_unrar(self):
        # RAR is extracted by binwalk natively (unrar); the inner image then
        # yields a SquashFS rootfs through the normal pipeline.
        self._extract_and_validate("rar_native_unrar")

    def test_ext_native_tsk(self):
        # EXT is extracted by binwalk natively (tsk_recover) after the Python
        # recursion decompresses the LZMA-wrapped filesystem.
        self._extract_and_validate("ext_native_tsk")


if __name__ == "__main__":
    unittest.main()
