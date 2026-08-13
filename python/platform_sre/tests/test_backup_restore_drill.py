from pathlib import Path
import tempfile
import unittest

from python.platform_sre.backup_restore_drill import (
    BackupRestoreDrillError,
    run_drill,
)


class BackupRestoreDrillTests(unittest.TestCase):
    def test_invalid_or_missing_real_binaries_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            openssl = root / "openssl"
            openssl.write_bytes(b"")
            with self.assertRaisesRegex(
                BackupRestoreDrillError, "BACKUP_RESTORE_DRILL_BINARY_MISSING"
            ):
                run_drill(root, openssl, root, "release-1", 55441, 55442)


if __name__ == "__main__":
    unittest.main()
