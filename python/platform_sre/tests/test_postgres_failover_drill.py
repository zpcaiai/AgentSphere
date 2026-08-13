from pathlib import Path
import tempfile
import unittest

from python.platform_sre.postgres_failover_drill import DrillError, run_drill


class PostgresFailoverDrillTests(unittest.TestCase):
    def test_broad_or_relative_work_root_is_denied_before_execution(self):
        with self.assertRaises(DrillError):
            run_drill(Path("relative"), Path("/"), "release", 55431, 55432)
        with tempfile.TemporaryDirectory() as raw:
            with self.assertRaises(DrillError):
                run_drill(Path("relative"), Path(raw), "bad release", 55431, 55431)


if __name__ == "__main__":
    unittest.main()
