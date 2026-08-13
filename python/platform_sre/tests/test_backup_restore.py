from pathlib import Path
import tempfile
import unittest

from python.platform_sre.backup_restore import BackupConfig, BackupController, _postgres_env


class FakeRunner:
    def run(self, args, *, env, timeout):
        file_arg = next((item for item in args if item.startswith("--file=")), None)
        if file_arg:
            Path(file_arg.split("=", 1)[1]).write_bytes(b"pg-dump")
            return b""
        if "cms" in args and "-out" in args:
            destination = Path(args[args.index("-out") + 1])
            source = Path(args[args.index("-in") + 1])
            destination.write_bytes(source.read_bytes())
            return b""
        command = next((item for item in args if item.startswith("--command=")), "")
        if "pg_catalog.pg_class" in command:
            return b"0\n"
        if "pg_current_wal_lsn" in command:
            return b"0/1234\n"
        if "count(*)" in command:
            return b"3\n"
        if "--list" in args:
            return b"TABLE DATA public tasks\n"
        return b""


class BackupRestoreTests(unittest.TestCase):
    def test_database_url_requires_tls_and_hides_password_from_arguments(self) -> None:
        env = _postgres_env("postgresql://user:secret@db.example/agenttrust?sslmode=verify-full")
        self.assertEqual(env["PGPASSWORD"], "secret")
        with self.assertRaisesRegex(ValueError, "BACKUP_DATABASE_URL_INVALID"):
            _postgres_env("postgresql://user:secret@db.example/agenttrust?sslmode=disable")

    def test_encrypted_backup_and_tamper_detection(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            objects = root / "objects"
            objects.mkdir()
            (objects / "evidence.json").write_text("{}", encoding="utf-8")
            cert = root / "cert.pem"
            key = root / "key.pem"
            cert.write_text("cert", encoding="utf-8")
            key.write_text("key", encoding="utf-8")
            config = BackupConfig(
                backup_root=root / "backups",
                object_roots=(objects,),
                encryption_certificate=cert,
                decryption_private_key=key,
                restore_object_root=root / "restored-objects",
                pg_dump=Path("/usr/bin/pg_dump"),
                pg_restore=Path("/usr/bin/pg_restore"),
                psql=Path("/usr/bin/psql"),
                openssl=Path("/usr/bin/openssl"),
                maximum_object_files=10,
                maximum_object_bytes=1024,
                record_count_tables=("orchestrator_tasks",),
                command_timeout_seconds=10,
            )
            controller = BackupController(config, FakeRunner())
            manifest = controller.create(
                backup_id="backup-1",
                release_digest="a" * 64,
                key_version="kms-v1",
                database_url="postgresql://user:secret@db.example/agenttrust?sslmode=require",
                ledger_head_digest="b" * 64,
            )
            self.assertTrue(manifest["encrypted"])
            report = controller.verify_restore(
                "backup-1",
                database_url="postgresql://user:secret@db.example/agenttrust?sslmode=require",
            )
            self.assertTrue(report["database_archive_verified"])
            self.assertTrue(report["actual_restore_executed"])
            self.assertTrue(
                (config.restore_object_root / "backup-1" / "objects" / "evidence.json").is_file()
            )
            (config.backup_root / "backup-1" / "database.dump.cms").write_bytes(b"tampered")
            with self.assertRaisesRegex(RuntimeError, "RESTORE_MANIFEST_TAMPERED"):
                controller.verify_restore(
                    "backup-1",
                    database_url="postgresql://user:secret@db.example/agenttrust?sslmode=require",
                )


if __name__ == "__main__":
    unittest.main()
