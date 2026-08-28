from __future__ import annotations

import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "migrations" / "control-plane" / "0023_source_uploads.sql"
OPENAPI = ROOT / "api" / "openapi" / "openapi.yaml"
HANDLER = ROOT / "cmd" / "open-card-server" / "g3_source_upload.go"


class G3SourceUploadContractTests(unittest.TestCase):
    def test_migration_is_metadata_only_and_one_time_claimed(self) -> None:
        text = MIGRATION.read_text(encoding="utf-8").lower()
        for required in (
            "create table if not exists source_uploads",
            "create table if not exists source_upload_files",
            "status in ('ready','claimed','expired','failed')",
            "storage_ref = 'upload://' || id",
            "claimed_application_id",
            "claimed_source_revision_id",
            "idempotency_key text not null unique",
        ):
            self.assertIn(required, text)
        for forbidden in ("file_content", "client_path", "absolute_path", "tccli", "dnspod", "secretid", "secretkey"):
            self.assertNotIn(forbidden, text)

    def test_openapi_and_handler_hide_storage_references(self) -> None:
        spec = yaml.safe_load(OPENAPI.read_text(encoding="utf-8"))
        schemas = spec["components"]["schemas"]
        response = schemas["SourceUploadResponse"]
        self.assertEqual(spec["paths"]["/api/v1/source-uploads"]["post"]["x-open-card-handler-status"], "implemented")
        self.assertEqual(spec["paths"]["/api/v1/source-uploads/{uploadId}"]["get"]["x-open-card-handler-status"], "implemented")
        self.assertNotIn("storage_ref", response["properties"])
        source = schemas["CreateApplicationRequest"]["properties"]["source"]
        self.assertEqual(len(source["oneOf"]), 2)
        handler = HANDLER.read_text(encoding="utf-8")
        self.assertIn("sourceUploadResponse", handler)
        self.assertIn("type sourceUploadHTTPResponse struct", handler)
        self.assertNotIn("StorageRef", handler[handler.index("type sourceUploadHTTPResponse struct") : handler.index("func readSourceUploadText")])
        self.assertNotIn("tccli", handler.lower())
        self.assertNotIn("dnspod", handler.lower())


if __name__ == "__main__":
    unittest.main()
