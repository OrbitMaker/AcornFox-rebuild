from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
SPEC = ROOT / "api/openapi/openapi.yaml"
FIXTURE = ROOT / "tests/fixtures/gate3/api-contract/ui-facing-contract-v1.json"
GENERATED = ROOT / "web/src/api/generated-schema.ts"
HTTP_METHODS = {"get", "put", "post", "delete", "patch", "head", "options", "trace"}


class Gate3OpenAPIContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.text = SPEC.read_text(encoding="utf-8")
        self.spec = yaml.safe_load(self.text)
        self.fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        self.paths = self.spec["paths"]
        self.components = self.spec["components"]

    def operation(self, label: str) -> dict:
        method, path = label.split(" ", 1)
        return self.paths[path][method.lower()]

    def test_ui_paths_operation_ids_and_handler_boundary_are_frozen(self) -> None:
        for label, operation_id in self.fixture["ui_operations"].items():
            operation = self.operation(label)
            self.assertEqual(operation["operationId"], operation_id)
            self.assertEqual(operation["x-open-card-handler-status"], self.fixture["handler_status"])
        self.assertIn("/api/v1/access/platform-domains", self.paths, "M3 internal compatibility path must remain declared")
        self.assertIn("ApplicationDetail", self.components["schemas"])
        detail = self.paths["/api/v1/applications/{applicationId}"]["get"]
        self.assertEqual(detail["x-open-card-handler-status"], "partial_contract")
        self.assertEqual(detail["responses"]["200"]["content"]["application/json"]["schema"]["$ref"], "#/components/schemas/ApplicationDetail")

    def test_operation_ids_are_globally_unique_and_generated_types_match(self) -> None:
        operation_ids = []
        for path in self.paths.values():
            for method, operation in path.items():
                if method in HTTP_METHODS:
                    operation_ids.append(operation["operationId"])
        self.assertEqual(len(operation_ids), len(set(operation_ids)))
        generated = GENERATED.read_text(encoding="utf-8")
        for operation_id in self.fixture["ui_operations"].values():
            self.assertIn(f'operations["{operation_id}"]', generated)

    def test_session_csrf_and_error_contracts_are_uniform(self) -> None:
        self.assertEqual(self.spec["security"], [{self.fixture["session_security_scheme"]: []}])
        for path, path_item in self.paths.items():
            for method, operation in path_item.items():
                if method not in {"post", "put", "patch", "delete"} or (path, method) in {("/api/v1/auth/login", "post"), ("/api/v1/auth/logout", "post"), ("/api/v1/auth/password", "post")}:
                    continue
                parameters = [parameter.get("$ref") for parameter in operation["parameters"]]
                self.assertIn("#/components/parameters/CSRFHeader", parameters)
                self.assertIn("#/components/parameters/RequiredIdempotencyKey" if operation["operationId"] != "createApplication" else "#/components/parameters/IdempotencyKey", parameters)
        for _, response_name in self.fixture["error_responses"].items():
            self.assertIn(response_name, self.components["responses"])
            self.assertEqual(self.components["responses"][response_name].get("content", {}).get("application/json", {}).get("schema", {}).get("$ref"), "#/components/schemas/APIError")

    def test_domain_and_upload_safety_constraints_are_explicit(self) -> None:
        platform = self.components["schemas"]["PlatformDomainSettingsResponse"]
        self.assertEqual(platform["properties"]["status"]["$ref"], "#/components/schemas/DomainLifecycleStatus")
        self.assertIn("<slug>-<short>.apps.<base_domain>", self.operation("PUT /api/v1/settings/platform-domain")["description"])
        custom = self.operation("POST /api/v1/applications/{applicationId}/domains")
        self.assertIn("never writes a customer DNS zone", custom["description"])
        verify = self.operation("POST /api/v1/applications/{applicationId}/domains/{domainId}/verify")
        self.assertIn("never creates", verify["description"])
        upload = self.operation("POST /api/v1/source-uploads")
        self.assertIn("multipart/form-data", upload["requestBody"]["content"])
        schema = self.components["schemas"]["SourceUploadRequest"]
        variants = [self.components["schemas"][item["$ref"].rsplit("/", 1)[1]] for item in schema["oneOf"]]
        self.assertEqual(sorted(variant["properties"]["mode"]["enum"][0] for variant in variants), self.fixture["multipart_modes"])
        archive = next(variant for variant in variants if variant["properties"]["mode"]["enum"] == ["archive"])
        directory = next(variant for variant in variants if variant["properties"]["mode"]["enum"] == ["directory"])
        self.assertEqual(set(archive["required"]), {"mode", "archive"})
        self.assertEqual(set(directory["required"]), {"mode", "files", "manifest"})
        self.assertIn("normalized relative path", directory["properties"]["files"]["description"])
        pattern = re.compile(self.components["schemas"]["SourceUploadManifestEntry"]["properties"]["path"]["pattern"])
        for value in self.fixture["invalid_relative_paths"]:
            self.assertIsNone(pattern.fullmatch(value), value)
        self.assertIn("absolute", self.text.lower())

    def test_sse_reconnect_and_cloud_credential_exclusion_are_declared(self) -> None:
        for path in ("/api/v1/events", "/api/v1/operations/{operationId}/events"):
            operation = self.paths[path]["get"]
            self.assertIn("Last-Event-ID", json.dumps(operation))
            self.assertIn("reconnect", operation["description"])
        lower = self.text.lower()
        for forbidden in self.fixture["forbidden_cloud_terms"]:
            self.assertNotIn(forbidden, lower)


if __name__ == "__main__":
    unittest.main()
