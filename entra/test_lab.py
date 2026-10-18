"""Offline contract tests; synthetic signatures are NOT Entra proof."""

import datetime as dt
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

import lab


class AuthorizationTests(unittest.TestCase):
    def test_owner_check_uses_oid_not_caller_or_display_name(self):
        claims = {"oid": "alice", "azp": "api-a", "scp": "Docs.Read"}
        self.assertEqual(lab.authorize_delegated(claims, "alice"), "allow")
        self.assertEqual(lab.authorize_delegated(claims, "bob"), "wrong_owner")

    def test_scope_is_exact_and_app_role_does_not_become_delegation(self):
        for claims in (
            {"oid": "alice", "scp": "Docs.Read.All"},
            {"oid": "alice", "scp": "Docs.Metadata"},
            {"oid": "alice", "roles": ["Docs.Read.All"]},
        ):
            self.assertEqual(lab.authorize_delegated(claims, "alice"), "missing_scope")

    def test_real_omitted_scope_not_requested_scope_controls_negative(self):
        claims = {"oid": "alice", "scp": "Docs.Read"}
        self.assertEqual(lab.authorize_delegated(
            claims, "alice", "Docs.Metadata"), "missing_scope")
        claims["scp"] = "Docs.Read Docs.Metadata"
        self.assertEqual(lab.authorize_delegated(claims, "alice"), "allow")

    def test_app_only_requires_role_and_expected_caller(self):
        claims = {"roles": ["Docs.Read.All"], "azp": "api-a", "oid": "sp-a"}
        self.assertEqual(lab.authorize_application(claims, "api-a"), "allow")
        self.assertEqual(lab.authorize_application(claims, "other"), "wrong_application")
        claims["scp"] = "Docs.Read"
        self.assertEqual(lab.authorize_application(claims, "api-a"), "missing_application_role")


class TokenValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def setUp(self):
        self.validator = lab.Validator.__new__(lab.Validator)
        self.validator.tenant = "tenant"
        self.validator.issuer = "https://login.microsoftonline.com/tenant/v2.0"
        self.validator.keys = SimpleNamespace(
            get_signing_key_from_jwt=lambda _: SimpleNamespace(key=self.key.public_key()))
        current = int(dt.datetime.now(dt.timezone.utc).timestamp())
        self.claims = {
            "iss": self.validator.issuer, "aud": "api-b", "tid": "tenant",
            "oid": "alice", "ver": "2.0", "iat": current,
            "nbf": current - 1, "exp": current + 300, "scp": "Docs.Read",
        }

    def token(self, key=None):
        return jwt.encode(self.claims, key or self.key, algorithm="RS256")

    def test_accepts_correct_signature_issuer_audience_and_lifetime(self):
        self.assertEqual(self.validator.validate(self.token(), "api-b")["oid"], "alice")

    def test_rejects_wrong_audience(self):
        with self.assertRaises(jwt.InvalidAudienceError):
            self.validator.validate(self.token(), "api-a")

    def test_rejects_wrong_signature(self):
        with self.assertRaises(jwt.InvalidSignatureError):
            self.validator.validate(self.token(self.wrong_key), "api-b")

    def test_rejects_wrong_issuer(self):
        self.claims["iss"] = "https://invalid.example"
        with self.assertRaises(jwt.InvalidIssuerError):
            self.validator.validate(self.token(), "api-b")

    def test_rejects_expired_token(self):
        self.claims["exp"] = self.claims["iat"] - 120
        with self.assertRaises(jwt.ExpiredSignatureError):
            self.validator.validate(self.token(), "api-b")

    def test_rejects_missing_expiry(self):
        self.claims.pop("exp")
        with self.assertRaises(jwt.MissingRequiredClaimError):
            self.validator.validate(self.token(), "api-b")

    def test_rejects_wrong_tenant_and_v1(self):
        for key, value in (("tid", "different"), ("ver", "1.0")):
            previous = self.claims[key]
            self.claims[key] = value
            with self.assertRaises(jwt.InvalidTokenError):
                self.validator.validate(self.token(), "api-b")
            self.claims[key] = previous

    def test_rejects_future_nbf(self):
        self.claims["nbf"] = self.claims["iat"] + 120
        with self.assertRaises(jwt.ImmatureSignatureError):
            self.validator.validate(self.token(), "api-b")


class PrivacyAndSafetyTests(unittest.TestCase):
    def test_report_rejects_real_identifier_token_url_or_email(self):
        for value in (
            str(uuid.UUID(int=1)),
            jwt.encode({"offline_fixture": True},
                       b"synthetic-unit-test-key-not-a-credential" * 2, algorithm="HS256"),
            "https://tenant.example", "alice@tenant.example",
        ):
            with self.subTest(value=value), self.assertRaises(lab.Blocked):
                lab.save_report({"value": value})

    def test_blocker_omits_untrusted_messages(self):
        error = lab.Blocked("create_api_a", "Authorization_RequestDenied", status=403)
        self.assertEqual(error.public(), {
            "stage": "create_api_a", "code": "Authorization_RequestDenied", "http_status": 403})
        self.assertEqual(lab.Blocked("a", "secret text").code, "UnclassifiedError")

    def test_report_rejects_sensitive_fields_even_if_opaque_value_is_not_jwt(self):
        for field in ("client_secret", "access_token", "refreshToken", "assertion"):
            with self.subTest(field=field), self.assertRaises(lab.Blocked):
                lab.save_report({"nested": [{field: "opaque-sensitive-value"}]})

    def test_graph_encodes_filter_spaces_without_altering_odata(self):
        graph = lab.Graph.__new__(lab.Graph)
        graph.token = "in-memory-test-token"
        with patch("lab.json_request", return_value={}) as request:
            graph.call("GET", "/servicePrincipals?$filter=appId eq 'public'&$select=id",
                       "lookup")
        url = request.call_args.args[0]
        self.assertNotIn(" ", url)
        self.assertIn("appId%20eq%20'public'", url)

    def test_cli_failure_does_not_leak_message_or_token(self):
        failure = SimpleNamespace(returncode=1, stdout="a raw secret", stderr=(
            "AADSTS50076: user@private.example requires MFA in tenant private"))
        with patch("lab.shutil.which", return_value="az.cmd"), patch(
                "lab.subprocess.run", return_value=failure):
            with self.assertRaises(lab.Blocked) as context:
                lab.cli_json(["account", "get-access-token"], "silent")
        self.assertEqual(context.exception.public()["code"], "AADSTS50076")
        self.assertNotIn("private", json.dumps(context.exception.public()))

    def test_ownership_guard_prevents_existing_app_patch_or_delete(self):
        state = SimpleNamespace(data={
            "prefix": "shoten21-obo-test",
            "apps": {"a": {"id": "id", "appId": "client", "displayName": "existing-app"}},
        })
        graph = SimpleNamespace(call=lambda *args: {
            "id": "id", "appId": "client", "displayName": "existing-app"})
        with self.assertRaises(lab.Blocked) as context:
            lab.owned_application(graph, state, "a")
        self.assertEqual(context.exception.code, "OwnershipGuardFailed")

    def test_manifest_restricts_custom_resources_and_principal_consent(self):
        manifest = json.loads((Path(__file__).parent / "lab-manifest.json").read_text(
            encoding="utf-8-sig"))
        self.assertEqual(manifest["maximum_new_applications"], 2)
        self.assertEqual(manifest["consent"]["type"], "Principal")
        self.assertEqual(manifest["obo_protocol"]["requested_token_use"], "on_behalf_of")

    def test_scope_definitions_are_persisted_before_preauthorization(self):
        calls = []
        apps = {
            name: {"id": f"id-{name}", "appId": f"client-{name}",
                   "spId": f"sp-{name}", "displayName": f"shoten21-obo-test-api-{name}"}
            for name in ("a", "b")
        }
        store = SimpleNamespace(data={
            "apps": apps, "prefix": "shoten21-obo-test",
            "user": "user", "grants": [], "assignments": [],
        }, save=lambda: None)

        def call(method, path, stage, body=None):
            calls.append((method, stage, body))
            if stage == "verify_owned_application":
                return apps["a" if "id-a" in path else "b"]
            if stage == "lookup_existing_cli_sp":
                return {"value": []}
            return {}

        with patch("lab.record"), self.assertRaises(lab.Blocked) as error:
            lab.configure_created_apps(SimpleNamespace(call=call), store, lab.new_report())
        self.assertEqual(error.exception.code, "ExistingCliServicePrincipalRequired")
        patches = [item for item in calls if item[0] == "PATCH"]
        self.assertEqual([item[1] for item in patches], [
            "configure_api_b", "configure_api_a",
            "preauthorize_cli_for_api_b", "preauthorize_cli_for_api_a"])
        for item in patches[:2]:
            self.assertNotIn("preAuthorizedApplications", item[2]["api"])
        for item in patches[2:]:
            self.assertIn("preAuthorizedApplications", item[2]["api"])


class CleanupTests(unittest.TestCase):
    def test_never_deletes_changed_or_tenant_wide_consent(self):
        for changed in ({"consentType": "AllPrincipals"},
                        {"scope": "unrelated"}, {"principalId": "someone-else"}):
            grant = {
                "id": "grant-id", "clientId": "client", "resourceId": "resource",
                "principalId": "user", "scope": "Docs.Read",
            }
            calls = []

            def call(method, path, stage, body=None):
                calls.append(method)
                return {**grant, "consentType": "Principal", **changed}

            store = SimpleNamespace(
                data={"grants": [grant], "assignments": [], "apps": {}}, save=lambda: None)
            with self.subTest(changed=changed), self.assertRaises(lab.Blocked):
                lab.cleanup(SimpleNamespace(call=call), store, lab.new_report())
            self.assertEqual(calls, ["GET"])

    def test_never_deletes_changed_app_role_assignment(self):
        assignment = {"id": "assignment-id", "resourceId": "lab-b",
                      "principalId": "lab-a", "appRoleId": "role"}
        calls = []

        def call(method, path, stage, body=None):
            calls.append(method)
            return {**assignment, "principalId": "unrelated"}

        store = SimpleNamespace(data={
            "grants": [], "assignments": [assignment], "apps": {},
        }, save=lambda: None)
        with self.assertRaises(lab.Blocked):
            lab.cleanup(SimpleNamespace(call=call), store, lab.new_report())
        self.assertEqual(calls, ["GET"])

    def test_exact_grant_deleted_and_local_secret_removed(self):
        grant = {"id": "new-grant", "clientId": "cli", "resourceId": "new-api",
                 "principalId": "user", "scope": "Docs.Read"}
        calls = []

        def call(method, path, stage, body=None):
            calls.append((method, path))
            return {**grant, "consentType": "Principal"} if method == "GET" else {}

        store = SimpleNamespace(data={
            "grants": [grant], "assignments": [], "apps": {},
            "credential": {"secret": "synthetic-only"},
        }, save=lambda: None)
        report = lab.new_report()
        with patch("lab.record"):
            lab.cleanup(SimpleNamespace(call=call), store, report)
        self.assertEqual(calls, [
            ("GET", "/oauth2PermissionGrants/new-grant"),
            ("DELETE", "/oauth2PermissionGrants/new-grant"),
        ])
        self.assertNotIn("credential", store.data)
        self.assertEqual(report["cleanup"], "completed_exact_recorded_objects")

    def test_cleanup_missing_recorded_grant_is_idempotent(self):
        def call(*args, **kwargs):
            raise lab.Blocked("verify_created_grant", "Request_ResourceNotFound", status=404)

        store = SimpleNamespace(data={
            "grants": [{"id": "already-gone"}], "assignments": [], "apps": {},
        }, save=lambda: None)
        with patch("lab.record"):
            lab.cleanup(SimpleNamespace(call=call), store, lab.new_report())
        self.assertEqual(store.data["grants"], [])


if __name__ == "__main__":
    unittest.main()
