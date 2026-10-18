"""Safety regressions. All fixtures below are synthetic and never published."""

import copy
import datetime as dt
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

import lab
import report_safety as safety


def valid_report():
    report = lab.new_report()
    report.update(status="succeeded", proof_status="complete", finished_at=lab.now())
    report["capability"] = {
        "default_user_allowed_to_create_apps": False,
        "application_management_role_available": True, "policy_changed": False,
        "role_is_not_policy_bypass": True,
        "creation_capability": "verified_by_graph_creation",
    }
    report["operations"] = [{"operation": name, "status": "succeeded"} for name in (
        "create_api_a", "create_api_b", "create_api_a_sp", "create_api_b_sp",
        "assign_new_lab_role_between_new_sps", "create_24h_lab_secret",
        "create_principal_only_consent", "create_principal_only_consent",
        "create_principal_only_consent")]
    for name in safety.TOKENS:
        app_only = name == "api_b_app_only"
        report["tokens"][name] = {
            "signature_issuer_audience_lifetime": "verified", "ver": "2.0",
            "aud": "[API_A]" if name == "api_a_input" else "[API_B]",
            "azp": "[API_A]" if name in {"api_b_obo", "api_b_app_only"} else "[AZURE_CLI]",
            "oid": "[API_A_SP]" if app_only else "[USER_A]",
            "tid": "[TENANT]", "iss": "[TENANT_V2_ISSUER]",
            "scp": ([] if app_only else ["access_as_user"] if name == "api_a_input"
                    else ["Docs.Read"] if name == "api_b_obo"
                    else ["Docs.Metadata", "Docs.Read"]),
            "roles": ["Docs.Read.All"] if app_only else [], "lifetime_seconds": 3600,
        }
        report["token_attempts"][name] = 1
    report["experiments"] = [
        {"name": name, "actual": expected, "expected": expected, "passed": True}
        for name, expected in safety.EXPECTED.items()
    ]
    report["relationships"] = safety.relationships(report["tokens"])
    report["resource_audit"] = {
        "checked_at": lab.now(), "checks": {key: True for key in safety.AUDIT_CHECKS}}
    report["integrity"] = {
        "kind": "local_private_run_hmac", "origin": "live_local_capture",
        "bound_at": lab.now(), "remote_attestation": False,
    }
    report["finished_at"] = lab.now()
    return report


class ReportSafetyTests(unittest.TestCase):
    def test_valid_synthetic_report_passes_schema_and_consistency(self):
        lab.validate_report(valid_report(), final=True)

    def test_unknown_field_or_non_guid_identifier_is_rejected(self):
        for patcher in (
            lambda r: r.update(customer="opaque-customer-handle"),
            lambda r: r["capability"].update(customer="opaque-customer-handle"),
            lambda r: r["tokens"]["api_b_obo"].update(oid="opaque-user-handle"),
            lambda r: r["tokens"]["api_b_obo"].update(scp=["customer-read-secret"]),
            lambda r: r["tokens"]["api_b_obo"].update(roles=["private-team-role"]),
            lambda r: r["operations"].append({"operation": "private-account", "status": "succeeded"}),
            lambda r: r["blockers"].append({"stage": "obo", "code": "customer-secret", "http_status": 403}),
            lambda r: r["tokens"]["api_b_obo"].update(iss="tenant-private-host"),
            lambda r: r["tokens"]["api_b_obo"].update(azp="[MY_CUSTOMER]"),
        ):
            report = valid_report()
            patcher(report)
            with self.assertRaises(lab.Blocked):
                lab.validate_report(report)

    def test_actual_role_names_cannot_be_published(self):
        report = valid_report()
        report["capability"] = {
            "default_user_allowed_to_create_apps": False,
            "documented_application_management_roles": ["Global Administrator"],
            "policy_changed": False, "role_is_not_policy_bypass": True,
            "creation_capability": "verified_by_graph_creation",
        }
        with self.assertRaises(lab.Blocked):
            lab.validate_report(report)

    def test_unknown_error_and_stage_are_not_exported(self):
        error = lab.Blocked("private-account-handle", "opaque-secret")
        self.assertEqual(error.public(), {
            "stage": "local_execution", "code": "UnclassifiedError", "http_status": None})

    def test_empty_success_is_not_proof(self):
        report = lab.new_report()
        report.update(status="succeeded", proof_status="complete")
        with self.assertRaises(lab.Blocked):
            lab.validate_report(report)

    def test_forged_pass_flags_or_relationships_are_rejected(self):
        for mutation in (
            lambda r: r["experiments"][0].update(actual="wrong_owner", passed=True),
            lambda r: r["tokens"]["api_b_obo"].update(oid="[OTHER_ACTOR]"),
            lambda r: r["relationships"].update(obo_caller_is_api_a=False),
            lambda r: r["token_attempts"].update(api_b_obo=0),
        ):
            report = valid_report()
            mutation(report)
            with self.assertRaises(lab.Blocked):
                lab.validate_report(report)

    def test_final_requires_exhaustive_audit(self):
        report = valid_report()
        report["resource_audit"]["checks"].pop("no_unrecorded_or_tenant_wide_grants")
        with self.assertRaises(lab.Blocked):
            lab.validate_report(report, final=True)

    def test_hmac_binds_to_exact_private_run_and_detects_safe_enum_tampering(self):
        store = lab.PrivateStore.__new__(lab.PrivateStore)
        store.data = {"run": "a" * 32}
        store.save = lambda: None
        report = valid_report()
        store.bind_report(report)
        store.verify_report(report)
        edited = copy.deepcopy(report)
        edited["tokens"]["api_b_obo"]["lifetime_seconds"] += 1
        lab.validate_report(edited)  # Safe and consistent, but not the recorded observation.
        with self.assertRaises(lab.Blocked):
            store.verify_report(edited)
        with self.assertRaises(lab.Blocked):
            store.bind_report(edited)
        store.data["run"] = "b" * 32
        with self.assertRaises(lab.Blocked):
            store.verify_report(report)

    def test_binding_missing_and_reimport_both_fail_closed(self):
        store = lab.PrivateStore.__new__(lab.PrivateStore)
        store.data = {"run": "a" * 32}
        store.save = lambda: None
        with self.assertRaises(lab.Blocked):
            store.verify_report(valid_report())
        store.bind_report(valid_report())
        with self.assertRaises(lab.Blocked):
            store.bind_report(valid_report(), importing=True)

    def test_verify_command_never_rewrites_or_reseals_the_report(self):
        report = valid_report()
        store = SimpleNamespace(verify_report=lambda _: None)
        with patch.object(lab, "REPORT", SimpleNamespace(
                read_text=lambda **kwargs: json.dumps(report))), \
                patch("lab.PrivateStore", return_value=store), \
                patch("lab.save_report") as save, patch("builtins.print"):
            self.assertEqual(lab.main(["verify-report"]), 0)
        save.assert_not_called()


class AtomicStateTests(unittest.TestCase):
    def setUp(self):
        self.parent = Path.cwd() / ".test-work"
        self.parent.mkdir(exist_ok=True)
        self.directory = self.parent / uuid.uuid4().hex
        self.directory.mkdir()
        self.path = self.directory / "state.json"

    def tearDown(self):
        for path in self.directory.iterdir():
            path.unlink()
        self.directory.rmdir()
        if not any(self.parent.iterdir()):
            self.parent.rmdir()

    def test_failed_replace_preserves_previous_valid_state(self):
        lab.write_json(self.path, {"generation": 1})
        with patch("lab.os.replace", side_effect=OSError("synthetic disk failure")):
            with self.assertRaises(OSError):
                lab.write_json(self.path, {"generation": 2})
        self.assertEqual(json.loads(self.path.read_text(encoding="utf-8-sig")), {"generation": 1})
        self.assertEqual(list(self.directory.iterdir()), [self.path])

    def test_fsync_precedes_replace_in_same_directory(self):
        events = []
        original = lab.os.replace
        def replace(source, destination):
            events.append("replace")
            self.assertEqual(Path(source).parent, Path("."))
            original(source, destination)
        with patch("lab.os.fsync", side_effect=lambda _: events.append("fsync")), \
                patch("lab.os.replace", side_effect=replace):
            lab.write_json(self.path, {"generation": 1})
        self.assertEqual(events, ["fsync", "replace"])


class MutationJournalTests(unittest.TestCase):
    def fixture(self):
        run = "a" * 32
        body = {
            "displayName": "shoten21-obo-" + run + "-api-a",
            "tags": ["shoten21-obo-run:" + run],
            "signInAudience": "AzureADMyOrg", "api": {"requestedAccessTokenVersion": 2},
        }
        state = {"run": run, "prefix": "shoten21-obo-" + run,
                 "apps": {}, "grants": [], "assignments": []}
        store = SimpleNamespace(data=state)
        return store, body

    def test_no_remote_post_before_intent_is_durable(self):
        store, body = self.fixture()
        store.save = lambda: (_ for _ in ()).throw(OSError("synthetic failure"))
        called = []
        graph = SimpleNamespace(call=lambda *args: called.append(args))
        with self.assertRaises(OSError):
            lab.create_recorded(graph, store, "app", "/applications", "create_api_a", body, name="a")
        self.assertEqual(called, [])

    def test_success_after_response_save_failure_can_be_read_only_reconciled(self):
        store, body = self.fixture()
        durable = []
        def save():
            if durable:
                raise OSError("synthetic replacement failure")
            durable.append(copy.deepcopy(store.data))
        store.save = save
        returned = {"id": "new-object", "appId": "new-client", **body}
        with self.assertRaises(lab.Blocked) as error:
            lab.create_recorded(
                SimpleNamespace(call=lambda *args: returned), store,
                "app", "/applications", "create_api_a", body, name="a")
        self.assertEqual(error.exception.code, "MutationOutcomeUncertain")
        recovered = SimpleNamespace(data=durable[0], save=lambda: None)
        queries = []
        def collection(path, stage):
            queries.append(path)
            return [returned]
        lab.reconcile_pending(SimpleNamespace(collection=collection), recovered)
        self.assertEqual(recovered.data["apps"]["a"]["id"], "new-object")
        self.assertNotIn("pending_mutation", recovered.data)
        self.assertIn("displayName eq '" + body["displayName"] + "'", queries[0])
        self.assertNotIn("startswith", queries[0])

    def test_ambiguous_or_no_exact_marker_never_counts_as_recovered(self):
        for result_count in (0, 2):
            store, body = self.fixture()
            store.save = lambda: None
            graph = SimpleNamespace(call=lambda *args: (_ for _ in ()).throw(
                lab.Blocked("create_api_a", "NetworkOrJsonError")))
            with self.assertRaises(lab.Blocked):
                lab.create_recorded(graph, store, "app", "/applications", "create_api_a", body, name="a")
            candidate = {"id": "id", "appId": "client", **body}
            with self.assertRaises(lab.Blocked):
                lab.reconcile_pending(SimpleNamespace(
                    collection=lambda *args: [candidate] * result_count), store)
            self.assertIn("pending_mutation", store.data)

    def test_confirmed_refusal_resolves_locally_and_forbids_further_creates(self):
        store, body = self.fixture()
        store.save = lambda: None
        graph = SimpleNamespace(call=lambda *args: (_ for _ in ()).throw(
            lab.Blocked("create_api_a", "Authorization_RequestDenied", status=403)))
        with self.assertRaises(lab.Blocked):
            lab.create_recorded(graph, store, "app", "/applications", "create_api_a", body, name="a")
        self.assertEqual(store.data["pending_mutation"]["phase"], "refused")
        lab.reconcile_pending(SimpleNamespace(), store)
        self.assertNotIn("pending_mutation", store.data)
        with self.assertRaises(lab.Blocked):
            lab.create_recorded(SimpleNamespace(), store, "app", "/applications",
                                "create_api_a", body, name="a")

    def test_exact_name_without_full_marker_is_not_recovered(self):
        store, body = self.fixture()
        store.save = lambda: None
        with self.assertRaises(lab.Blocked):
            lab.create_recorded(SimpleNamespace(call=lambda *args: (_ for _ in ()).throw(
                lab.Blocked("create_api_a", "NetworkOrJsonError"))),
                store, "app", "/applications", "create_api_a", body, name="a")
        candidate = {"id": "id", "appId": "client", **body, "tags": ["foreign-marker"]}
        with self.assertRaises(lab.Blocked):
            lab.reconcile_pending(SimpleNamespace(collection=lambda *args: [candidate]), store)
        self.assertIn("pending_mutation", store.data)

    def test_credential_recovery_never_invents_a_lost_secret(self):
        store, _ = self.fixture()
        store.data["apps"] = {
            name: {"id": "obj-" + name, "appId": "client-" + name, "spId": "sp-" + name,
                   "displayName": store.data["prefix"] + "-api-" + name}
            for name in ("a", "b")}
        store.save = lambda: None
        expires = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=23)).isoformat()
        body = {"passwordCredential": {
            "displayName": "isolated-lab-24h-" + store.data["run"], "endDateTime": expires}}
        with self.assertRaises(lab.Blocked):
            lab.create_recorded(SimpleNamespace(call=lambda *args: (_ for _ in ()).throw(
                lab.Blocked("create_24h_lab_secret", "NetworkOrJsonError"))),
                store, "credential", "/applications/obj-a/addPassword",
                "create_24h_lab_secret", body)
        actual = {"keyId": "synthetic-key-id", **body["passwordCredential"]}
        graph = SimpleNamespace(call=lambda *args: {"passwordCredentials": [actual]})
        with patch("lab.owned_application"), self.assertRaises(lab.Blocked) as error:
            lab.reconcile_pending(graph, store)
        self.assertEqual(error.exception.code, "CredentialSecretUnrecoverable")
        self.assertNotIn("secret", store.data["credential"])
        self.assertFalse(store.data.get("provisioned", False))


class CleanupOrphanTests(unittest.TestCase):
    def test_recorded_sp_is_checked_even_when_application_is_404(self):
        app = {"id": "app-object", "appId": "app-client",
               "displayName": "shoten21-obo-test-api-a", "spId": "sp-object"}
        store = SimpleNamespace(data={
            "prefix": "shoten21-obo-test", "apps": {"a": app},
            "grants": [], "assignments": [],
        }, save=lambda: None)
        calls = []
        def call(method, path, stage, body=None):
            calls.append((method, path))
            if method == "GET" and path.startswith("/applications/"):
                raise lab.Blocked(stage, "Request_ResourceNotFound", status=404)
            if method == "GET":
                return {"id": "sp-object", "appId": "app-client",
                        "displayName": app["displayName"]}
            return {}
        with patch("lab.record"):
            lab.cleanup(SimpleNamespace(call=call), store, lab.new_report())
        self.assertIn(("DELETE", "/servicePrincipals/sp-object"), calls)
        self.assertNotIn(("DELETE", "/applications/app-object"), calls)


class ExhaustiveAuditTests(unittest.TestCase):
    def fixture(self):
        permissions = {"a": "scope-a", "b": "scope-b", "metadata": "scope-meta", "role": "role-b"}
        apps = {
            name: {"id": "object-" + name, "appId": "client-" + name,
                   "spId": "sp-" + name, "displayName": "shoten21-obo-test-api-" + name}
            for name in ("a", "b")}
        grants = [
            {"id": "g1", "clientId": "cli-sp", "resourceId": "sp-a", "principalId": "user",
             "scope": "access_as_user", "consentType": "Principal"},
            {"id": "g2", "clientId": "cli-sp", "resourceId": "sp-b", "principalId": "user",
             "scope": "Docs.Read Docs.Metadata", "consentType": "Principal"},
            {"id": "g3", "clientId": "sp-a", "resourceId": "sp-b", "principalId": "user",
             "scope": "Docs.Read", "consentType": "Principal"},
        ]
        assignment = {"id": "assignment", "principalId": "sp-a",
                      "resourceId": "sp-b", "appRoleId": "role-b"}
        state = {"apps": apps, "prefix": "shoten21-obo-test", "permissions": permissions,
                 "grants": copy.deepcopy(grants), "assignments": [assignment],
                 "user": "user", "cliSpId": "cli-sp"}
        definitions = {
            "a": [lab.permission("access_as_user", "scope-a")],
            "b": [lab.permission("Docs.Read", "scope-b"),
                  lab.permission("Docs.Metadata", "scope-meta")]}
        application_data = {}
        for name in ("a", "b"):
            application_data[name] = {
                "api": {"requestedAccessTokenVersion": 2,
                        "oauth2PermissionScopes": definitions[name],
                        "preAuthorizedApplications": [{
                            "appId": lab.CLI_CLIENT,
                            "delegatedPermissionIds": [item["id"] for item in definitions[name]]}]},
                "appRoles": [] if name == "a" else [lab.application_role("role-b")],
                "identifierUris": ["api://client-" + name],
                "requiredResourceAccess": [] if name == "b" else [{
                    "resourceAppId": "client-b", "resourceAccess": [
                        {"id": "scope-b", "type": "Scope"}, {"id": "role-b", "type": "Role"}]}],
            }
        incoming = {"a": [], "b": [assignment]}
        outgoing = {"a": [assignment], "b": []}
        methods = []
        def call(method, path, stage, body=None):
            methods.append(method)
            if stage == "verify_owned_application":
                return apps["a" if "object-a" in path else "b"]
            if stage == "audit_lab_application":
                return application_data["a" if "object-a" in path else "b"]
            if stage == "audit_lab_sp":
                name = "a" if "/sp-a?" in path else "b"
                return {"id": "sp-" + name, "appId": "client-" + name,
                        "oauth2PermissionScopes": definitions[name],
                        "appRoles": application_data[name]["appRoles"]}
            return {"defaultUserRolePermissions": {"allowedToCreateApps": False}}
        def collection(path, stage):
            if path.startswith("/oauth2PermissionGrants"):
                resource = "sp-a" if "'sp-a'" in path else "sp-b"
                return [item for item in grants if item["resourceId"] == resource]
            name = "a" if "/sp-a/" in path else "b"
            return (incoming if path.endswith("appRoleAssignedTo") else outgoing)[name]
        report = lab.new_report()
        report["capability"]["default_user_allowed_to_create_apps"] = False
        return (SimpleNamespace(data=state), SimpleNamespace(call=call, collection=collection),
                report, grants, application_data, incoming, methods)

    def test_exact_full_manifest_passes_read_only(self):
        store, graph, report, *_ = self.fixture()
        lab.audit_resources(graph, store, report)
        self.assertEqual(set(report["resource_audit"]["checks"]), safety.AUDIT_CHECKS)
        self.assertTrue(all(report["resource_audit"]["checks"].values()))

    def test_unknown_or_all_principals_grant_fails_without_delete(self):
        for consent in ("Principal", "AllPrincipals"):
            store, graph, report, grants, _, _, methods = self.fixture()
            grants.append({"id": "unknown", "clientId": "unknown", "resourceId": "sp-b",
                           "principalId": None, "scope": "Docs.Read", "consentType": consent})
            with self.assertRaises(lab.Blocked):
                lab.audit_resources(graph, store, report)
            self.assertEqual(set(methods), {"GET"})

    def test_scope_role_preauthorization_or_unknown_assignment_drift_fails(self):
        for drift in ("scope", "role", "preauth", "assignment"):
            store, graph, report, _, apps, incoming, _ = self.fixture()
            if drift == "scope":
                apps["b"]["api"]["oauth2PermissionScopes"][0]["type"] = "Admin"
            elif drift == "role":
                apps["b"]["appRoles"][0]["allowedMemberTypes"] = ["User", "Application"]
            elif drift == "preauth":
                apps["b"]["api"]["preAuthorizedApplications"][0]["delegatedPermissionIds"].append("extra")
            else:
                incoming["b"].append({"id": "extra", "principalId": "foreign",
                                      "resourceId": "sp-b", "appRoleId": "role-b"})
            with self.subTest(drift=drift), self.assertRaises(lab.Blocked):
                lab.audit_resources(graph, store, report)

    def test_graph_collection_follows_pages_and_rejects_foreign_next_link(self):
        graph = lab.Graph.__new__(lab.Graph)
        calls = []
        def call(method, path, stage):
            calls.append(path)
            return ({"value": [{"id": "first"}], "@odata.nextLink": lab.GRAPH + "/items?$skiptoken=a%2Bb"}
                    if len(calls) == 1 else {"value": [{"id": "second"}]})
        graph.call = call
        self.assertEqual(len(graph.collection("/items", "audit_principal_consent")), 2)
        self.assertIn("%2B", calls[1])
        graph.call = lambda *args: {"value": [], "@odata.nextLink": "https://invalid.example"}
        with self.assertRaises(lab.Blocked):
            graph.collection("/items", "audit_principal_consent")


if __name__ == "__main__":
    unittest.main()
