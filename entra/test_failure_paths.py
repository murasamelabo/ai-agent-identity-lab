"""Offline regressions for refusal and report-publication recovery only."""

import copy
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

import lab
from test_safety import valid_report


def known_state():
    run = "a" * 32
    prefix = "shoten21-obo-" + run
    return {
        "run": run, "prefix": prefix, "cliSpId": "cli-sp", "user": "user",
        "permissions": {"role": "role-b"}, "grants": [], "assignments": [],
        "apps": {
            name: {"id": "obj-" + name, "appId": "client-" + name, "spId": "sp-" + name,
                   "displayName": prefix + "-api-" + name} for name in ("a", "b")
        },
    }


def exact_cleanup_graph(state, calls):
    def call(method, path, stage, body=None):
        calls.append((method, path))
        if method == "POST":
            raise AssertionError("Cleanup must not retry a POST")
        if stage == "verify_owned_application":
            return state["apps"]["a" if "obj-a" in path else "b"]
        if stage == "verify_created_sp":
            app = state["apps"]["a" if "/sp-a?" in path else "b"]
            return {"id": app["spId"], "appId": app["appId"],
                    "displayName": app["displayName"]}
        return {}
    return SimpleNamespace(call=call)


class ConfirmedRefusalTests(unittest.TestCase):
    def refusal(self, status):
        state = known_state()
        store = SimpleNamespace(data=state, save=lambda: None)
        graph = SimpleNamespace(call=lambda *args: (_ for _ in ()).throw(
            lab.Blocked("create_principal_only_consent", "Authorization_RequestDenied",
                        status=status)))
        body = {"clientId": "cli-sp", "resourceId": "sp-a", "principalId": "user",
                "consentType": "Principal", "scope": "access_as_user"}
        with self.assertRaises(lab.Blocked):
            lab.create_recorded(graph, store, "grant", "/oauth2PermissionGrants",
                                "create_principal_only_consent", body)
        return store

    def test_refused_grant_after_apps_and_sps_allows_exact_known_cleanup(self):
        store = self.refusal(403)
        calls = []
        with patch("lab.record"):
            lab.cleanup(exact_cleanup_graph(store.data, calls), store, lab.new_report())
        self.assertNotIn("pending_mutation", store.data)
        self.assertTrue(store.data["provisioning_refused"])
        self.assertEqual(len(store.data["refused_mutations"]), 1)
        self.assertEqual({path for method, path in calls if method == "DELETE"}, {
            "/applications/obj-a", "/applications/obj-b",
            "/servicePrincipals/sp-a", "/servicePrincipals/sp-b"})
        self.assertNotIn("POST", [method for method, _ in calls])

    def test_timeout_never_becomes_a_confirmed_refusal(self):
        store = self.refusal(408)
        self.assertEqual(store.data["pending_mutation"]["phase"], "uncertain")
        with self.assertRaises(lab.Blocked):
            lab.cleanup(SimpleNamespace(), store, lab.new_report())
        self.assertIn("pending_mutation", store.data)

    def test_refusal_without_durable_http_confirmation_remains_blocked(self):
        store = self.refusal(403)
        store.data["pending_mutation"].pop("http_status")
        with self.assertRaises(lab.Blocked):
            lab.cleanup(SimpleNamespace(), store, lab.new_report())
        self.assertIn("pending_mutation", store.data)


class ReportPublicationRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.parent = Path.cwd() / ".test-work"
        self.parent.mkdir(exist_ok=True)
        self.directory = self.parent / uuid.uuid4().hex
        self.directory.mkdir()
        self.report_path = self.directory / "comparison.json"
        self.store = lab.PrivateStore.__new__(lab.PrivateStore)
        self.store.path = self.directory / "state.json"
        self.store.data = known_state()
        self.report = valid_report()
        with patch.object(lab, "REPORT", self.report_path):
            lab.save_report(self.report, self.store)

    def tearDown(self):
        for path in self.directory.iterdir():
            path.unlink()
        self.directory.rmdir()
        if not any(self.parent.iterdir()):
            self.parent.rmdir()

    def reload(self):
        store = lab.PrivateStore.__new__(lab.PrivateStore)
        store.path = self.store.path
        store.data = json.loads(store.path.read_text(encoding="utf-8-sig"))
        return store

    def fail_public_replace(self):
        edited = copy.deepcopy(self.report)
        edited["finished_at"] = lab.now()
        original = lab.os.replace
        def replace(source, destination):
            if destination == self.report_path.name:
                raise OSError("synthetic public replacement failure")
            return original(source, destination)
        with patch.object(lab, "REPORT", self.report_path), \
                patch("lab.os.replace", side_effect=replace), self.assertRaises(OSError):
            lab.save_report(edited, self.store)
        return edited

    def test_failed_report_replace_keeps_known_old_report_usable_for_cleanup(self):
        self.fail_public_replace()
        store = self.reload()
        calls = []
        with patch.object(lab, "REPORT", self.report_path), \
                patch("lab.PrivateStore", return_value=store), \
                patch("lab.Graph", return_value=exact_cleanup_graph(store.data, calls)), \
                patch("builtins.print"):
            self.assertEqual(lab.main(["cleanup"]), 0)
        self.assertNotIn("pending_report_write", store.data)
        self.assertEqual(len([item for item in calls if item[0] == "DELETE"]), 4)

    def test_edited_public_report_cannot_be_resealed_during_recovery(self):
        self.fail_public_replace()
        tampered = copy.deepcopy(self.report)
        tampered["tokens"]["api_b_obo"]["lifetime_seconds"] += 1
        lab.write_json(self.report_path, tampered)
        store = self.reload()
        before = copy.deepcopy(store.data)
        with patch.object(lab, "REPORT", self.report_path), \
                patch("lab.PrivateStore", return_value=store), \
                patch("lab.Graph") as graph, patch("builtins.print"):
            self.assertEqual(lab.main(["cleanup"]), 2)
        graph.assert_not_called()
        self.assertEqual(store.data, before)

    def test_published_new_report_survives_private_finalize_failure(self):
        edited = copy.deepcopy(self.report)
        edited["finished_at"] = lab.now()
        original = self.store.save
        def save():
            if "pending_report_write" not in self.store.data:
                raise OSError("synthetic private finalization failure")
            original()
        with patch.object(lab, "REPORT", self.report_path), \
                patch.object(self.store, "save", side_effect=save), \
                self.assertRaises(OSError):
            lab.save_report(edited, self.store)
        self.assertEqual(json.loads(self.report_path.read_text(encoding="utf-8-sig")), edited)
        store = self.reload()
        self.assertIn("pending_report_write", store.data)
        calls = []
        with patch.object(lab, "REPORT", self.report_path), \
                patch("lab.PrivateStore", return_value=store), \
                patch("lab.Graph", return_value=exact_cleanup_graph(store.data, calls)), \
                patch("builtins.print"):
            self.assertEqual(lab.main(["cleanup"]), 0)
        self.assertNotIn("pending_report_write", store.data)
        self.assertEqual(len([item for item in calls if item[0] == "DELETE"]), 4)


if __name__ == "__main__":
    unittest.main()
