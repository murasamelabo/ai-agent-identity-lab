"""JWT teaching views use synthetic tokens, never real Entra credentials."""

import copy
import io
import json
import unittest
from unittest.mock import patch

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

import lab
import report_safety as safety
from test_safety import valid_report


def inspection_fixture(summary):
    payload = {key: summary[key] for key in
               ("ver", "iss", "aud", "azp", "oid", "tid")}
    payload.update(iat=1800000000, nbf=1800000000,
                   exp=1800000000 + summary["lifetime_seconds"], sub="[REDACTED]")
    if summary["scp"]:
        payload["scp"] = " ".join(summary["scp"])
    if summary["roles"]:
        payload["roles"] = list(summary["roles"])
    return {
        "compact_redacted": ("eyJ0eXAiOiJKV1Qi[HEADER_REDACTED]."
                             "[PAYLOAD_REDACTED].[SIGNATURE_REDACTED]"),
        "segment_lengths": {"header": 80, "payload": 800, "signature": 342},
        "header": {"alg": "RS256", "typ": "JWT", "kid": "[REDACTED]"},
        "payload": payload,
    }


def inspected_report():
    report = valid_report()
    report["token_inspection"] = {
        name: inspection_fixture(summary) for name, summary in report["tokens"].items()}
    return report


class InspectionSchemaTests(unittest.TestCase):
    def test_accepts_redacted_inspection_and_old_reports(self):
        lab.validate_report(valid_report(), final=True)
        lab.validate_report(inspected_report(), final=True)

    def test_rejects_private_or_unknown_content_at_every_level(self):
        changes = (
            lambda t: t.update(raw="private-token"),
            lambda t: t.update(compact_redacted="eyJprivate.payload.signature"),
            lambda t: t["header"].update(kid="private-signing-key"),
            lambda t: t["header"].update(extra="private-header"),
            lambda t: t["payload"].update(email="alice@private.example"),
            lambda t: t["payload"].update(sub="private-subject"),
            lambda t: t["payload"].update(scp="customer-secret"),
            lambda t: t["payload"].update(oid="[API_A_SP]"),
            lambda t: t["payload"].update(exp=1800000000),
            lambda t: t["payload"].update(iat=True),
            lambda t: t["segment_lengths"].update(payload="private"),
        )
        for change in changes:
            report = inspected_report()
            change(report["token_inspection"]["api_b_obo"])
            with self.subTest(change=change), self.assertRaises(lab.Blocked):
                lab.validate_report(report)

    def test_inspection_is_bound_to_immutable_observation(self):
        report = inspected_report()
        changed = copy.deepcopy(report)
        changed["token_inspection"]["api_b_obo"]["segment_lengths"]["payload"] += 1
        lab.validate_report(changed)
        self.assertNotEqual(safety.observation_digest(report),
                            safety.observation_digest(changed))

    def test_views_preserve_scope_string_and_absence(self):
        report = inspected_report()
        obo = safety.render_token_view(report, "api_b_obo", "payload")
        app = safety.render_token_view(report, "api_b_app_only", "payload")
        self.assertIn('"scp": "Docs.Read"', obo)
        self.assertNotIn('"roles"', obo)
        self.assertIn('"roles": [', app)
        self.assertNotIn('"scp"', app)
        for view in ("encoded", "header", "payload"):
            text = safety.render_token_view(report, "api_b_obo", view)
            self.assertIn("publication-redacted", text)
            self.assertIn("no token is acquired", text)

    def test_cannot_render_old_or_malformed_evidence_as_new_inspection(self):
        with self.assertRaises(safety.Rejected):
            safety.render_token_view(valid_report(), "api_b_obo", "payload")
        report = inspected_report()
        report["token_inspection"]["api_b_obo"]["payload"]["email"] = "private"
        with self.assertRaises(safety.Rejected):
            safety.render_token_view(report, "api_b_obo", "payload")


class InspectionProductionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def test_projection_does_not_export_encoded_private_claims_or_signature(self):
        state = {"tenant": "private-tenant", "user": "private-user", "apps": {
            "a": {"appId": "private-api-a", "spId": "private-sp-a"},
            "b": {"appId": "private-api-b", "spId": "private-sp-b"}}}
        claims = {
            "ver": "2.0", "iss": "https://private.example/v2.0", "tid": state["tenant"],
            "aud": "private-api-b", "azp": "private-api-a", "oid": state["user"],
            "iat": 1800000000, "nbf": 1800000000, "exp": 1800003600,
            "scp": "Docs.Read", "sub": "private-pairwise-id",
            "name": "Private Person", "ipaddr": "192.0.2.1",
        }
        token = jwt.encode(claims, self.key, algorithm="RS256",
                           headers={"kid": "private-kid", "extra": "private-header"})
        value = lab.inspect_verified_token(token, claims, state)
        text = json.dumps(value)
        for private in (state["tenant"], state["user"], "private-api-a", "private-api-b",
                        "private-sp-a", "private-sp-b", claims["iss"], claims["sub"], claims["name"],
                        claims["ipaddr"], "private-kid", "private-header", token,
                        token.split(".")[1], token.split(".")[2]):
            if isinstance(private, str):
                self.assertNotIn(private, text)
        self.assertEqual(value["payload"]["scp"], "Docs.Read")
        self.assertEqual(value["header"]["kid"], "[REDACTED]")
        self.assertEqual(value["segment_lengths"]["payload"], len(token.split(".")[1]))

    def test_raw_display_rejects_redirected_output_before_writing(self):
        output = io.StringIO()
        with patch("lab.sys.stdout", output), self.assertRaises(lab.Blocked):
            lab.display_raw_tokens({"api_b_obo": "synthetic-not-a-credential"})
        self.assertEqual(output.getvalue(), "")

    def test_raw_display_requires_console_but_retains_exact_local_token(self):
        output = io.StringIO()
        with patch.object(output, "isatty", return_value=True), \
                patch("lab.sys.stdout", output):
            lab.display_raw_tokens({"api_b_obo": "synthetic-not-a-credential"})
        self.assertIn("LOCAL ONLY", output.getvalue())
        self.assertIn("synthetic-not-a-credential", output.getvalue())

    def test_raw_option_is_rejected_for_non_acquisition_or_redirected_run(self):
        for arguments in (["audit", "--show-raw-tokens"],
                          ["run", "--show-raw-tokens"]):
            with patch("lab.PrivateStore") as store, patch(
                    "lab.sys.stdout", io.StringIO()), patch(
                    "lab.sys.stderr", io.StringIO()), self.assertRaises(SystemExit):
                lab.main(arguments)
            store.assert_not_called()

    def test_cli_view_requires_same_run_integrity_and_never_acquires(self):
        report = inspected_report()
        for valid_binding in (True, False):
            output = io.StringIO()
            with patch("lab.REPORT") as path, patch("lab.PrivateStore") as store, \
                    patch("lab.Graph") as graph, patch("lab.Validator") as validator, \
                    patch("lab.sys.stdout", output):
                path.read_text.return_value = json.dumps(report)
                if not valid_binding:
                    store.return_value.verify_report.side_effect = lab.Blocked(
                        "report_integrity", "ReportBindingMismatch")
                result = lab.main(["token-view", "--view", "payload"])
            self.assertEqual(result, 0 if valid_binding else 1)
            graph.assert_not_called()
            validator.assert_not_called()
            self.assertEqual('"scp": "Docs.Read"' in output.getvalue(), valid_binding)

    def test_acquisition_inspects_only_verified_tokens_and_never_logs_raw_by_default(self):
        from types import SimpleNamespace

        state = {"provisioned": True, "tenant": "tenant", "user": "user", "apps": {
            "a": {"appId": "api-a", "spId": "sp-a"},
            "b": {"appId": "api-b", "spId": "sp-b"}}, "credential": {"secret": "secret"}}
        claims_by_name = {}
        tokens = {}
        for name in lab.TOKEN_NAMES:
            summary = valid_report()["tokens"][name]
            claims = {
                "ver": "2.0", "iss": "https://issuer.example", "tid": "tenant",
                "aud": "api-a" if name == "api_a_input" else "api-b",
                "azp": "api-a" if name in ("api_b_app_only", "api_b_obo") else lab.CLI_CLIENT,
                "oid": "sp-a" if name == "api_b_app_only" else "user",
                "iat": 1800000000, "nbf": 1800000000, "exp": 1800003600,
            }
            if summary["scp"]:
                claims["scp"] = " ".join(summary["scp"])
            if summary["roles"]:
                claims["roles"] = summary["roles"]
            claims_by_name[name] = claims
            tokens[name] = jwt.encode(claims, self.key, algorithm="RS256")

        def cli(arguments, stage):
            name = {"silent_access_as_user": "api_a_input", "silent_Docs_Read": "api_b_direct",
                    "silent_Docs_Metadata": "api_b_metadata"}[stage]
            return {"accessToken": tokens[name]}

        def confidential(*args, **kwargs):
            name = "api_b_obo" if "assertion" in kwargs["form"] else "api_b_app_only"
            return {"access_token": tokens[name]}

        def validate(token, audience):
            name = next(key for key, value in tokens.items() if value == token)
            self.assertEqual(audience, claims_by_name[name]["aud"])
            return claims_by_name[name]

        report = lab.new_report()
        output = io.StringIO()
        with patch("lab.Validator") as validator, patch(
                "lab.cli_json", side_effect=cli), patch(
                "lab.json_request", side_effect=confidential), patch(
                "lab.experiments", return_value=valid_report()["experiments"]), patch(
                "lab.save_report", side_effect=lambda value, store: lab.validate_report(value)), \
                patch("lab.sys.stdout", output):
            validator.return_value.validate.side_effect = validate
            result = lab.acquire_and_compare(SimpleNamespace(data=state, save=lambda: None), report)
        self.assertIsNone(result)
        self.assertEqual(validator.return_value.validate.call_count, 5)
        self.assertEqual(report["status"], "succeeded")
        self.assertEqual(set(report["token_inspection"]), set(lab.TOKEN_NAMES))
        self.assertEqual(output.getvalue(), "")
        for token in tokens.values():
            self.assertNotIn(token, json.dumps(report))


if __name__ == "__main__":
    unittest.main()
