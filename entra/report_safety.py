"""Closed publication schema and local consistency checks, not remote attestation."""

import datetime as dt
import hashlib
import hmac
import json
import re

TOKENS = {"api_a_input", "api_b_direct", "api_b_app_only", "api_b_obo", "api_b_metadata"}
CORE = TOKENS - {"api_b_metadata"}
SCOPES = {"access_as_user", "Docs.Read", "Docs.Metadata"}
ROLES = {"Docs.Read.All"}
OPERATIONS = {
    "create_api_a", "create_api_b", "create_api_a_sp", "create_api_b_sp",
    "configure_api_a", "configure_api_b", "preauthorize_cli_for_api_a",
    "preauthorize_cli_for_api_b", "create_principal_only_consent",
    "assign_new_lab_role_between_new_sps", "create_24h_lab_secret",
    "delete_created_grant", "delete_created_assignment", "delete_created_application",
    "delete_created_sp",
}
STAGES = OPERATIONS | TOKENS | {
    "private_storage", "account_context", "graph_silent_token", "read_signed_in_user",
    "read_creation_policy", "read_application_roles", "creation_capability",
    "verify_owned_application", "provision", "configure", "lookup_existing_cli_sp",
    "oidc_discovery", "resume", "silent_access_as_user", "silent_Docs_Read",
    "silent_Docs_Metadata", "obo", "client_credentials", "report", "local_execution",
    "verify_created_grant", "verify_created_assignment", "verify_created_sp",
    "audit_lab_application", "audit_lab_sp", "audit_principal_consent",
    "audit_lab_application_role", "audit_unchanged_creation_policy", "resource_audit",
    "mutation", "reconcile", "report_integrity",
}
CODES = {
    "UnclassifiedError", "AzureCliNotInstalled", "AzureCliUnavailable",
    "AzureCliInvalidResponse", "AzureCliSilentTokenUnavailable", "HttpError",
    "NetworkOrJsonError", "InvalidGraphPath", "WindowsPrivateAclRequired",
    "UnsafeLocalAppData", "LinkedPrivateDirectory", "InvalidRunHandle",
    "PrivateAclFailed", "OnlyPublicCloudSupported", "SignedInUserRequired",
    "NoDocumentedCreationCapability", "OwnershipGuardFailed", "UseResumeForExistingRun",
    "ConfigurationAlreadyPassedConsentBoundary", "ExistingCliServicePrincipalRequired",
    "IssuerMetadataMismatch", "UnsafeJwksUri", "ProvisioningIncompleteCleanupAvailable",
    "AuthenticationAttemptLimit", "TokenValidationFailed", "BlockedByMissingApiAUserToken",
    "GrantOwnershipGuardFailed", "AssignmentOwnershipGuardFailed",
    "ServicePrincipalOwnershipGuardFailed", "ResourceAuditMismatch", "LocalExecutionError",
    "InvalidValue", "Authorization_RequestDenied", "Request_BadRequest",
    "Request_ResourceNotFound", "Forbidden", "AccessDenied", "InvalidAuthenticationToken",
    "Authentication_MissingOrMalformed", "invalid_grant", "invalid_client",
    "invalid_scope", "unauthorized_client", "interaction_required", "consent_required",
    "UnsafePublicationContent", "ReportSchemaRejected", "ReportConsistencyRejected",
    "ReportBindingMissing", "ReportBindingMismatch", "ReportBindingAlreadyExists",
    "PendingMutationRequiresReconciliation", "MutationOutcomeUncertain",
    "MutationOwnershipMismatch", "ReconciliationAmbiguous", "CredentialSecretUnrecoverable",
    "PaginationLimitExceeded", "UnsafeGraphNextLink",
    "ProvisioningRefusedCleanupOnly",
} | {f"AADSTS{code}" for code in (
    50020, 50058, 50076, 50079, 50173, 53000, 53003, 65001, 650057,
    700016, 7000215, 7000222, 70011, 90002,
)}
RELATIONSHIPS = {
    "input_cli_same_user_and_scope", "same_v2_api_b_audience",
    "direct_and_obo_same_user", "direct_and_obo_same_tenant", "direct_caller_is_cli",
    "obo_caller_is_api_a", "app_only_actor_is_api_a_sp", "app_only_has_role_not_user_scope",
}
AUDIT_CHECKS = {
    *(f"api_{name}_{suffix}" for name in ("a", "b") for suffix in (
        "v2", "only_own_identifier_uri", "only_cli_preauthorized",
        "exact_scope_definitions", "exact_role_definitions", "exact_preauthorization",
        "exact_required_resource_access", "sp_exact_scope_and_role_definitions",
        "exact_all_incoming_role_assignments", "exact_all_outgoing_role_assignments")),
    "only_new_api_b_required_resource", "three_exact_principal_only_custom_api_grants",
    "one_role_assignment_only_between_new_sps", "default_user_creation_policy_unchanged",
    "no_unrecorded_or_tenant_wide_grants",
}
EXPECTED = {
    "api_b_direct_alice": "allow", "api_b_direct_bob": "wrong_owner",
    "api_b_obo_alice": "allow", "api_b_obo_bob": "wrong_owner",
    "api_b_app_only_alice": "allow", "api_b_app_only_bob": "allow",
    "app_only_cannot_impersonate_owner": "missing_scope",
    "obo_read_token_missing_metadata_route_scope": "missing_scope",
    "api_a_token_rejected_by_api_b": "rejected_wrong_audience",
}
DECISIONS = {
    "allow", "wrong_owner", "missing_scope", "missing_application_role",
    "wrong_application", "rejected_wrong_audience", "incorrectly_accepted",
}
CONTEXT = {
    "tenant": "[TENANT]", "user": "[USER_A]", "client": "[AZURE_CLI]",
    "api_a": "[API_A]", "api_b": "[API_B]", "app_actor": "[API_A_SP]",
    "alice_bob": "Synthetic local document owners, not directory users",
}
SURFACE = "Local in-process API authorization harness; real Entra tokens"
PRIVACY = "Allowlisted claims, aliases, codes, booleans only; no raw tokens"
CORRECTION = (
    "Persist scope definitions before referencing them in preauthorization; "
    "no policy or permission elevation"
)
HEADER_PREFIXES = ("eyJ0eXAiOiJKV1Qi", "eyJhbGciOiJSUzI1", "")
REDACTED_SUFFIX = "[HEADER_REDACTED].[PAYLOAD_REDACTED].[SIGNATURE_REDACTED]"


class Rejected(ValueError):
    pass


def require(condition):
    if not condition:
        raise Rejected("ReportSchemaRejected")


def shape(value, required, optional=()):
    require(type(value) is dict)
    require(set(required) <= value.keys() <= set(required) | set(optional))


def enum(value, choices):
    require(type(value) is str and value in choices)


def boolean(value):
    require(type(value) is bool)


def timestamp(value, nullable=False):
    if nullable and value is None:
        return
    require(type(value) is str and re.fullmatch(
        r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?\+00:00", value) is not None)
    try:
        dt.datetime.fromisoformat(value)
    except ValueError:
        raise Rejected("ReportSchemaRejected") from None


def members(value, allowed, maximum=128):
    require(type(value) is list and len(value) <= maximum)
    require(all(type(item) is str and item in allowed for item in value))
    require(len(value) == len(set(value)))


def privacy(report):
    """Every published string is a fixed enum or a validated UTC timestamp."""
    shape(report, {
        "schema", "started_at", "finished_at", "status", "mode", "execution_surface",
        "privacy", "identity_context", "capability", "operations", "tokens",
        "experiments", "blockers", "proof_status", "token_attempts", "cleanup",
    }, {"setup_diagnostics", "relationships", "scope_observations", "resource_audit",
        "local_error_type", "integrity", "token_inspection"})
    require(type(report["schema"]) is int and report["schema"] == 1)
    timestamp(report["started_at"])
    timestamp(report["finished_at"], nullable=True)
    enum(report["status"], {"running", "succeeded", "failed", "blocked", "probe_only", "provisioned"})
    enum(report["proof_status"], {"not_started", "blocked", "partial", "failed", "complete"})
    enum(report["mode"], {"real-entra"})
    enum(report["execution_surface"], {SURFACE})
    enum(report["privacy"], {PRIVACY})
    require(report["identity_context"] == CONTEXT)
    capability = report["capability"]
    if capability:
        shape(capability, {"default_user_allowed_to_create_apps",
                          "application_management_role_available", "policy_changed",
                          "role_is_not_policy_bypass", "creation_capability"})
        for field in ("default_user_allowed_to_create_apps", "policy_changed",
                      "application_management_role_available",
                      "role_is_not_policy_bypass"):
            boolean(capability[field])
        enum(capability["creation_capability"], {
            "not_yet_tested", "verified_by_graph_creation"})
    else:
        require(capability == {})
    require(type(report["operations"]) is list and len(report["operations"]) <= 128)
    for item in report["operations"]:
        shape(item, {"operation", "status"})
        enum(item["operation"], OPERATIONS)
        enum(item["status"], {"succeeded"})
    require(type(report["tokens"]) is dict and report["tokens"].keys() <= TOKENS)
    for token in report["tokens"].values():
        shape(token, {"signature_issuer_audience_lifetime", "ver", "aud", "azp",
                      "oid", "tid", "iss", "scp", "roles", "lifetime_seconds"})
        enum(token["signature_issuer_audience_lifetime"], {"verified"})
        enum(token["ver"], {"2.0"})
        enum(token["aud"], {"[API_A]", "[API_B]"})
        enum(token["azp"], {"[AZURE_CLI]", "[API_A]", "[API_B]", "[OTHER_ACTOR]"})
        enum(token["oid"], {"[USER_A]", "[API_A_SP]", "[API_B_SP]", "[OTHER_ACTOR]"})
        enum(token["tid"], {"[TENANT]"})
        enum(token["iss"], {"[TENANT_V2_ISSUER]"})
        members(token["scp"], SCOPES)
        members(token["roles"], ROLES)
        require(type(token["lifetime_seconds"]) is int and 0 < token["lifetime_seconds"] <= 172800)
    if "token_inspection" in report:
        views = report["token_inspection"]
        shape(views, report["tokens"])
        require(bool(views))
        for name, value in views.items():
            validate_inspection(value, report["tokens"][name])
    require(type(report["experiments"]) is list and len(report["experiments"]) <= len(EXPECTED))
    for item in report["experiments"]:
        shape(item, {"name", "actual", "expected", "passed"})
        enum(item["name"], EXPECTED)
        enum(item["actual"], DECISIONS)
        enum(item["expected"], DECISIONS)
        boolean(item["passed"])
    require(type(report["blockers"]) is list and len(report["blockers"]) <= 16)
    for item in report["blockers"]:
        shape(item, {"stage", "code", "http_status"})
        enum(item["stage"], STAGES)
        enum(item["code"], CODES)
        require(item["http_status"] is None or
                type(item["http_status"]) is int and 400 <= item["http_status"] <= 599)
    require(type(report["token_attempts"]) is dict and report["token_attempts"].keys() <= TOKENS)
    require(all(type(value) is int and 0 <= value <= 2
                for value in report["token_attempts"].values()))
    enum(report["cleanup"], {"not_requested", "completed_exact_recorded_objects"})
    if "local_error_type" in report:
        enum(report["local_error_type"], {
            "KeyError", "ValueError", "TypeError", "OSError", "FileNotFoundError",
            "PermissionError", "RuntimeError", "ImportError", "ModuleNotFoundError"})
    if "relationships" in report:
        shape(report["relationships"], RELATIONSHIPS)
        for value in report["relationships"].values():
            boolean(value)
    if "setup_diagnostics" in report:
        require(type(report["setup_diagnostics"]) is list and len(report["setup_diagnostics"]) <= 1)
        for item in report["setup_diagnostics"]:
            shape(item, {"stage", "code", "http_status", "attempts", "field",
                         "correction", "resolved"})
            require(type(item["attempts"]) is int and type(item["http_status"]) is int)
            require(item["resolved"] is True)
            require(item == {
                "stage": "configure_api_b", "code": "InvalidValue", "http_status": 400,
                "attempts": 2, "field": "preAuthorizedApplications.delegatedPermissionIds",
                "correction": CORRECTION, "resolved": True,
            })
    if "scope_observations" in report:
        obs = report["scope_observations"]
        shape(obs, {"cli_direct_requested", "cli_direct_issued", "obo_requested",
                    "obo_issued", "missing_scope_negative"},
              {"cli_metadata_requested", "cli_metadata_issued",
               "cli_metadata_request_document_decision"})
        for key, value in obs.items():
            if key == "missing_scope_negative":
                enum(value, {"OBO Docs.Read token against Docs.Metadata route"})
            elif key == "cli_metadata_request_document_decision":
                enum(value, DECISIONS)
            else:
                members(value, SCOPES)
    if "resource_audit" in report:
        shape(report["resource_audit"], {"checked_at", "checks"})
        timestamp(report["resource_audit"]["checked_at"])
        require(type(report["resource_audit"]["checks"]) is dict
                and report["resource_audit"]["checks"].keys() <= AUDIT_CHECKS)
        for value in report["resource_audit"]["checks"].values():
            boolean(value)
    if "integrity" in report:
        shape(report["integrity"], {"kind", "origin", "bound_at", "remote_attestation"})
        enum(report["integrity"]["kind"], {"local_private_run_hmac"})
        enum(report["integrity"]["origin"], {
            "imported_existing_local_observations", "live_local_capture"})
        timestamp(report["integrity"]["bound_at"])
        require(report["integrity"]["remote_attestation"] is False)


def validate_inspection(value, summary):
    shape(value, {"compact_redacted", "segment_lengths", "header", "payload"})
    enum(value["compact_redacted"], {prefix + REDACTED_SUFFIX for prefix in HEADER_PREFIXES})
    shape(value["segment_lengths"], {"header", "payload", "signature"})
    for length in value["segment_lengths"].values():
        require(type(length) is int and 0 < length <= 65536)
    header = value["header"]
    shape(header, {"alg"}, {"typ", "kid", "x5t"})
    enum(header["alg"], {"RS256"})
    if "typ" in header:
        enum(header["typ"], {"JWT", "at+jwt"})
    for field in ("kid", "x5t"):
        if field in header:
            enum(header[field], {"[REDACTED]"})
    payload = value["payload"]
    aliases = ("ver", "iss", "aud", "azp", "oid", "tid")
    shape(payload, {*aliases, "iat", "nbf", "exp"}, {"scp", "roles", "sub"})
    for field in aliases:
        require(payload[field] == summary[field])
    for field in ("iat", "nbf", "exp"):
        require(type(payload[field]) is int and 0 < payload[field] < 10**12)
    require(payload["nbf"] < payload["exp"])
    require(payload["exp"] - payload["iat"] == summary["lifetime_seconds"])
    if "sub" in payload:
        enum(payload["sub"], {"[REDACTED]"})
    scopes = payload.get("scp", "")
    require(type(scopes) is str and len(scopes) <= 64)
    require(" ".join(scopes.split()) == scopes)
    members(scopes.split(), SCOPES)
    require(sorted(scopes.split()) == summary["scp"])
    members(payload.get("roles", []), ROLES)
    require(sorted(payload.get("roles", [])) == summary["roles"])


def render_token_view(report, name, view):
    privacy(report)
    enum(name, TOKENS)
    enum(view, {"encoded", "header", "payload"})
    require(name in report.get("token_inspection", {}))
    value = report["token_inspection"][name]
    lines = [
        f"VERIFIED ENTRA JWT - {view.upper()} (publication-redacted)",
        f"Token: {name}",
        "Saved sanitized evidence; no token is acquired by this view.",
        "Source verified: RS256 signature, issuer, audience, lifetime.",
        "",
    ]
    if view == "encoded":
        lengths = value["segment_lengths"]
        lines += [
            value["compact_redacted"],
            "",
            ("Base64url lengths (characters): "
             f"header={lengths['header']}; payload={lengths['payload']}; "
             f"signature={lengths['signature']}"),
            "Original header prefix only; all remaining JWT content is redacted.",
            "This redacted text is not a usable or verifiable JWT.",
        ]
    else:
        lines += [
            json.dumps(value[view], indent=2),
            "",
            "Selected original fields only; identity values are redacted.",
            "Omitted fields are not evidence of absence in the original JWT.",
            "Decoding alone is not signature validation.",
        ]
    return "\n".join(lines)


def relationships(tokens):
    a, direct, app, obo = (tokens[name] for name in
                          ("api_a_input", "api_b_direct", "api_b_app_only", "api_b_obo"))
    return {
        "input_cli_same_user_and_scope": a["oid"] == "[USER_A]" and a["azp"] == "[AZURE_CLI]"
        and "access_as_user" in a["scp"],
        "same_v2_api_b_audience": {direct["aud"], app["aud"], obo["aud"]} == {"[API_B]"},
        "direct_and_obo_same_user": direct["oid"] == obo["oid"] == "[USER_A]",
        "direct_and_obo_same_tenant": direct["tid"] == obo["tid"] == "[TENANT]",
        "direct_caller_is_cli": direct["azp"] == "[AZURE_CLI]",
        "obo_caller_is_api_a": obo["azp"] == "[API_A]",
        "app_only_actor_is_api_a_sp": app["oid"] == "[API_A_SP]",
        "app_only_has_role_not_user_scope": not app["scp"] and "Docs.Read.All" in app["roles"],
    }


def consistency(report, final=False):
    try:
        require(report["started_at"] <= (report["finished_at"] or report["started_at"]))
        if report["capability"]:
            require(report["capability"]["policy_changed"] is False)
            require(report["capability"]["role_is_not_policy_bypass"] is True)
        items = {item["name"]: item for item in report["experiments"]}
        require(len(items) == len(report["experiments"]))
        for name, item in items.items():
            require(item["expected"] == EXPECTED[name])
            require(item["passed"] == (item["actual"] == item["expected"]))
            if name == "api_a_token_rejected_by_api_b":
                require("api_a_input" in report["tokens"])
                continue
            flow = next((key for key in ("api_b_direct", "api_b_obo", "api_b_app_only")
                         if name.startswith(key)), None)
            flow = flow or ("api_b_obo" if name.startswith("obo_") else "api_b_app_only")
            require(flow in report["tokens"])
            token = report["tokens"][flow]
            if name.startswith("api_b_app_only_"):
                actual = "allow" if ("Docs.Read.All" in token["roles"]
                                     and not token["scp"] and token["azp"] == "[API_A]") \
                    else "missing_application_role"
            else:
                scope = "Docs.Metadata" if name.startswith("obo_") else "Docs.Read"
                owner = "[SYNTHETIC_BOB]" if name.endswith("_bob") else "[USER_A]"
                actual = ("missing_scope" if scope not in token["scp"] else
                          "allow" if token["oid"] == owner else "wrong_owner")
            require(item["actual"] == actual)
        if "relationships" in report:
            require(CORE <= report["tokens"].keys())
            require(report["relationships"] == relationships(report["tokens"]))
        if report["proof_status"] == "complete":
            require(CORE <= report["tokens"].keys() and set(items) == set(EXPECTED))
            require(all(item["passed"] for item in items.values()))
            require(all(report.get("relationships", {}).values()) and
                    set(report.get("relationships", {})) == RELATIONSHIPS)
            require(report["tokens"]["api_a_input"]["aud"] == "[API_A]")
        if report["status"] == "succeeded":
            require(report["proof_status"] == "complete" and not report["blockers"])
        if report["status"] in {"probe_only", "provisioned"}:
            require(not report["tokens"] and report["proof_status"] == "not_started")
        for name, token in report["tokens"].items():
            allowed = {"access_as_user"} if name == "api_a_input" else {"Docs.Read", "Docs.Metadata"}
            require(set(token["scp"]) <= allowed)
            require(token["aud"] == ("[API_A]" if name == "api_a_input" else "[API_B]"))
        for name in report["tokens"]:
            require(report["token_attempts"].get(name, 0) > 0)
        if "scope_observations" in report:
            obs = report["scope_observations"]
            for label, flow, requested in (
                ("cli_direct", "api_b_direct", ["Docs.Read"]),
                ("obo", "api_b_obo", ["Docs.Read"]),
                ("cli_metadata", "api_b_metadata", ["Docs.Metadata"]),
            ):
                if label + "_issued" in obs:
                    require(flow in report["tokens"])
                    require(obs[label + "_issued"] == report["tokens"][flow]["scp"])
                    require(obs[label + "_requested"] == requested)
            if "cli_metadata_request_document_decision" in obs:
                expected = "allow" if "Docs.Read" in report["tokens"]["api_b_metadata"]["scp"] else "missing_scope"
                require(obs["cli_metadata_request_document_decision"] == expected)
        if final:
            require(report["proof_status"] == "complete")
            require(report["status"] == "succeeded" and not report["blockers"])
            require(set(report.get("resource_audit", {}).get("checks", {})) == AUDIT_CHECKS)
            require(all(report["resource_audit"]["checks"].values()))
            require("integrity" in report)
            require(report["capability"].get("creation_capability") == "verified_by_graph_creation")
            operations = [item["operation"] for item in report["operations"]]
            for name in ("create_api_a", "create_api_b", "create_api_a_sp", "create_api_b_sp",
                         "assign_new_lab_role_between_new_sps", "create_24h_lab_secret"):
                require(operations.count(name) == 1)
            require(operations.count("create_principal_only_consent") == 3)
            require(report["resource_audit"]["checked_at"] <= report["finished_at"])
    except (Rejected, KeyError, TypeError):
        raise Rejected("ReportConsistencyRejected") from None


def canonical(report):
    return json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def observation_digest(report):
    fields = ("started_at", "tokens", "experiments", "relationships",
              "scope_observations", "token_attempts", "token_inspection")
    return hashlib.sha256(canonical({key: report[key] for key in fields if key in report})).hexdigest()


def report_mac(report, key, run):
    payload = run.encode("ascii") + b"\0" + canonical(report)
    return hmac.new(bytes.fromhex(key), payload, hashlib.sha256).hexdigest()
