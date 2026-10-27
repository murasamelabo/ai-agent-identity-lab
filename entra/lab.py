"""An isolated Entra OBO lab. Raw tokens require explicit local-console opt-in."""

from __future__ import annotations

import argparse
import contextlib
import csv
import datetime as dt
import hashlib
import hmac
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parent
# Azure CLI's bundled Python can use an isolated search path. Load only this
# trusted sibling, without widening the process-wide module search path.
_safety_spec = importlib.util.spec_from_file_location("report_safety", ROOT / "report_safety.py")
report_safety = importlib.util.module_from_spec(_safety_spec)
_safety_spec.loader.exec_module(report_safety)
REPORT = ROOT / "reports" / "comparison.json"
GRAPH = "https://graph.microsoft.com/v1.0"
LOGIN = "https://login.microsoftonline.com"
# Public Microsoft Azure CLI application ID, not a tenant/lab identifier.
CLI_CLIENT = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
ROLE_NAMES = {
    "Application Administrator", "Cloud Application Administrator",
    "Global Administrator", "Application Developer",
}
TOKEN_NAMES = ("api_a_input", "api_b_direct", "api_b_app_only", "api_b_obo",
               "api_b_metadata")
TOKEN_ALIASES = {
    "agent_input": "api_a_input",
    "direct": "api_b_direct",
    "app_only": "api_b_app_only",
    "obo": "api_b_obo",
    "metadata": "api_b_metadata",
}
APP_SLUGS = {"a": "ai-agent-app", "b": "backend-api"}
APP_NAMES = {"a": "AI-Agent-App", "b": "Backend-API"}


def app_display_name(prefix, name):
    return f"{APP_NAMES[name]}-{prefix}"


def allowed_app_display_names(prefix, name):
    return {
        app_display_name(prefix, name),
        f"{prefix}-{APP_SLUGS[name]}",
        f"{prefix}-api-{name}",
    }
GUID = re.compile(r"\b[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\b")
JWT_PATTERN = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
SAFE_CODE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,100}$")
CONFIRMED_REFUSAL_STATUSES = {400, 401, 403, 404, 405, 409, 412, 422}


class Blocked(Exception):
    def __init__(self, stage, code, *, status=None):
        super().__init__(code)
        self.stage = stage if stage in report_safety.STAGES else "local_execution"
        self.code = code if code in report_safety.CODES else "UnclassifiedError"
        self.status = status

    def public(self):
        return {"stage": self.stage, "code": self.code, "http_status": self.status}


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


@contextlib.contextmanager
def working_at(path):
    previous = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


def write_json(path, value):
    # The sibling inherits the protected private-directory ACL before any bytes.
    encoded = (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8-sig")
    with working_at(path.parent):
        pending = Path(f".{path.name}.{uuid.uuid4().hex}.pending")
        try:
            with pending.open("xb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(pending, path.name)
        finally:
            pending.unlink(missing_ok=True)


def cli_json(arguments, stage):
    executable = shutil.which("az")
    if executable is None:
        raise Blocked(stage, "AzureCliNotInstalled")
    try:
        result = subprocess.run(
            [executable, *arguments, "--only-show-errors", "--output", "json"],
            capture_output=True, text=True, encoding="utf-8", timeout=120,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise Blocked(stage, "AzureCliUnavailable") from None
    if result.returncode:
        # Only known machine error codes are retained; never emit stderr/stdout.
        codes = re.findall(r"\bAADSTS\d+\b", result.stderr + result.stdout)
        raise Blocked(stage, codes[0] if codes else "AzureCliSilentTokenUnavailable")
    try:
        return json.loads(result.stdout)
    except (ValueError, TypeError):
        raise Blocked(stage, "AzureCliInvalidResponse") from None


def json_request(url, stage, *, method="GET", bearer=None, body=None, form=None):
    headers = {"Accept": "application/json"}
    if bearer:
        headers["Authorization"] = "Bearer " + bearer
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if form is not None:
        data = urllib.parse.urlencode(form).encode("ascii")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    request = urllib.request.Request(url, data, headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            raw = response.read(4 * 1024 * 1024)
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as error:
        try:
            payload = json.loads(error.read(65536))
        except (ValueError, OSError):
            payload = {}
        detail = payload.get("error", {})
        if isinstance(detail, dict):
            code = detail.get("code", "HttpError")
        else:
            aadsts = re.findall(r"\bAADSTS\d+\b", payload.get("error_description", ""))
            code = aadsts[0] if aadsts else str(detail or "HttpError")
        raise Blocked(stage, code, status=error.code) from None
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        raise Blocked(stage, "NetworkOrJsonError") from None


class Graph:
    def __init__(self):
        self.token = cli_json(
            ["account", "get-access-token", "--resource-type", "ms-graph"],
            "graph_silent_token",
        )["accessToken"]

    def call(self, method, path, stage, body=None):
        if not path.startswith("/") or path.startswith("//"):
            raise Blocked(stage, "InvalidGraphPath")
        encoded_path = urllib.parse.quote(path, safe="/?$=&'(),:%")
        return json_request(GRAPH + encoded_path, stage, method=method,
                            bearer=self.token, body=body)

    def collection(self, path, stage, *, max_pages=8):
        items, seen = [], set()
        for _ in range(max_pages):
            if path in seen:
                raise Blocked(stage, "PaginationLimitExceeded")
            seen.add(path)
            page = self.call("GET", path, stage)
            items.extend(page.get("value", []))
            link = page.get("@odata.nextLink")
            if not link:
                return items
            if not isinstance(link, str) or not link.startswith(GRAPH + "/"):
                raise Blocked(stage, "UnsafeGraphNextLink")
            path = link[len(GRAPH):]
        raise Blocked(stage, "PaginationLimitExceeded")


class PrivateStore:
    """Private state lives only under LocalAppData with a protected user DACL."""

    def __init__(self, run=None, *, create=False):
        if os.name != "nt":
            raise Blocked("private_storage", "WindowsPrivateAclRequired")
        local = Path(os.environ.get("LOCALAPPDATA", "")).resolve()
        if not local.is_dir() or "onedrive" in str(local).lower():
            raise Blocked("private_storage", "UnsafeLocalAppData")
        with working_at(local):
            Path("Shoten21IdentityLab").mkdir(exist_ok=True)
        self.root = local / "Shoten21IdentityLab"
        if self.root.is_symlink() or self.root.is_junction():
            raise Blocked("private_storage", "LinkedPrivateDirectory")
        self.secure(self.root)
        if create:
            run = uuid.uuid4().hex
            with working_at(self.root):
                Path(run).mkdir()
            self.directory = self.root / run
            self.secure(self.directory)
            self.path = self.directory / "state.json"
            self.data = {
                "run": run, "prefix": "shoten21-obo-" + run[:8],
                "created_at": now(), "apps": {}, "grants": [], "assignments": [],
            }
            self.save()
            write_json(self.root / "latest.json", {"run": run})
        else:
            if run is None:
                latest = self.root / "latest.json"
                run = (json.loads(latest.read_text(encoding="utf-8-sig"))["run"]
                       if latest.exists() else
                       (self.root / "latest.txt").read_text(encoding="utf-8-sig"))
            if not re.fullmatch(r"[0-9a-f]{32}", run):
                raise Blocked("private_storage", "InvalidRunHandle")
            self.directory = self.root / run
            if self.directory.is_symlink() or self.directory.is_junction():
                raise Blocked("private_storage", "LinkedPrivateDirectory")
            self.secure(self.directory)
            self.path = self.directory / "state.json"
            self.data = json.loads(self.path.read_text(encoding="utf-8-sig"))

    @staticmethod
    def secure(path):
        try:
            identity = subprocess.run(
                ["whoami", "/user", "/fo", "csv", "/nh"],
                capture_output=True, text=True, check=True,
            )
            sid = next(csv.reader(io.StringIO(identity.stdout)))[1]
            if not re.fullmatch(r"S-1-[0-9-]+", sid):
                raise ValueError()
            subprocess.run(
                ["icacls", str(path), "/inheritance:r", "/grant:r",
                 f"*{sid}:(OI)(CI)F"],
                capture_output=True, text=True, check=True,
            )
        except (OSError, ValueError, IndexError, StopIteration, subprocess.CalledProcessError):
            raise Blocked("private_storage", "PrivateAclFailed") from None

    def save(self):
        write_json(self.path, self.data)

    def report_binding_for(self, report, *, importing=False):
        if importing and "report_binding" in self.data:
            raise Blocked("report_integrity", "ReportBindingAlreadyExists")
        key = self.data.setdefault("report_hmac_key", os.urandom(32).hex())
        binding = self.data.get("report_binding", {})
        digest = report_safety.observation_digest(report)
        if (binding.get("observation_digest") and not self.data.get("capturing_observations")
                and binding["observation_digest"] != digest):
            raise Blocked("report_integrity", "ReportBindingMismatch")
        return {
            "mac": report_safety.report_mac(report, key, self.data["run"]),
            "sha256": hashlib.sha256(report_safety.canonical(report)).hexdigest(),
            "observation_digest": digest if report["proof_status"] == "complete" else None,
        }

    def bind_report(self, report, *, importing=False):
        self.data["report_binding"] = self.report_binding_for(report, importing=importing)
        self.save()

    def binding_matches(self, report, binding):
        key = self.data.get("report_hmac_key")
        if not binding or not key:
            return False
        actual = report_safety.report_mac(report, key, self.data["run"])
        digest = hashlib.sha256(report_safety.canonical(report)).hexdigest()
        return (hmac.compare_digest(actual, binding["mac"])
                and hmac.compare_digest(digest, binding["sha256"])
                and (not binding.get("observation_digest") or
                     binding["observation_digest"] == report_safety.observation_digest(report)))

    def known_report_binding(self, report):
        pending = self.data.get("pending_report_write")
        if pending:
            if self.data.get("report_binding") not in (
                    pending["old_binding"], pending["new_binding"]):
                raise Blocked("report_integrity", "ReportBindingMismatch")
            for binding in (pending["old_binding"], pending["new_binding"]):
                if self.binding_matches(report, binding):
                    return binding
            raise Blocked("report_integrity", "ReportBindingMismatch")
        binding = self.data.get("report_binding")
        if not binding:
            raise Blocked("report_integrity", "ReportBindingMissing")
        if not self.binding_matches(report, binding):
            raise Blocked("report_integrity", "ReportBindingMismatch")
        return binding

    def verify_report(self, report):
        self.known_report_binding(report)

    def recover_report_write(self, report):
        if self.data.get("pending_report_write"):
            binding = self.known_report_binding(report)
            self.data["report_binding"] = binding
            self.data.pop("pending_report_write")
            self.save()

    def prepare_report_write(self, report, *, importing=False):
        if self.data.get("report_binding") or self.data.get("pending_report_write"):
            published = json.loads(REPORT.read_text(encoding="utf-8-sig"))
            self.recover_report_write(published)
            self.verify_report(published)
        self.data["pending_report_write"] = {
            "old_binding": self.data.get("report_binding"),
            "new_binding": self.report_binding_for(report, importing=importing),
        }
        self.save()

    def finish_report_write(self):
        pending = self.data["pending_report_write"]
        published = json.loads(REPORT.read_text(encoding="utf-8-sig"))
        if not self.binding_matches(published, pending["new_binding"]):
            raise Blocked("report_integrity", "ReportBindingMismatch")
        self.data["report_binding"] = pending["new_binding"]
        self.data.pop("pending_report_write")
        self.save()


def new_report():
    return {
        "schema": 1, "started_at": now(), "finished_at": None,
        "status": "running", "mode": "real-entra",
        "execution_surface": "Local in-process API authorization harness; real Entra tokens",
        "privacy": "Allowlisted claims, aliases, codes, booleans only; no raw tokens",
        "identity_context": {
            "tenant": "[TENANT]", "user": "[USER_A]", "client": "[AZURE_CLI]",
            "api_a": "[API_A]", "api_b": "[API_B]", "app_actor": "[API_A_SP]",
            "alice_bob": "Synthetic local document owners, not directory users",
        },
        "capability": {}, "operations": [], "tokens": {}, "experiments": [],
        "blockers": [], "proof_status": "not_started",
        "token_attempts": {}, "cleanup": "not_requested",
    }


def validate_report(report, *, final=False):
    try:
        report_safety.privacy(report)
        report_safety.consistency(report, final=final)
    except report_safety.Rejected as error:
        raise Blocked("report", str(error)) from None


def save_report(report, store=None, *, importing=False):
    validate_report(report)
    if store is None:
        raise Blocked("report_integrity", "ReportBindingMissing")
    store.prepare_report_write(report, importing=importing)
    with working_at(ROOT):
        Path("reports").mkdir(exist_ok=True)
    write_json(REPORT, report)
    store.finish_report_write()


def record(report, operation, store=None):
    report["operations"].append({"operation": operation, "status": "succeeded"})
    save_report(report, store)


def probe(graph, store, report):
    account = cli_json(["account", "show"], "account_context")
    if account.get("environmentName") != "AzureCloud":
        raise Blocked("account_context", "OnlyPublicCloudSupported")
    if account.get("user", {}).get("type") != "user":
        raise Blocked("account_context", "SignedInUserRequired")
    tenant = str(uuid.UUID(account["tenantId"]))
    user = graph.call("GET", "/me?$select=id", "read_signed_in_user")["id"]
    policy = graph.call(
        "GET", "/policies/authorizationPolicy?$select=defaultUserRolePermissions",
        "read_creation_policy",
    )
    roles = graph.call(
        "GET", "/me/memberOf/microsoft.graph.directoryRole?$select=displayName",
        "read_application_roles",
    )
    supported = sorted(
        role["displayName"] for role in roles.get("value", [])
        if role.get("displayName") in ROLE_NAMES
    )
    allowed = policy["defaultUserRolePermissions"]["allowedToCreateApps"]
    report["capability"] = {
        "default_user_allowed_to_create_apps": allowed,
        "application_management_role_available": bool(supported),
        "policy_changed": False, "role_is_not_policy_bypass": True,
        "creation_capability": "not_yet_tested",
    }
    store.data.update({"tenant": tenant, "user": user,
                       "application_management_roles": supported})
    store.save()
    save_report(report, store)
    if not allowed and not supported:
        raise Blocked("creation_capability", "NoDocumentedCreationCapability")


def permission(value, scope_id):
    return {
        "id": scope_id, "value": value, "type": "User", "isEnabled": True,
        "adminConsentDisplayName": "Read synthetic lab documents",
        "adminConsentDescription": "Access only the new isolated OBO lab API.",
        "userConsentDisplayName": "Read my synthetic lab documents",
        "userConsentDescription": "Access only my synthetic local lab documents.",
    }


def application_role(role_id):
    return {
        "id": role_id, "value": "Docs.Read.All", "isEnabled": True,
        "allowedMemberTypes": ["Application"],
        "displayName": "Read all synthetic lab documents",
        "description": "Read only synthetic documents in the isolated lab.",
    }


def owned_application(graph, store, name):
    app = store.data["apps"][name]
    actual = graph.call(
        "GET", f"/applications/{app['id']}?$select=id,appId,displayName,tags",
        "verify_owned_application",
    )
    if (actual.get("id") != app["id"] or actual.get("displayName") != app["displayName"]
            or actual.get("appId") != app["appId"]
            or app["displayName"] not in allowed_app_display_names(store.data["prefix"], name)
            or app.get("marker") and actual.get("tags") != [app["marker"]]):
        raise Blocked("verify_owned_application", "OwnershipGuardFailed")
    return app


def matches_intent(actual, intent):
    body, kind = intent["body"], intent["kind"]
    if kind == "app":
        return (actual.get("displayName") == body["displayName"]
                and actual.get("tags") == body["tags"]
                and actual.get("signInAudience") == body["signInAudience"]
                and actual.get("api", {}).get("requestedAccessTokenVersion") == 2)
    if kind == "sp":
        return all(actual.get(key) == body[key] for key in ("appId", "displayName", "tags"))
    if kind in ("grant", "assignment"):
        return all(actual.get(key) == value for key, value in body.items())
    if kind == "credential":
        expected = body["passwordCredential"]
        return (actual.get("displayName") == expected["displayName"]
                and dt.datetime.fromisoformat(actual["endDateTime"].replace("Z", "+00:00"))
                == dt.datetime.fromisoformat(expected["endDateTime"]))
    return False


def commit_created(store, intent, actual, *, recovering=False):
    kind, body = intent["kind"], intent["body"]
    if kind == "app":
        store.data["apps"][intent["name"]] = {
            "id": actual["id"], "appId": actual["appId"],
            "displayName": body["displayName"], "marker": body["tags"][0],
        }
    elif kind == "sp":
        store.data["apps"][intent["name"]]["spId"] = actual["id"]
    elif kind == "grant":
        record = {"id": actual["id"], **{key: body[key] for key in
                  ("clientId", "resourceId", "principalId", "scope")}}
        if not any(item["id"] == record["id"] for item in store.data["grants"]):
            store.data["grants"].append(record)
    elif kind == "assignment":
        record = {"id": actual["id"], **body}
        if not any(item["id"] == record["id"] for item in store.data["assignments"]):
            store.data["assignments"].append(record)
    elif kind == "credential":
        store.data["credential"] = {
            "keyId": actual["keyId"],
            "expires_at": body["passwordCredential"]["endDateTime"],
        }
        if not recovering:
            store.data["credential"]["secret"] = actual["secretText"]
        else:
            store.data["credential_secret_unrecoverable"] = True
    store.data.pop("pending_mutation", None)
    store.save()


def validate_intent(store, intent):
    state, body = store.data, intent["body"]
    kind, marker = intent["kind"], "shoten21-obo-run:" + state["run"]
    valid = intent["run_marker"] == marker
    if kind in ("app", "sp"):
        name = intent["name"]
        valid = valid and name in {"a", "b"}
        valid = valid and body.get("displayName") in allowed_app_display_names(state["prefix"], name)
        valid = valid and body.get("tags") == [marker]
        if kind == "app":
            valid = (valid and intent["path"] == "/applications"
                     and body.get("signInAudience") == "AzureADMyOrg"
                     and body.get("api") == {"requestedAccessTokenVersion": 2})
        else:
            valid = (valid and intent["path"] == "/servicePrincipals"
                     and body.get("appId") == state["apps"][name]["appId"])
    else:
        a, b = state["apps"]["a"], state["apps"]["b"]
        if kind == "grant":
            allowed = {
                (state["cliSpId"], a["spId"]): {"access_as_user"},
                (state["cliSpId"], b["spId"]): {"Docs.Read", "Docs.Metadata"},
                (a["spId"], b["spId"]): {"Docs.Read"},
            }
            valid = (valid and intent["path"] == "/oauth2PermissionGrants"
                     and body.get("consentType") == "Principal"
                     and body.get("principalId") == state["user"]
                     and set(body.get("scope", "").split())
                     == allowed.get((body.get("clientId"), body.get("resourceId"))))
        elif kind == "assignment":
            valid = (valid and intent["path"] == f"/servicePrincipals/{b['spId']}/appRoleAssignedTo"
                     and body == {"principalId": a["spId"], "resourceId": b["spId"],
                                  "appRoleId": state["permissions"]["role"]})
        elif kind == "credential":
            credential = body.get("passwordCredential", {})
            valid = (valid and intent["path"] == f"/applications/{a['id']}/addPassword"
                     and credential.get("displayName") == "isolated-lab-24h-" + state["run"])
            if valid:
                expires = dt.datetime.fromisoformat(credential["endDateTime"])
                prepared = dt.datetime.fromisoformat(intent["prepared_at"])
                valid = prepared < expires <= prepared + dt.timedelta(hours=24)
        else:
            valid = False
    if not valid:
        raise Blocked("mutation", "MutationOwnershipMismatch")


def create_recorded(graph, store, kind, path, stage, body, *, name=None):
    if store.data.get("provisioning_refused"):
        raise Blocked("mutation", "ProvisioningRefusedCleanupOnly")
    if store.data.get("pending_mutation"):
        raise Blocked("mutation", "PendingMutationRequiresReconciliation")
    intent = {
        "kind": kind, "path": path, "stage": stage, "body": body,
        "name": name, "phase": "prepared", "prepared_at": now(),
        "run_marker": "shoten21-obo-run:" + store.data["run"],
    }
    validate_intent(store, intent)
    store.data["pending_mutation"] = intent
    store.save()  # No remote POST may occur before this durable intent.
    try:
        actual = graph.call("POST", path, stage, body)
    except Blocked as error:
        intent["phase"] = "refused" if error.status in CONFIRMED_REFUSAL_STATUSES else "uncertain"
        intent["error_code"] = error.code
        intent["http_status"] = error.status
        store.save()
        raise
    try:
        if not matches_intent(actual, intent):
            raise Blocked("mutation", "MutationOwnershipMismatch")
        commit_created(store, intent, actual)
    except (OSError, KeyError, ValueError):
        # The durable prepared intent remains recoverable even if the response
        # was successful but the subsequent local replacement failed.
        raise Blocked("mutation", "MutationOutcomeUncertain") from None
    return actual


def resolve_confirmed_refusal(store):
    intent = store.data.get("pending_mutation")
    if not intent or intent.get("phase") != "refused":
        return
    validate_intent(store, intent)
    if (intent.get("http_status") not in CONFIRMED_REFUSAL_STATUSES
            or intent.get("error_code") not in report_safety.CODES):
        raise Blocked("mutation", "PendingMutationRequiresReconciliation")
    store.data.setdefault("refused_mutations", []).append(intent)
    store.data["provisioning_refused"] = True
    store.data.pop("pending_mutation")
    store.save()


def reconcile_pending(graph, store):
    """Bounded, read-only discovery; never retry POST or delete uncertain objects."""
    intent = store.data.get("pending_mutation")
    if not intent:
        return
    if intent["phase"] == "refused":
        resolve_confirmed_refusal(store)
        return
    validate_intent(store, intent)
    if intent["run_marker"] != "shoten21-obo-run:" + store.data["run"]:
        raise Blocked("reconcile", "MutationOwnershipMismatch")
    body, kind = intent["body"], intent["kind"]
    if kind == "app":
        allowed_names = allowed_app_display_names(store.data["prefix"], intent["name"])
        if body["displayName"] not in allowed_names or body.get("tags") != [intent["run_marker"]]:
            raise Blocked("reconcile", "MutationOwnershipMismatch")
        escaped = body["displayName"].replace("'", "''")
        candidates = graph.collection(
            f"/applications?$filter=displayName eq '{escaped}'"
            "&$select=id,appId,displayName,tags,signInAudience,api", "reconcile")
    elif kind == "sp":
        owned_application(graph, store, intent["name"])
        if body.get("tags") != [intent["run_marker"]]:
            raise Blocked("reconcile", "MutationOwnershipMismatch")
        candidates = graph.collection(
            f"/servicePrincipals?$filter=appId eq '{body['appId']}'"
            "&$select=id,appId,displayName,tags", "reconcile")
    elif kind in ("grant", "assignment", "credential"):
        for name in ("a", "b"):
            owned_application(graph, store, name)
        own_sps = {app["spId"] for app in store.data["apps"].values()}
        if kind in ("grant", "assignment") and body.get("resourceId") not in own_sps:
            raise Blocked("reconcile", "MutationOwnershipMismatch")
        if kind == "grant":
            candidates = graph.collection(
                f"/oauth2PermissionGrants?$filter=resourceId eq '{body['resourceId']}'",
                "reconcile")
        elif kind == "assignment":
            candidates = graph.collection(
                f"/servicePrincipals/{body['resourceId']}/appRoleAssignedTo", "reconcile")
        else:
            app = store.data["apps"]["a"]
            marker = "isolated-lab-24h-" + store.data["run"]
            if body["passwordCredential"]["displayName"] != marker:
                raise Blocked("reconcile", "MutationOwnershipMismatch")
            candidates = graph.call(
                "GET", f"/applications/{app['id']}?$select=passwordCredentials",
                "reconcile").get("passwordCredentials", [])
    else:
        raise Blocked("reconcile", "MutationOwnershipMismatch")
    matches = [item for item in candidates if matches_intent(item, intent)]
    if len(matches) != 1:
        code = "ReconciliationAmbiguous" if len(matches) > 1 else "MutationOutcomeUncertain"
        raise Blocked("reconcile", code)
    commit_created(store, intent, matches[0], recovering=True)
    if kind == "credential":
        raise Blocked("reconcile", "CredentialSecretUnrecoverable")


def provision(graph, store, report):
    if store.data["apps"]:
        raise Blocked("provision", "UseResumeForExistingRun")
    for name in ("a", "b"):
        display = app_display_name(store.data["prefix"], name)
        app = create_recorded(
            graph, store, "app", "/applications", f"create_api_{name}",
            {"displayName": display, "signInAudience": "AzureADMyOrg",
             "tags": ["shoten21-obo-run:" + store.data["run"]],
             "api": {"requestedAccessTokenVersion": 2}}, name=name,
        )
        report["capability"]["creation_capability"] = "verified_by_graph_creation"
        record(report, f"create_api_{name}", store)
        create_recorded(
            graph, store, "sp", "/servicePrincipals", f"create_api_{name}_sp",
            {"appId": app["appId"], "displayName": display,
             "tags": ["shoten21-obo-run:" + store.data["run"]]}, name=name)
        record(report, f"create_api_{name}_sp", store)
    configure_created_apps(graph, store, report)


def configure_created_apps(graph, store, report):
    if store.data.get("provisioning_refused"):
        raise Blocked("mutation", "ProvisioningRefusedCleanupOnly")
    a, b = (owned_application(graph, store, key) for key in ("a", "b"))
    if store.data.get("grants") or store.data.get("assignments") or store.data.get("credential"):
        raise Blocked("configure", "ConfigurationAlreadyPassedConsentBoundary")
    if "permissions" not in store.data:
        store.data["permissions"] = {
            key: str(uuid.uuid4()) for key in ("a", "b", "metadata", "role")
        }
    store.save()
    scope_a, scope_b, metadata, app_role = (
        store.data["permissions"][key] for key in ("a", "b", "metadata", "role")
    )
    configurations = {
        "a": {
            "identifierUris": [f"api://{a['appId']}"],
            "api": {
                "requestedAccessTokenVersion": 2,
                "oauth2PermissionScopes": [permission("access_as_user", scope_a)],
                "preAuthorizedApplications": [
                    {"appId": CLI_CLIENT, "delegatedPermissionIds": [scope_a]},
                ],
            },
            "requiredResourceAccess": [{
                "resourceAppId": b["appId"],
                "resourceAccess": [
                    {"id": scope_b, "type": "Scope"},
                    {"id": app_role, "type": "Role"},
                ],
            }],
        },
        "b": {
            "identifierUris": [f"api://{b['appId']}"],
            "api": {
                "requestedAccessTokenVersion": 2,
                "oauth2PermissionScopes": [
                    permission("Docs.Read", scope_b),
                    permission("Docs.Metadata", metadata),
                ],
                "preAuthorizedApplications": [
                    {"appId": CLI_CLIENT,
                     "delegatedPermissionIds": [scope_b, metadata]},
                ],
            },
            "appRoles": [application_role(app_role)],
        },
    }
    # Graph validates preauthorization IDs against scopes already persisted.
    # Publish scopes first; do not introduce scopes and their references together.
    for name in ("b", "a"):
        app = owned_application(graph, store, name)
        body = {
            **configurations[name],
            "api": {key: value for key, value in configurations[name]["api"].items()
                    if key != "preAuthorizedApplications"},
        }
        graph.call("PATCH", f"/applications/{app['id']}", f"configure_api_{name}",
                   body)
        record(report, f"configure_api_{name}", store)
    for name in ("b", "a"):
        app = owned_application(graph, store, name)
        graph.call("PATCH", f"/applications/{app['id']}",
                   f"preauthorize_cli_for_api_{name}",
                   {"api": configurations[name]["api"]})
        record(report, f"preauthorize_cli_for_api_{name}", store)

    cli = graph.call(
        "GET", f"/servicePrincipals?$filter=appId eq '{CLI_CLIENT}'&$select=id",
        "lookup_existing_cli_sp",
    ).get("value", [])
    if len(cli) != 1:
        raise Blocked("lookup_existing_cli_sp", "ExistingCliServicePrincipalRequired")
    store.data["cliSpId"] = cli[0]["id"]
    store.save()
    # Existing CLI receives only new custom API scopes, only for this user.
    for client, resource, scope in (
        (cli[0]["id"], a["spId"], "access_as_user"),
        (cli[0]["id"], b["spId"], "Docs.Read Docs.Metadata"),
        (a["spId"], b["spId"], "Docs.Read"),
    ):
        create_recorded(
            graph, store, "grant", "/oauth2PermissionGrants", "create_principal_only_consent",
            {"clientId": client, "resourceId": resource, "scope": scope,
             "consentType": "Principal", "principalId": store.data["user"]},
        )
        record(report, "create_principal_only_consent", store)

    create_recorded(
        graph, store, "assignment", f"/servicePrincipals/{b['spId']}/appRoleAssignedTo",
        "assign_new_lab_role_between_new_sps",
        {"principalId": a["spId"], "resourceId": b["spId"], "appRoleId": app_role},
    )
    record(report, "assign_new_lab_role_between_new_sps", store)
    expires = dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=24)
    create_recorded(
        graph, store, "credential", f"/applications/{a['id']}/addPassword", "create_24h_lab_secret",
        {"passwordCredential": {
            "displayName": "isolated-lab-24h-" + store.data["run"],
            "endDateTime": expires.isoformat(),
        }},
    )
    store.data["provisioned"] = True
    store.save()
    record(report, "create_24h_lab_secret", store)


class Validator:
    def __init__(self, tenant):
        import jwt

        self.tenant = tenant
        discovery = json_request(
            f"{LOGIN}/{tenant}/v2.0/.well-known/openid-configuration",
            "oidc_discovery",
        )
        self.issuer = f"{LOGIN}/{tenant}/v2.0"
        if discovery.get("issuer") != self.issuer:
            raise Blocked("oidc_discovery", "IssuerMetadataMismatch")
        jwks = discovery.get("jwks_uri", "")
        parsed = urllib.parse.urlsplit(jwks)
        if (parsed.scheme != "https" or parsed.hostname != "login.microsoftonline.com"
                or parsed.username or parsed.password or parsed.port not in (None, 443)):
            raise Blocked("oidc_discovery", "UnsafeJwksUri")
        self.keys = jwt.PyJWKClient(jwks, timeout=60)

    def validate(self, token, audience):
        import jwt

        key = self.keys.get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token, key.key, algorithms=["RS256"], audience=audience,
            issuer=self.issuer, leeway=30,
            options={"require": ["exp", "iat", "nbf", "iss", "aud", "tid", "oid", "ver"]},
        )
        if claims["tid"] != self.tenant or claims["ver"] != "2.0":
            raise jwt.InvalidTokenError("Unexpected tenant or token version")
        return claims


def authorize_delegated(claims, owner, required_scope="Docs.Read"):
    if required_scope not in claims.get("scp", "").split():
        return "missing_scope"
    if claims.get("oid") != owner:
        return "wrong_owner"
    return "allow"


def authorize_application(claims, actor):
    if claims.get("scp") or "Docs.Read.All" not in claims.get("roles", []):
        return "missing_application_role"
    if claims.get("azp") != actor:
        return "wrong_application"
    return "allow"


def summarize_claims(claims, state):
    aliases = {
        state["tenant"]: "[TENANT]", state["user"]: "[USER_A]",
        state["apps"]["a"]["appId"]: "[API_A]",
        state["apps"]["b"]["appId"]: "[API_B]", CLI_CLIENT: "[AZURE_CLI]",
        state["apps"]["a"]["spId"]: "[API_A_SP]",
        state["apps"]["b"]["spId"]: "[API_B_SP]",
    }
    result = {"signature_issuer_audience_lifetime": "verified", "ver": claims["ver"]}
    for key in ("aud", "azp", "oid", "tid"):
        value = claims.get(key)
        if value is not None:
            result[key] = aliases.get(value, "[OTHER_ACTOR]")
    result["iss"] = "[TENANT_V2_ISSUER]"
    result["scp"] = sorted(claims.get("scp", "").split())
    result["roles"] = sorted(claims.get("roles", []))
    result["lifetime_seconds"] = claims["exp"] - claims["iat"]
    return result


def inspect_verified_token(token, claims, state):
    """Called only after signature/context validation; never retain full JWT parts."""
    import jwt

    parts = token.split(".")
    if len(parts) != 3:
        raise Blocked("report", "TokenValidationFailed")
    original_header = jwt.get_unverified_header(token)
    header = {"alg": original_header["alg"]}
    if "typ" in original_header:
        header["typ"] = original_header["typ"]
    for field in ("kid", "x5t"):
        if field in original_header:
            header[field] = "[REDACTED]"
    summary = summarize_claims(claims, state)
    payload = {field: summary[field] for field in ("ver", "iss", "aud", "azp", "oid", "tid")}
    for field in ("iat", "nbf", "exp", "scp", "roles"):
        if field in claims:
            payload[field] = claims[field]
    if "sub" in claims:
        payload["sub"] = "[REDACTED]"
    prefix = next(value for value in report_safety.HEADER_PREFIXES
                  if parts[0].startswith(value))
    result = {
        "compact_redacted": prefix + report_safety.REDACTED_SUFFIX,
        "segment_lengths": dict(zip(("header", "payload", "signature"), map(len, parts))),
        "header": header, "payload": payload,
    }
    try:
        report_safety.validate_inspection(result, summary)
    except report_safety.Rejected:
        raise Blocked("report", "ReportSchemaRejected") from None
    return result


def display_raw_tokens(tokens):
    if not sys.stdout.isatty():
        raise Blocked("report", "UnsafePublicationContent")
    print("LOCAL ONLY: bearer credentials below. Do not record, photograph or share.")
    for name in TOKEN_NAMES:
        if name in tokens:
            print(f"\n{name}\n{tokens[name]}")


def experiments(tokens, claims, validator, state):
    import jwt

    user = state["user"]
    actor = state["apps"]["a"]["appId"]
    # Alice maps to the real signed-in subject; Bob is not a directory user.
    fixtures = json.loads((ROOT / "synthetic-documents.json").read_text(encoding="utf-8-sig"))
    documents = {
        key: {**value, "owner": user if value["owner_alias"] == "[USER_A]"
              else "synthetic-bob"} for key, value in fixtures.items()
    }
    results = []

    def check(name, actual, expected):
        results.append({
            "name": name, "actual": actual, "expected": expected,
            "passed": actual == expected,
        })

    for flow in ("api_b_direct", "api_b_obo"):
        for document in ("alice", "bob"):
            check(f"{flow}_{document}", authorize_delegated(
                claims[flow], documents[document]["owner"]),
                "allow" if document == "alice" else "wrong_owner")
    for document in ("alice", "bob"):
        check(f"api_b_app_only_{document}", authorize_application(
            claims["api_b_app_only"], actor), "allow")
    check("app_only_cannot_impersonate_owner",
          authorize_delegated(claims["api_b_app_only"], user), "missing_scope")
    check("obo_read_token_missing_metadata_route_scope",
          authorize_delegated(claims["api_b_obo"], user, "Docs.Metadata"), "missing_scope")
    try:
        validator.validate(tokens["api_a_input"], state["apps"]["b"]["appId"])
        actual = "incorrectly_accepted"
    except jwt.InvalidAudienceError:
        actual = "rejected_wrong_audience"
    check("api_a_token_rejected_by_api_b", actual, "rejected_wrong_audience")
    return results


def acquire_and_compare(store, report, *, return_raw_tokens=False):
    import jwt

    state = store.data
    if not state.get("provisioned"):
        raise Blocked("resume", "ProvisioningIncompleteCleanupAvailable")
    validator = Validator(state["tenant"])
    tokens, claims = {}, {}
    attempts = state.setdefault("token_attempts", {})
    report["token_attempts"] = dict(attempts)
    a, b = state["apps"]["a"], state["apps"]["b"]
    endpoint = f"{LOGIN}/{state['tenant']}/oauth2/v2.0/token"

    def acquire(name, action, audience):
        if attempts.get(name, 0) >= 2:
            report["blockers"].append(Blocked(name, "AuthenticationAttemptLimit").public())
            save_report(report, store)
            return
        attempts[name] = attempts.get(name, 0) + 1
        report["token_attempts"] = dict(attempts)
        store.save()
        try:
            token = action()
            try:
                verified = validator.validate(token, audience)
            except jwt.PyJWTError:
                raise Blocked(name, "TokenValidationFailed") from None
            tokens[name], claims[name] = token, verified
            report["tokens"][name] = summarize_claims(verified, state)
        except Blocked as error:
            report["blockers"].append(error.public())
        save_report(report, store)

    def cli_token(app, scope):
        return cli_json(
            ["account", "get-access-token", "--tenant", state["tenant"],
             "--scope", f"api://{app['appId']}/{scope}"],
            f"silent_{scope.replace('.', '_')}",
        )["accessToken"]

    def confidential(scope, assertion=None):
        form = {
            "client_id": a["appId"], "client_secret": state["credential"]["secret"],
            "scope": f"api://{b['appId']}/{scope}",
            "grant_type": "client_credentials",
        }
        if assertion is not None:
            form.update({
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "requested_token_use": "on_behalf_of", "assertion": assertion,
            })
        return json_request(endpoint, "obo" if assertion else "client_credentials",
                            method="POST", form=form)["access_token"]

    acquire("api_a_input", lambda: cli_token(a, "access_as_user"), a["appId"])
    # An independent app-only request remains useful if silent user auth is blocked.
    acquire("api_b_app_only", lambda: confidential(".default"), b["appId"])
    if "api_a_input" in tokens:
        acquire("api_b_direct", lambda: cli_token(b, "Docs.Read"), b["appId"])
        acquire("api_b_obo", lambda: confidential("Docs.Read", tokens["api_a_input"]),
                b["appId"])
        if "api_b_direct" in tokens:
            acquire("api_b_metadata", lambda: cli_token(b, "Docs.Metadata"), b["appId"])
    else:
        report["blockers"].append(
            Blocked("api_b_obo", "BlockedByMissingApiAUserToken").public())

    core = {"api_a_input", "api_b_direct", "api_b_app_only", "api_b_obo"}
    if core.issubset(claims):
        report["experiments"] = experiments(tokens, claims, validator, state)
        report["relationships"] = {
            "input_cli_same_user_and_scope": (
                claims["api_a_input"]["oid"] == state["user"]
                and claims["api_a_input"].get("azp") == CLI_CLIENT
                and "access_as_user" in claims["api_a_input"].get("scp", "").split()
            ),
            "same_v2_api_b_audience": len({claims[n]["aud"] for n in core - {"api_a_input"}}) == 1,
            "direct_and_obo_same_user": claims["api_b_direct"]["oid"] == claims["api_b_obo"]["oid"] == state["user"],
            "direct_and_obo_same_tenant": claims["api_b_direct"]["tid"] == claims["api_b_obo"]["tid"] == state["tenant"],
            "direct_caller_is_cli": claims["api_b_direct"].get("azp") == CLI_CLIENT,
            "obo_caller_is_api_a": claims["api_b_obo"].get("azp") == a["appId"],
            "app_only_actor_is_api_a_sp": claims["api_b_app_only"]["oid"] == a["spId"],
            "app_only_has_role_not_user_scope": (
                not claims["api_b_app_only"].get("scp")
                and "Docs.Read.All" in claims["api_b_app_only"].get("roles", [])
            ),
        }
        report["scope_observations"] = {
            "cli_direct_requested": ["Docs.Read"],
            "cli_direct_issued": sorted(claims["api_b_direct"].get("scp", "").split()),
            "obo_requested": ["Docs.Read"],
            "obo_issued": sorted(claims["api_b_obo"].get("scp", "").split()),
            "missing_scope_negative": "OBO Docs.Read token against Docs.Metadata route",
        }
        if "api_b_metadata" in claims:
            report["scope_observations"].update({
                "cli_metadata_requested": ["Docs.Metadata"],
                "cli_metadata_issued": sorted(claims["api_b_metadata"].get("scp", "").split()),
                "cli_metadata_request_document_decision": authorize_delegated(
                    claims["api_b_metadata"], state["user"]),
            })
        passed = (all(report["relationships"].values())
                  and all(item["passed"] for item in report["experiments"]))
        report["proof_status"] = "complete" if passed else "failed"
    else:
        # Even partial proof runs a real app-role authorization check when possible.
        if "api_b_app_only" in claims:
            for document in ("alice", "bob"):
                decision = authorize_application(claims["api_b_app_only"], a["appId"])
                report["experiments"].append({
                    "name": f"api_b_app_only_{document}", "actual": decision,
                    "expected": "allow", "passed": decision == "allow",
                })
            decision = authorize_delegated(claims["api_b_app_only"], state["user"])
            report["experiments"].append({
                "name": "app_only_cannot_impersonate_owner", "actual": decision,
                "expected": "missing_scope", "passed": decision == "missing_scope",
            })
        report["proof_status"] = "partial" if claims else "blocked"
    report["status"] = (
        "succeeded" if report["proof_status"] == "complete" and not report["blockers"]
        else "blocked" if report["blockers"] else "failed"
    )
    if report["status"] == "succeeded":
        report["token_inspection"] = {
            name: inspect_verified_token(tokens[name], claims[name], state)
            for name in tokens
        }
    save_report(report, store)
    return tokens if return_raw_tokens and report["status"] == "succeeded" else None


def cleanup(graph, store, report):
    """Delete only recorded grants/assignments and exact verified new objects."""
    state = store.data
    resolve_confirmed_refusal(store)
    if state.get("pending_mutation"):
        raise Blocked("mutation", "PendingMutationRequiresReconciliation")
    for grant in list(state.get("grants", [])):
        try:
            actual = graph.call("GET", f"/oauth2PermissionGrants/{grant['id']}",
                                "verify_created_grant")
        except Blocked as error:
            if error.status != 404:
                raise
        else:
            if (actual.get("consentType") != "Principal"
                    or any(actual.get(key) != grant[key] for key in
                           ("clientId", "resourceId", "principalId", "scope"))):
                raise Blocked("verify_created_grant", "GrantOwnershipGuardFailed")
            graph.call("DELETE", f"/oauth2PermissionGrants/{grant['id']}",
                       "delete_created_grant")
        state["grants"].remove(grant)
        store.save()
        record(report, "delete_created_grant", store)
    for assignment in list(state.get("assignments", [])):
        path = (f"/servicePrincipals/{assignment['resourceId']}"
                f"/appRoleAssignedTo/{assignment['id']}")
        try:
            actual = graph.call("GET", path, "verify_created_assignment")
        except Blocked as error:
            if error.status != 404:
                raise
        else:
            if any(actual.get(key) != assignment[key] for key in
                   ("principalId", "resourceId", "appRoleId")):
                raise Blocked("verify_created_assignment", "AssignmentOwnershipGuardFailed")
            graph.call("DELETE", path, "delete_created_assignment")
        state["assignments"].remove(assignment)
        store.save()
        record(report, "delete_created_assignment", store)
    for name in ("a", "b"):
        app = state.get("apps", {}).get(name)
        if not app:
            continue
        app_exists = True
        try:
            owned_application(graph, store, name)
        except Blocked as error:
            if error.status != 404:
                raise
            app_exists = False
        # A missing application never proves its independently recorded SP is gone.
        if app.get("spId"):
            try:
                sp = graph.call(
                    "GET", f"/servicePrincipals/{app['spId']}?$select=id,appId,displayName,tags",
                    "verify_created_sp",
                )
            except Blocked as error:
                if error.status != 404:
                    raise
            else:
                if (sp.get("id") != app["spId"] or sp.get("appId") != app["appId"]
                        or sp.get("displayName") != app["displayName"]
                        or app["displayName"] not in allowed_app_display_names(state["prefix"], name)
                        or app.get("marker") and sp.get("tags") != [app["marker"]]):
                    raise Blocked("verify_created_sp", "ServicePrincipalOwnershipGuardFailed")
                graph.call("DELETE", f"/servicePrincipals/{app['spId']}", "delete_created_sp")
        if app_exists:
            graph.call("DELETE", f"/applications/{app['id']}", "delete_created_application")
        app["deleted"] = True
        store.save()
        record(report, "delete_created_application", store)
    state.pop("credential", None)
    state["cleanup_completed_at"] = now()
    store.save()
    report["cleanup"] = "completed_exact_recorded_objects"


def audit_resources(graph, store, report):
    """Enumerate all relevant collections; never mutate unknown objects."""
    state = store.data
    a, b = (owned_application(graph, store, name) for name in ("a", "b"))
    manifest = json.loads((ROOT / "lab-manifest.json").read_text(encoding="utf-8-sig"))
    if (manifest["api_a"]["delegated_scopes"] != ["access_as_user"]
            or manifest["api_b"]["delegated_scopes"] != ["Docs.Read", "Docs.Metadata"]
            or manifest["api_b"]["application_roles"] != ["Docs.Read.All"]):
        raise Blocked("resource_audit", "ResourceAuditMismatch")
    p = state["permissions"]
    scope_definitions = {
        "a": [permission("access_as_user", p["a"])],
        "b": [permission("Docs.Read", p["b"]), permission("Docs.Metadata", p["metadata"])],
    }
    role_definitions = {"a": [], "b": [application_role(p["role"])]}
    expected_access = [{
        "resourceAppId": b["appId"],
        "resourceAccess": [{"id": p["b"], "type": "Scope"}, {"id": p["role"], "type": "Role"}],
    }]

    def definitions_match(actual, expected):
        if len(actual) != len(expected):
            return False
        by_id = {item["id"]: item for item in actual}
        return len(by_id) == len(actual) and all(
            item["id"] in by_id and all(by_id[item["id"]].get(key) == value
                                       for key, value in item.items())
            for item in expected)

    def access_shape(values):
        return sorted((item["resourceAppId"], sorted(
            (entry["id"], entry["type"]) for entry in item["resourceAccess"]))
            for item in values)

    def grant_shape(item):
        return (item["id"], item["clientId"], item["resourceId"],
                item.get("principalId"), item.get("consentType", "Principal"),
                tuple(sorted(item["scope"].split())))

    def assignment_shape(item):
        return tuple(item[key] for key in ("id", "principalId", "resourceId", "appRoleId"))

    checks = {}
    all_grants = []
    expected_assignments = sorted(assignment_shape(item) for item in state["assignments"])
    for name, app in (("a", a), ("b", b)):
        actual = graph.call(
            "GET", f"/applications/{app['id']}?$select=api,appRoles,identifierUris,requiredResourceAccess",
            "audit_lab_application",
        )
        sp = graph.call(
            "GET", f"/servicePrincipals/{app['spId']}?$select=id,appId,oauth2PermissionScopes,appRoles",
            "audit_lab_sp",
        )
        api = actual.get("api", {})
        checks[f"api_{name}_v2"] = api.get("requestedAccessTokenVersion") == 2
        checks[f"api_{name}_only_own_identifier_uri"] = actual.get("identifierUris") == [
            f"api://{app['appId']}"]
        preauth = api.get("preAuthorizedApplications", [])
        checks[f"api_{name}_only_cli_preauthorized"] = (
            len(preauth) == 1 and preauth[0].get("appId") == CLI_CLIENT)
        checks[f"api_{name}_exact_preauthorization"] = (
            checks[f"api_{name}_only_cli_preauthorized"]
            and sorted(preauth[0].get("delegatedPermissionIds", []))
            == sorted(item["id"] for item in scope_definitions[name]))
        checks[f"api_{name}_exact_scope_definitions"] = definitions_match(
            api.get("oauth2PermissionScopes", []), scope_definitions[name])
        checks[f"api_{name}_exact_role_definitions"] = definitions_match(
            actual.get("appRoles", []), role_definitions[name])
        checks[f"api_{name}_sp_exact_scope_and_role_definitions"] = (
            sp.get("id") == app["spId"] and sp.get("appId") == app["appId"]
            and definitions_match(sp.get("oauth2PermissionScopes", []), scope_definitions[name])
            and definitions_match(sp.get("appRoles", []), role_definitions[name]))
        checks[f"api_{name}_exact_required_resource_access"] = (
            access_shape(actual.get("requiredResourceAccess", []))
            == access_shape(expected_access if name == "a" else []))
        all_grants.extend(graph.collection(
            f"/oauth2PermissionGrants?$filter=resourceId eq '{app['spId']}'",
            "audit_principal_consent"))
        for relationship, suffix, endpoint_key in (
            ("appRoleAssignedTo", "incoming", "resourceId"),
            ("appRoleAssignments", "outgoing", "principalId"),
        ):
            assignments = graph.collection(
                f"/servicePrincipals/{app['spId']}/{relationship}",
                "audit_lab_application_role")
            recorded = sorted(assignment_shape(item) for item in state["assignments"]
                              if item[endpoint_key] == app["spId"])
            checks[f"api_{name}_exact_all_{suffix}_role_assignments"] = (
                sorted(assignment_shape(item) for item in assignments) == recorded)
    checks["only_new_api_b_required_resource"] = checks["api_a_exact_required_resource_access"]
    expected_grants = sorted([
        (state["cliSpId"], a["spId"], state["user"], ("access_as_user",)),
        (state["cliSpId"], b["spId"], state["user"], ("Docs.Metadata", "Docs.Read")),
        (a["spId"], b["spId"], state["user"], ("Docs.Read",)),
    ])
    recorded_grants = sorted(
        (item["clientId"], item["resourceId"], item["principalId"],
         tuple(sorted(item["scope"].split()))) for item in state["grants"])
    exact_grants = (len(all_grants) == 3
                    and all(item.get("consentType") == "Principal" for item in all_grants)
                    and sorted(grant_shape(item) for item in all_grants)
                    == sorted(grant_shape(item) for item in state["grants"])
                    and recorded_grants == expected_grants)
    checks["three_exact_principal_only_custom_api_grants"] = exact_grants
    checks["no_unrecorded_or_tenant_wide_grants"] = exact_grants
    checks["one_role_assignment_only_between_new_sps"] = (
        len(expected_assignments) == 1
        and state["assignments"][0]["principalId"] == a["spId"]
        and state["assignments"][0]["resourceId"] == b["spId"]
        and state["assignments"][0]["appRoleId"] == p["role"]
        and all(checks[f"api_{name}_exact_all_{direction}_role_assignments"]
                for name in ("a", "b") for direction in ("incoming", "outgoing"))
        )
    policy = graph.call(
        "GET", "/policies/authorizationPolicy?$select=defaultUserRolePermissions",
        "audit_unchanged_creation_policy",
    )
    checks["default_user_creation_policy_unchanged"] = (
        policy["defaultUserRolePermissions"]["allowedToCreateApps"]
        == report["capability"]["default_user_allowed_to_create_apps"])
    report["resource_audit"] = {"checked_at": now(), "checks": checks}
    if not all(checks.values()):
        raise Blocked("resource_audit", "ResourceAuditMismatch")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command", choices=("probe", "prepare", "run", "resume", "audit", "cleanup",
                            "verify-report", "bind-existing-report", "reconcile", "token-view"))
    parser.add_argument("--run", help="Private run handle; defaults to latest private run")
    parser.add_argument("--view", choices=("encoded", "header", "payload"), default="encoded")
    parser.add_argument("--token-name", choices=(*TOKEN_NAMES, *TOKEN_ALIASES), default="api_b_obo")
    parser.add_argument("--show-raw-tokens", action="store_true",
                        help="LOCAL CONSOLE ONLY: print newly acquired bearer credentials")
    args = parser.parse_args(argv)
    args.token_name = TOKEN_ALIASES.get(args.token_name, args.token_name)
    if args.show_raw_tokens and (
            args.command not in ("run", "resume") or not sys.stdout.isatty()):
        parser.error("--show-raw-tokens requires run/resume and an unredirected local console")
    if args.command in ("verify-report", "token-view"):
        checks = {"privacy": False, "evidence_consistency": False,
                  "local_run_integrity": False, "remote_attestation": False}
        store = None
        try:
            report = json.loads(REPORT.read_text(encoding="utf-8-sig"))
            report_safety.privacy(report)
            checks["privacy"] = True
            report_safety.consistency(report, final=True)
            checks["evidence_consistency"] = True
            store = PrivateStore(args.run)
            store.verify_report(report)
            checks["local_run_integrity"] = True
        except (Blocked, OSError, ValueError, KeyError):
            pass
        verified = all(checks[key] for key in
                       ("privacy", "evidence_consistency", "local_run_integrity"))
        if args.command == "token-view":
            if verified:
                try:
                    state = getattr(store, "data", None)
                    print(report_safety.render_token_view(
                        report, args.token_name, args.view, state=state))
                    return 0
                except report_safety.Rejected:
                    pass
            print("Token view unavailable: verified local inspection evidence is required.")
            return 1
        print(json.dumps(checks, indent=2))
        return 0 if verified else 1

    # Verify the previous binding before any rewrite; never auto-reseal a
    # tampered report. Migration is explicit and does not rerun token acquisition.
    try:
        create = args.command in ("probe", "prepare")
        store = PrivateStore(args.run, create=create)
        importing = args.command == "bind-existing-report"
        if create:
            report = new_report()
            report["integrity"] = {
                "kind": "local_private_run_hmac", "origin": "live_local_capture",
                "bound_at": now(), "remote_attestation": False,
            }
            store.data["capturing_observations"] = True
            store.save()
        else:
            report = json.loads(REPORT.read_text(encoding="utf-8-sig"))
            if importing:
                legacy = report.get("capability", {}).pop(
                    "documented_application_management_roles", None)
                if legacy is not None:
                    report_safety.members(legacy, ROLE_NAMES)
                    store.data["application_management_roles"] = legacy
                    report["capability"]["application_management_role_available"] = bool(legacy)
            validate_report(report)
            if importing:
                if store.data.get("report_binding"):
                    raise Blocked("report_integrity", "ReportBindingAlreadyExists")
                report["integrity"] = {
                    "kind": "local_private_run_hmac",
                    "origin": "imported_existing_local_observations",
                    "bound_at": now(), "remote_attestation": False,
                }
            else:
                store.recover_report_write(report)
                store.verify_report(report)
            if args.command not in ("audit", "bind-existing-report"):
                report["blockers"] = []
            if args.command in ("run", "resume"):
                store.data["capturing_observations"] = True
                store.save()
                report["tokens"] = {}
                report["experiments"] = []
                report.pop("relationships", None)
                report.pop("scope_observations", None)
                report.pop("token_inspection", None)
                report["proof_status"] = "not_started"
                report["status"] = "running"
                report["execution_surface"] = new_report()["execution_surface"]
    except (Blocked, OSError, ValueError, KeyError) as error:
        blocker = error if isinstance(error, Blocked) else Blocked(
            "report_integrity", "ReportBindingMismatch")
        print(json.dumps({"status": "blocked", "blocker": blocker.public()}))
        return 2
    raw_tokens = None
    try:
        if not importing:
            save_report(report, store)
        graph = Graph()
        if args.command == "cleanup":
            cleanup(graph, store, report)
        elif args.command in ("audit", "bind-existing-report"):
            audit_resources(graph, store, report)
        elif args.command == "reconcile":
            reconcile_pending(graph, store)
        else:
            if args.command in ("probe", "prepare"):
                probe(graph, store, report)
            if args.command == "probe":
                report["status"] = "probe_only"
            elif args.command == "prepare":
                provision(graph, store, report)
                audit_resources(graph, store, report)
                # Allow normal directory propagation without retrying mutations.
                time.sleep(15)
                report["status"] = "provisioned"
            else:
                if "resource_audit" not in report:
                    audit_resources(graph, store, report)
                raw_tokens = acquire_and_compare(
                    store, report, return_raw_tokens=args.show_raw_tokens)
    except Blocked as error:
        report["blockers"].append(error.public())
        report["status"] = "blocked"
        if report["proof_status"] == "not_started":
            report["proof_status"] = "blocked"
    except Exception:
        # Tracebacks can contain identifiers or HTTP bodies; never emit them.
        report["blockers"].append(Blocked("local_execution", "LocalExecutionError").public())
        report["status"] = "blocked"
    report["finished_at"] = now()
    store.data.pop("capturing_observations", None)
    try:
        save_report(report, store, importing=importing)
    except (Blocked, OSError, ValueError):
        print(json.dumps({"status": "blocked", "code": "ReportBindingMismatch"}))
        return 2
    if args.show_raw_tokens and raw_tokens and report["status"] == "succeeded":
        display_raw_tokens(raw_tokens)
    print(json.dumps({
        "status": report["status"], "proof_status": report["proof_status"],
        "verified_tokens": sorted(report["tokens"]), "blockers": report["blockers"],
        "cleanup": report["cleanup"],
    }, indent=2))
    successful_action = (
        report["status"] in ("succeeded", "probe_only", "provisioned")
        or args.command in ("cleanup", "audit", "reconcile", "bind-existing-report")
        and not report["blockers"]
    )
    return 0 if successful_action else 2


if __name__ == "__main__":
    sys.exit(main())
