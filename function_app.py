"""Azure Function — Teams Webhook proxy for Databricks Job Triage Agent.

No Entra ID or Bot Framework required. Uses:
  - Teams Outgoing Webhook (HMAC-SHA256 validation) for receiving commands
  - Teams Incoming Webhook (simple POST) for pushing results back
  - Databricks M2M OAuth for authenticating to the triage app

Flow:
  1. User @mentions the outgoing webhook in Teams: "@TriageBot triage 12345"
  2. Teams POSTs the message to this Function (HMAC-signed)
  3. Function validates HMAC, returns immediate acknowledgment (< 5 sec)
  4. Background thread: gets Databricks token, calls /triage/{job_id}
  5. When triage completes: POSTs formatted result to Incoming Webhook URL
  6. Result appears as a new message in the Teams channel
"""

import os
import re
import json
import hmac
import hashlib
import base64
import logging
import threading
from datetime import datetime, timezone, timedelta

import azure.functions as func
import httpx

# ---------------------------------------------------------------------------
# Configuration (set via Azure Function App Settings)
# ---------------------------------------------------------------------------
DATABRICKS_HOST = os.environ.get("DATABRICKS_HOST", "")
DATABRICKS_SP_CLIENT_ID = os.environ.get("DATABRICKS_SP_CLIENT_ID", "")
DATABRICKS_SP_SECRET = os.environ.get("DATABRICKS_SP_SECRET", "")
TRIAGE_APP_URL = os.environ.get("TRIAGE_APP_URL", "")
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "")

# Teams webhook config
TEAMS_OUTGOING_WEBHOOK_SECRET = os.environ.get("TEAMS_OUTGOING_WEBHOOK_SECRET", "")
TEAMS_INCOMING_WEBHOOK_URL = os.environ.get("TEAMS_INCOMING_WEBHOOK_URL", "")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("teams-triage-bot")


# ---------------------------------------------------------------------------
# HMAC Validation (Teams Outgoing Webhook uses HMAC-SHA256)
# ---------------------------------------------------------------------------
def validate_hmac(request_body: bytes, auth_header: str) -> bool:
    """Validate the HMAC-SHA256 signature from Teams Outgoing Webhook.

    Teams sends: Authorization: HMAC <base64-encoded-signature>
    We compute HMAC-SHA256(base64decode(secret), request_body) and compare.
    """
    if not TEAMS_OUTGOING_WEBHOOK_SECRET:
        logger.warning("No TEAMS_OUTGOING_WEBHOOK_SECRET — skipping validation (dev mode)")
        return True

    if not auth_header or not auth_header.startswith("HMAC "):
        return False

    provided_signature = auth_header[5:]  # Strip "HMAC " prefix
    secret_bytes = base64.b64decode(TEAMS_OUTGOING_WEBHOOK_SECRET)

    computed = hmac.new(
        secret_bytes,
        msg=request_body,
        digestmod=hashlib.sha256,
    ).digest()
    computed_signature = base64.b64encode(computed).decode("utf-8")

    return hmac.compare_digest(provided_signature, computed_signature)


# ---------------------------------------------------------------------------
# Token Cache (avoids fetching a new token on every request)
# ---------------------------------------------------------------------------
_token_cache = {"token": None, "expires_at": None}


def get_databricks_token() -> str:
    """Get M2M OAuth token via client_credentials. Caches for 50 min (token lasts 60)."""
    now = datetime.now(timezone.utc)
    if _token_cache["token"] and _token_cache["expires_at"] and now < _token_cache["expires_at"]:
        return _token_cache["token"]

    with httpx.Client(timeout=30) as client:
        resp = client.post(
            f"{DATABRICKS_HOST}/oidc/v1/token",
            data={
                "grant_type": "client_credentials",
                "client_id": DATABRICKS_SP_CLIENT_ID,
                "client_secret": DATABRICKS_SP_SECRET,
                "scope": "all-apis",
            },
        )
        resp.raise_for_status()
        data = resp.json()
        _token_cache["token"] = data["access_token"]
        _token_cache["expires_at"] = now + timedelta(minutes=50)
        logger.info("Databricks M2M token acquired/refreshed")
        return _token_cache["token"]


# ---------------------------------------------------------------------------
# Triage App Client
# ---------------------------------------------------------------------------
def call_triage(job_id: str) -> dict:
    """Call the Databricks triage app endpoint with proper auth."""
    token = get_databricks_token()
    with httpx.Client(timeout=120) as client:
        resp = client.post(
            f"{TRIAGE_APP_URL}/triage/{job_id}",
            params={"token": WEBHOOK_SECRET},
            headers={"Authorization": f"Bearer {token}"},
        )
        if resp.status_code == 404:
            return {"status": "no_errors_found", "job_id": job_id}
        resp.raise_for_status()
        return resp.json()


# ---------------------------------------------------------------------------
# Response Formatter
# ---------------------------------------------------------------------------
def format_triage_response(result: dict) -> str:
    """Format triage JSON into Teams-compatible markdown."""
    d = result.get("diagnosis", {})
    r = result.get("recommendation", {})
    fix = result.get("proposed_fix")
    steps = "\n".join(f"  {i+1}. {s}" for i, s in enumerate(r.get("steps", [])))

    msg = (
        f"**\U0001f6a8 {result.get('job_name')}** (Job {result.get('job_id')}, Run {result.get('run_id')})\n\n"
        f"**Category:** {d.get('category')} ({float(d.get('confidence', 0)):.0%} confidence)\n\n"
        f"**Root Cause:** {d.get('root_cause_summary')}\n\n"
        f"**Explanation:** {r.get('explanation')}\n\n"
        f"**Recommended Steps:**\n{steps}\n\n"
    )

    if fix and fix.get("fix_type") == "INSTALL_LIBRARY":
        msg += (
            f"**Proposed Fix:** Install `{fix.get('package_name')}` "
            f"(missing module: `{fix.get('detected_module')}`)\n\n"
        )

    if result.get("library_fix_link"):
        msg += f"[Apply Fix & Rerun]({result.get('library_fix_link')}) | "

    msg += f"[Approve & Restart]({result.get('approval_link')})"
    return msg


# ---------------------------------------------------------------------------
# Push Result to Teams via Incoming Webhook
# ---------------------------------------------------------------------------
def post_to_teams(message: str) -> None:
    """POST a message to the Teams channel via Incoming Webhook."""
    if not TEAMS_INCOMING_WEBHOOK_URL:
        logger.error("TEAMS_INCOMING_WEBHOOK_URL not configured")
        return

    payload = {"text": message}
    with httpx.Client(timeout=30) as client:
        resp = client.post(TEAMS_INCOMING_WEBHOOK_URL, json=payload)
        if resp.status_code in (200, 202):
            logger.info("Result posted to Teams channel")
        else:
            logger.error(f"Incoming webhook failed: {resp.status_code} {resp.text[:200]}")


# ---------------------------------------------------------------------------
# Background Triage Worker
# ---------------------------------------------------------------------------
def triage_and_post(job_id: str) -> None:
    """Run triage in background thread, then post result to Teams."""
    try:
        result = call_triage(job_id)
        if result.get("status") == "no_errors_found":
            post_to_teams(f"\u2705 No recent failed runs found for job **{job_id}**.")
        else:
            post_to_teams(format_triage_response(result))
    except httpx.HTTPStatusError as e:
        post_to_teams(
            f"\u274c Triage failed for job {job_id}: HTTP {e.response.status_code}\n\n"
            f"`{e.response.text[:300]}`"
        )
    except Exception as e:
        post_to_teams(f"\u274c Triage error for job {job_id}: {str(e)[:300]}")


# ---------------------------------------------------------------------------
# Message Parser
# ---------------------------------------------------------------------------
TRIAGE_CMD = re.compile(r"(?:triage|check|status)\s+(\d+)", re.IGNORECASE)
JOB_ID_ONLY = re.compile(r"(\d{5,})")  # Fallback: any long number


def extract_job_id(text: str) -> str | None:
    """Extract job ID from user message."""
    text = re.sub(r"<at>.*?</at>\s*", "", text).strip()
    match = TRIAGE_CMD.search(text)
    if match:
        return match.group(1)
    match = JOB_ID_ONLY.search(text)
    if match:
        return match.group(1)
    return None


# ---------------------------------------------------------------------------
# Azure Function Entry Point
# ---------------------------------------------------------------------------
app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)


@app.route(route="api/messages", methods=["POST"])
def messages(req: func.HttpRequest) -> func.HttpResponse:
    """Teams Outgoing Webhook endpoint.

    Teams sends a JSON payload with the message when user @mentions the webhook.
    Must respond within 5 seconds. For long-running triage, responds immediately
    and posts the result to the Incoming Webhook asynchronously.
    """
    # 1. Validate HMAC signature from Teams
    request_body = req.get_body()
    auth_header = req.headers.get("Authorization", "")

    if not validate_hmac(request_body, auth_header):
        logger.warning("HMAC validation failed")
        return func.HttpResponse(
            json.dumps({"type": "message", "text": "Unauthorized"}),
            status_code=401,
            mimetype="application/json",
        )

    # 2. Parse the incoming message
    body = req.get_json()
    text = body.get("text", "")
    logger.info(f"Received: {text[:100]}")

    # 3. Extract job ID
    job_id = extract_job_id(text)

    if not job_id:
        return func.HttpResponse(
            json.dumps({
                "type": "message",
                "text": "Send `triage <job_id>` to diagnose the latest failure.\n\n"
                        "Example: `@TriageBot triage 424360210276016`",
            }),
            status_code=200,
            mimetype="application/json",
        )

    # 4. Kick off triage in background thread (won't block the 5s response)
    thread = threading.Thread(target=triage_and_post, args=(job_id,), daemon=True)
    thread.start()

    # 5. Return immediate acknowledgment (must be < 5 seconds)
    return func.HttpResponse(
        json.dumps({
            "type": "message",
            "text": f"\u23f3 Triaging job **{job_id}**... results will appear in 30\u201360 seconds.",
        }),
        status_code=200,
        mimetype="application/json",
    )
