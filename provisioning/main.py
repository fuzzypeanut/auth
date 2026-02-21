"""
FuzzyPeanut Provisioning Service

Listens for Authentik webhook events and provisions/deprovisions resources
across FuzzyPeanut services (mailboxes, future: CalDAV collections, file homes).

Webhook flow:
  Authentik → POST /webhook → validate signature → respond 200 immediately
                             → spawn background task → retry up to 3× on failure
                             → write to FAILURES_FILE on final failure

Configure in Authentik: System → Outposts → create a Notification webhook
pointing at http://provisioning:3200/webhook.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import random
from datetime import datetime, timezone

import httpx
from fastapi import FastAPI, Header, HTTPException, Request

log = logging.getLogger("provisioning")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)

WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "")
STALWART_API   = os.environ.get("STALWART_API", "http://stalwart:8080")
STALWART_TOKEN = os.environ.get("STALWART_TOKEN", "")
MAIL_DOMAIN    = os.environ.get("MAIL_DOMAIN", "fuzzypeanut.local")
# File to persist failed provisioning records for operator review.
FAILURES_FILE  = os.environ.get("FAILURES_FILE", "/data/provisioning-failures.jsonl")

# Retry policy: 3 attempts, exponential backoff + uniform jitter
_RETRY_DELAYS = [2.0, 4.0, 8.0]  # seconds between attempts
_RETRY_JITTER = 1.0               # up to 1s added randomly to each delay

app = FastAPI(title="FuzzyPeanut Provisioning", version="0.1.0")


# ─── Signature verification ───────────────────────────────────────────────────

def _verify_signature(body: bytes, signature: str) -> bool:
    if not WEBHOOK_SECRET:
        log.warning("WEBHOOK_SECRET not set — skipping signature verification (dev mode)")
        return True
    expected = hmac.new(WEBHOOK_SECRET.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)


# ─── Failure persistence ──────────────────────────────────────────────────────

async def _record_failure(user_id: str, event_type: str, error: str) -> None:
    record = {
        "user_id": user_id,
        "event_type": event_type,
        "error": error,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    log.error("PROVISIONING FAILURE (manual remediation required): %s", json.dumps(record))
    try:
        os.makedirs(os.path.dirname(FAILURES_FILE), exist_ok=True)
        with open(FAILURES_FILE, "a") as f:
            f.write(json.dumps(record) + "\n")
    except Exception as e:
        log.error("Could not write failure record to %s: %s", FAILURES_FILE, e)


# ─── Retry wrapper ────────────────────────────────────────────────────────────

async def _with_retry(coro_fn, user_id: str, event_type: str) -> None:
    """
    Call coro_fn() up to 3 times with exponential backoff + jitter.
    On final failure, persist a record and log at ERROR level.
    coro_fn is a zero-arg async callable (use functools.partial or a lambda).
    """
    last_error: Exception | None = None
    for attempt, delay in enumerate(_RETRY_DELAYS, start=1):
        try:
            await coro_fn()
            if attempt > 1:
                log.info("Provisioning succeeded on attempt %d for %s/%s", attempt, event_type, user_id)
            return
        except Exception as e:
            last_error = e
            if attempt < len(_RETRY_DELAYS):
                jitter = random.uniform(0, _RETRY_JITTER)
                log.warning(
                    "Provisioning attempt %d/%d failed for %s/%s: %s — retrying in %.1fs",
                    attempt, len(_RETRY_DELAYS), event_type, user_id, e, delay + jitter,
                )
                await asyncio.sleep(delay + jitter)
            else:
                log.error(
                    "Provisioning failed after %d attempts for %s/%s: %s",
                    len(_RETRY_DELAYS), event_type, user_id, e,
                )
    await _record_failure(user_id, event_type, str(last_error))


# ─── Webhook endpoint ─────────────────────────────────────────────────────────

@app.post("/webhook")
async def authentik_webhook(
    request: Request,
    x_authentik_signature: str = Header(default=""),
) -> dict:
    body = await request.body()

    if not _verify_signature(body, x_authentik_signature):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    event = await request.json()
    event_type = event.get("type", "")
    user = event.get("user", {})
    user_id = str(user.get("pk") or user.get("username") or "unknown")

    log.info("Received event: %s for user: %s", event_type, user.get("username"))

    # Respond 200 immediately — retry happens in the background.
    # Authentik will not retry if it receives a 2xx response.
    if event_type == "user_created":
        asyncio.create_task(
            _with_retry(lambda: _provision_user(user), user_id, "user_created")
        )
    elif event_type == "user_deleted":
        asyncio.create_task(
            _with_retry(lambda: _deprovision_user(user), user_id, "user_deleted")
        )
    elif event_type == "user_updated":
        asyncio.create_task(
            _with_retry(lambda: _update_user(user), user_id, "user_updated")
        )
    else:
        log.debug("Ignoring unhandled event type: %s", event_type)

    return {"status": "ok"}


# ─── Provisioning logic ───────────────────────────────────────────────────────

async def _provision_user(user: dict) -> None:
    username = user.get("username", "")
    email = user.get("email", "") or f"{username}@{MAIL_DOMAIN}"
    if not username:
        return

    await _stalwart_create_account(username, email)
    log.info("Provisioned mailbox for %s (%s)", username, email)
    # Future: create Radicale CalDAV/CardDAV collection
    # Future: create file store home directory


async def _deprovision_user(user: dict) -> None:
    username = user.get("username", "")
    if not username:
        return

    await _stalwart_delete_account(username)
    log.info("Deprovisioned mailbox for %s", username)


async def _update_user(user: dict) -> None:
    """
    Handle user_updated events. Only syncs email address changes.
    Username changes: logged and ignored (no rename support in Stalwart).
    Display name changes: no action needed.
    """
    username = user.get("username", "")
    email = user.get("email", "")
    if not username or not email:
        return

    await _stalwart_update_email(username, email)
    log.info("Updated email for %s → %s", username, email)


# ─── Stalwart admin API calls ─────────────────────────────────────────────────

def _stalwart_headers() -> dict:
    return {"Authorization": f"Bearer {STALWART_TOKEN}"}


async def _stalwart_create_account(username: str, email: str) -> None:
    if not STALWART_TOKEN:
        log.warning("STALWART_TOKEN not set — skipping mailbox creation for %s", username)
        return

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{STALWART_API}/api/principal",
            headers=_stalwart_headers(),
            json={
                "type": "individual",
                "name": username,
                "emails": [email],
                "quota": 0,  # unlimited
                "secrets": [],
            },
            timeout=10,
        )
        # 409 = already exists — idempotent, treat as success
        if resp.status_code not in (200, 201, 409):
            resp.raise_for_status()


async def _stalwart_delete_account(username: str) -> None:
    if not STALWART_TOKEN:
        log.warning("STALWART_TOKEN not set — skipping mailbox deletion for %s", username)
        return

    async with httpx.AsyncClient() as client:
        resp = await client.delete(
            f"{STALWART_API}/api/principal/{username}",
            headers=_stalwart_headers(),
            timeout=10,
        )
        # 404 = already gone — idempotent, treat as success
        if resp.status_code not in (200, 204, 404):
            resp.raise_for_status()


async def _stalwart_update_email(username: str, email: str) -> None:
    """
    Update the primary email address on an existing Stalwart account.
    Uses PATCH with a field-level update operation.
    Ref: https://stalw.art/docs/management/api/overview
    """
    if not STALWART_TOKEN:
        log.warning("STALWART_TOKEN not set — skipping email update for %s", username)
        return

    async with httpx.AsyncClient() as client:
        resp = await client.patch(
            f"{STALWART_API}/api/principal/{username}",
            headers=_stalwart_headers(),
            json=[{"action": "set", "field": "emails", "value": [email]}],
            timeout=10,
        )
        # 404 = account doesn't exist yet — log but don't fail
        if resp.status_code == 404:
            log.warning("Stalwart account not found for email update: %s", username)
            return
        if resp.status_code not in (200, 204):
            resp.raise_for_status()


# ─── Health ───────────────────────────────────────────────────────────────────

@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}
