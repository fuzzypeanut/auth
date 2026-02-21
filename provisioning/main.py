"""
FuzzyPeanut Provisioning Service

Listens for Authentik webhook events and provisions/deprovisions
resources across FuzzyPeanut services (mailboxes, CalDAV collections, etc.).

Authentik → System Tasks → Outposts/Webhook → POST /webhook
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os

import httpx
from fastapi import FastAPI, Header, HTTPException, Request

log = logging.getLogger("provisioning")
logging.basicConfig(level=logging.INFO)

WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "")
STALWART_API = os.environ.get("STALWART_API", "http://stalwart:8080")
STALWART_TOKEN = os.environ.get("STALWART_TOKEN", "")
MAIL_DOMAIN = os.environ.get("MAIL_DOMAIN", "fuzzypeanut.local")

app = FastAPI(title="FuzzyPeanut Provisioning", version="0.1.0")


def _verify_signature(body: bytes, signature: str) -> bool:
    if not WEBHOOK_SECRET:
        return True  # skip verification in dev if no secret set
    expected = hmac.new(WEBHOOK_SECRET.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)


@app.post("/webhook")
async def authentik_webhook(
    request: Request,
    x_authentik_signature: str = Header(default=""),
) -> dict:
    body = await request.body()

    if not _verify_signature(body, x_authentik_signature):
        raise HTTPException(status_code=401, detail="Invalid signature")

    event = await request.json()
    event_type = event.get("type", "")
    user = event.get("user", {})

    log.info("Received event: %s for user: %s", event_type, user.get("username"))

    if event_type == "user_created":
        await _provision_user(user)
    elif event_type == "user_deleted":
        await _deprovision_user(user)

    return {"status": "ok"}


async def _provision_user(user: dict) -> None:
    username = user.get("username", "")
    email = user.get("email", "") or f"{username}@{MAIL_DOMAIN}"

    if not username:
        return

    # Create Stalwart mailbox
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


async def _stalwart_create_account(username: str, email: str) -> None:
    if not STALWART_TOKEN:
        log.warning("STALWART_TOKEN not set — skipping mailbox creation for %s", username)
        return

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{STALWART_API}/api/principal",
            headers={"Authorization": f"Bearer {STALWART_TOKEN}"},
            json={
                "type": "individual",
                "name": username,
                "emails": [email],
                "quota": 0,  # unlimited
                "secrets": [],
            },
        )
        if resp.status_code not in (200, 201, 409):
            log.error("Stalwart create failed: %s %s", resp.status_code, resp.text)
            resp.raise_for_status()


async def _stalwart_delete_account(username: str) -> None:
    if not STALWART_TOKEN:
        return

    async with httpx.AsyncClient() as client:
        resp = await client.delete(
            f"{STALWART_API}/api/principal/{username}",
            headers={"Authorization": f"Bearer {STALWART_TOKEN}"},
        )
        if resp.status_code not in (200, 204, 404):
            log.error("Stalwart delete failed: %s %s", resp.status_code, resp.text)


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}
