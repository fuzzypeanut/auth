# fuzzypeanut/auth

Authentik identity provider configuration and FuzzyPeanut provisioning service.

## What's here

| Path | Purpose |
|---|---|
| `docker-compose.yml` | Authentik server, worker, Postgres, Redis |
| `.env.example` | Required environment variables |
| `blueprints/fuzzypeanut.yaml` | Authentik blueprint — shell OIDC app, groups, branding |
| `provisioning/` | Python FastAPI webhook listener — auto-provisions mailboxes on user create |

## First-time setup

```bash
cp .env.example .env
# Edit .env — at minimum set AUTHENTIK_SECRET_KEY and AUTHENTIK_DB_PASSWORD
# Generate secret key:
openssl rand -hex 32

docker compose up -d
```

Authentik will be available at `http://localhost:9000`. Complete the initial admin setup at `/if/flow/initial-setup/`.

The blueprint at `blueprints/fuzzypeanut.yaml` is auto-applied on startup. It creates:
- `fuzzypeanut-users` and `fuzzypeanut-admins` groups
- The `FuzzyPeanut Shell` OIDC application (client ID: `fuzzypeanut-shell`)

## Provisioning service

The provisioning service listens for Authentik webhooks and auto-creates resources when users are added or removed.

To connect: in Authentik → System → Outposts → create a webhook integration pointing to `http://provisioning:3200/webhook`.

Environment variables:
| Variable | Description |
|---|---|
| `WEBHOOK_SECRET` | HMAC secret — must match Authentik webhook config |
| `STALWART_API` | Stalwart admin API base URL |
| `STALWART_TOKEN` | Stalwart admin API token |
| `MAIL_DOMAIN` | Default mail domain (e.g. `fuzzypeanut.local`) |

## Theming

Authentik brand/theme customization (login page, colors) is configured via the Authentik admin UI under `System → Brands`. Match the FuzzyPeanut design tokens:
- Primary: `#5b4fcf`
- Background: `#f5f5fb` (light) / `#1a1a2e` (dark)

## License

MIT
