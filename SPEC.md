# Wallos platform integration

This independent fork owns the Wallos application implementation. Platform topology,
production runtime definitions, App Contract and rollout approval live only in
`D:/DEV/Lab/vps-homelab`.

## Fixed input and supported mode

- Upstream/fork baseline: v5.8.2, `392893651bf037a5bda2ce25401f5bf549073b43`.
- Fork: `https://github.com/Forlooong/Wallos`; integration branch `platform/wallos-integration`.
- Sole application prefix `/apps/wallos/`; production issuer `https://www.040323.xyz/auth`.
- This image requires `HOMELAB_ENABLED=1`; it is not an unauthenticated general Wallos distribution.
- Each authorized member owns separate subscriptions, settings, currencies, categories,
  payment methods, household entries and uploads. No implicit cross-account sharing.

## Authentication and authorization

The maintained Composer OIDC client validates the signed code flow with S256 PKCE;
platform checks additionally require one-time state, nonce, issuer/audience, expiry,
RS256 and matching verified userinfo subject. Identity rows are keyed by issuer and
subject. Username collisions are rejected; neither username nor email merges accounts.

Every private PHP request uses `homelab_prepend.php`, configured as a PHP-FPM admin
value, to recheck the current website session. The application session is bound to
that website Cookie hash and identity. Missing/expired/switched website sessions
cannot revive a previous Wallos session through an upstream remember token.
Provider failures deny private access. The PHP session Cookie is `wallos_session`,
Secure/HttpOnly/SameSite=Lax, scoped to `/apps/wallos/`.

An empty database receives a reserved non-login ID 1. OIDC members are ordinary IDs
above 1. Global administration, full database download/restore, local password/TOTP,
public signup, account deletion, independent API keys, external calendar clients,
notifications and AI endpoints are denied by the server in this first integration.
The UI does not expose these unavailable controls. Password changes remain on the
existing platform account page.

Uploaded logos, variants and avatars are never served by nginx's public static handler.
`private_file.php` requires a current owner reference and verifies the real path and
image MIME. Random upload names prevent same-name writes from replacing another
member's file. Private responses are not cached; the Service Worker caches only an
explicit public static list within a Wallos-specific namespace and never deletes other
applications' caches. There is no offline private-page fallback.

## Runtime and persistence

The image starts its root supervisor only to set up permissions and processes; nginx,
PHP-FPM workers and subscription maintenance run as configured PUID/PGID (1001:1001
in the proposed deployment). The database and reserved identity must initialize before
HTTP opens. PHP-FPM uses a Unix socket. Production nginx binds only 127.0.0.1:18081.
Access logging is off so authorization queries and private paths are not recorded.

Two submounts share one canonical root `/data/homelab/apps/wallos/data/`: `db/` maps to
`/var/www/html/db`, `logos/` maps to `/var/www/html/images/uploads/logos`. SQLite journal/WAL
and all uploads belong to this App. No Notes or identity database is opened directly.
The platform unit enforces the `/data` UUID and `create_host_path=false`; no production
data is used by development tests. Startup may migrate/write the database, so image
rollback is not automatically a safe data rollback.

## Validation and release

Reuse `php tests/run.php homelab`, `php tests/run.php pwa_manifest` and the focused
Service Worker test. `tests/homelab_integration.py --image <local candidate>` uses an
isolated OIDC/site-session fixture, temporary CA and synthetic accounts/data only.
Results go to `test-results/`; test containers, keys and fixture data are removed.
No screenshots, credentials, response bodies or private production data are retained.

Only committed Git-archive bytes produce a release image. Composer lockfile, base
image digests, source revision and registry manifest digest are release evidence.
The control repository keeps the production card disabled until the separately
reviewed identity/route change and real-entry acceptance are complete.
