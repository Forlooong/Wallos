"""Isolated Wallos HTTP/OIDC/browser acceptance. Never connects to production.

Usage: python tests/homelab_integration.py --image wallos-integration:working
The candidate image must already exist. No builds, pulls, production cookies,
screenshots, response-body logs or retained fixture data are created.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import html
import http.client
import http.cookies
import http.server
import json
import os
import re
from pathlib import Path
import secrets
import shutil
import socket
import sqlite3
import ssl
import subprocess
import threading
import traceback
import time
import urllib.parse as url

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
ORIGIN = "https://localhost:18443"
APP = ORIGIN + "/apps/wallos/"
ISSUER = "https://provider.localhost:19443"
CALLBACK = APP + "homelab-oidc.php"
USERS = ("zhuqing", "yaojia")


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def cookies(header: str) -> dict:
    jar = http.cookies.SimpleCookie()
    jar.load(header or "")
    return {key: value.value for key, value in jar.items()}


class Fixture:
    def __init__(self, path: Path):
        self.path = path
        self.secret = secrets.token_urlsafe(32)
        self.sessions, self.providers, self.codes, self.tokens = {}, {}, {}, {}
        self.network = []
        self.signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.exchanges = 0
        self.step = "prepare"
        self.checks = []

    def check(self, name, condition):
        self.step = name
        if not condition:
            raise AssertionError(name)
        self.checks.append(name)

    def certificate(self):
        now = dt.datetime.now(dt.timezone.utc)
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Wallos ephemeral integration CA")])
        ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
              .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
              .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=1))
              .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
              .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
              .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
              .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=False, content_commitment=False, data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
              .sign(ca_key, hashes.SHA256()))
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        leaf = (x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
                .issuer_name(ca_name).public_key(leaf_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=1))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.DNSName("provider.localhost")]), critical=False)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
                .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=True, content_commitment=False, data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
                .sign(ca_key, hashes.SHA256()))
        (self.path / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        (self.path / "server.pem").write_bytes(leaf.public_bytes(serialization.Encoding.PEM) + ca.public_bytes(serialization.Encoding.PEM))
        (self.path / "server.key").write_bytes(leaf_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        spki = leaf_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        return base64.b64encode(hashlib.sha256(spki).digest()).decode()

    def jwt(self, claims):
        header = b64(json.dumps({"alg": "RS256", "kid": "integration", "typ": "JWT"}, separators=(",", ":")).encode())
        payload = b64(json.dumps(claims, separators=(",", ":")).encode())
        signing = (header + "." + payload).encode()
        signature = self.signing_key.sign(signing, padding.PKCS1v15(), hashes.SHA256())
        return signing.decode() + "." + b64(signature)


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass  # No authorization codes, Cookies, tokens or private paths in logs.

    def reply(self, status, body=b"", headers=()):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        for key, value in headers:
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            try:
                self.wfile.write(body)
            except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
                pass  # Chromium deliberately disconnects during offline/logout tests.

    def redirect(self, location, extra=()):
        self.reply(302, headers=[("Location", location), ("Cache-Control", "no-store"), *extra])

    def json(self, status, value):
        self.reply(status, json.dumps(value), [("Content-Type", "application/json"), ("Cache-Control", "no-store")])

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        self.route()

    def do_POST(self):
        self.route()

    def route(self):
        fixture = self.server.fixture
        fixture.network.append({"port": self.server.server_port, "method": self.command, "path": url.urlsplit(self.path).path})
        parsed = url.urlsplit(self.path)
        query = {key: values[0] for key, values in url.parse_qs(parsed.query).items()}
        jar = cookies(self.headers.get("Cookie", ""))
        port = self.server.server_port
        if port == 19092:
            user = fixture.sessions.get(jar.get("site_session"))
            self.reply(200 if user else 401, headers=[("Remote-User", user or ""), ("Remote-Groups", "site-users" if user else "")])
            return
        if port == 19443:
            self.provider(fixture, parsed.path, query, jar)
            return
        if parsed.path == "/auth/":
            rd = query.get("rd", APP)
            links = "".join('<a href="/auth/select?' + html.escape(url.urlencode({"user": user, "rd": rd}), quote=True) + '">' + user + ' (test only)</a><br>' for user in USERS)
            self.reply(200, "<!doctype html><title>Isolated fixture login</title><h1>Local test accounts; no password</h1>" + links, [("Content-Type", "text/html"), ("Cache-Control", "no-store")])
        elif parsed.path == "/auth/select" and query.get("user") in USERS:
            token = secrets.token_urlsafe(32)
            fixture.sessions[token] = query["user"]
            rd = query.get("rd", APP)
            if not rd.startswith(ORIGIN + "/"):
                self.reply(400)
                return
            self.redirect(ISSUER + "/test-login?" + url.urlencode({"user": query["user"], "rd": rd}), [("Set-Cookie", "site_session=" + token + "; Path=/; Secure; HttpOnly; SameSite=Lax")])
        elif parsed.path == "/test/logout":
            fixture.sessions.pop(jar.get("site_session"), None)
            self.reply(200, "Local website session ended", [("Set-Cookie", "site_session=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax")])
        elif parsed.path == "/":
            self.reply(200, "<!doctype html><title>Fixture Home</title><p>Local test Home</p>", [("Content-Type", "text/html")])
        else:
            self.proxy()

    def provider(self, fixture, path, query, jar):
        if path == "/test-login" and query.get("user") in USERS:
            token = secrets.token_urlsafe(32)
            fixture.providers[token] = query["user"]
            self.redirect(query.get("rd", APP), [("Set-Cookie", "provider_session=" + token + "; Path=/; Secure; HttpOnly; SameSite=Lax")])
        elif path == "/.well-known/openid-configuration":
            self.json(200, {"issuer": ISSUER, "authorization_endpoint": ISSUER + "/authorize", "token_endpoint": ISSUER + "/token", "userinfo_endpoint": ISSUER + "/userinfo", "jwks_uri": ISSUER + "/jwks", "response_types_supported": ["code"], "subject_types_supported": ["public"], "id_token_signing_alg_values_supported": ["RS256"], "token_endpoint_auth_methods_supported": ["client_secret_basic"], "code_challenge_methods_supported": ["S256"], "scopes_supported": ["openid", "profile", "email"]})
        elif path == "/jwks":
            pub = fixture.signing_key.public_key().public_numbers()
            self.json(200, {"keys": [{"kty": "RSA", "kid": "integration", "use": "sig", "alg": "RS256", "n": b64(pub.n.to_bytes((pub.n.bit_length()+7)//8, "big")), "e": b64(pub.e.to_bytes((pub.e.bit_length()+7)//8, "big"))}]})
        elif path == "/authorize":
            user = fixture.providers.get(jar.get("provider_session"))
            if not user or query.get("client_id") != "wallos-test" or query.get("redirect_uri") != CALLBACK or query.get("response_type") != "code" or query.get("code_challenge_method") != "S256" or not query.get("nonce") or not query.get("state"):
                self.json(400, {"error": "invalid_request"})
                return
            code = secrets.token_urlsafe(32)
            fixture.codes[code] = {**query, "user": user}
            self.redirect(CALLBACK + "?" + url.urlencode({"code": code, "state": query["state"]}))
        elif path == "/token" and self.command == "POST":
            form = {key: values[0] for key, values in url.parse_qs(self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()).items()}
            record = fixture.codes.pop(form.get("code"), None)
            expected = "Basic " + base64.b64encode(("wallos-test:" + fixture.secret).encode()).decode()
            if self.headers.get("Authorization") != expected or not record or form.get("grant_type") != "authorization_code" or form.get("redirect_uri") != CALLBACK or b64(hashlib.sha256(form.get("code_verifier", "").encode()).digest()) != record["code_challenge"]:
                self.json(400, {"error": "invalid_grant"})
                return
            access = secrets.token_urlsafe(32)
            fixture.tokens[access] = record["user"]
            now = int(time.time())
            token = fixture.jwt({"iss": ISSUER, "sub": "test-sub-" + record["user"], "aud": "wallos-test", "nonce": record["nonce"], "iat": now, "exp": now + 300})
            fixture.exchanges += 1
            self.json(200, {"access_token": access, "token_type": "Bearer", "expires_in": 300, "id_token": token})
        elif path == "/userinfo":
            user = fixture.tokens.get(self.headers.get("Authorization", "").removeprefix("Bearer "))
            if not user:
                self.json(401, {"error": "invalid_token"})
                return
            self.json(200, {"sub": "test-sub-" + user, "preferred_username": user, "name": user, "email": user + "@integration.invalid", "email_verified": True})
        else:
            self.reply(404)

    def proxy(self):
        request_body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        headers = {key: value for key, value in self.headers.items() if key.lower() not in {"connection", "transfer-encoding", "host"}}
        headers.update({"Host": url.urlsplit(ORIGIN).netloc, "X-Forwarded-Proto": "https"})
        connection = http.client.HTTPConnection("127.0.0.1", 18081, timeout=15)
        try:
            connection.request(self.command, self.path, request_body, headers)
            response = connection.getresponse()
            body = response.read()
            allowed = [(key, value) for key, value in response.getheaders() if key.lower() not in {"connection", "transfer-encoding", "content-length", "server", "date"}]
            self.reply(response.status, body, allowed)
        finally:
            connection.close()


def fetch(page, path, method="GET", form=None, data=None, upload=None, headers=None):
    return page.evaluate("""async args => {
        const options = {method: args.method, headers: {...args.headers}};
        if (args.form) {
            const body = new FormData();
            for (const [key,value] of Object.entries(args.form)) body.append(key, String(value));
            if (args.upload) body.append(args.upload.field, new File([Uint8Array.from(atob(args.upload.bytes), c => c.charCodeAt(0))], 'shared-filename.png', {type:'image/png'}));
            options.body = body;
        } else if (args.data) {
            options.headers['Content-Type']='application/json'; options.body=JSON.stringify(args.data);
        }
        if (args.method !== 'GET') options.headers['X-CSRF-Token']=window.csrfToken || '';
        const result=await fetch(args.path, options), text=await result.text();
        let json=null; try { json=JSON.parse(text); } catch (_) {}
        return {status:result.status, text, json, cache:result.headers.get('cache-control')};
    }""", {"path": APP + path, "method": method, "form": form, "data": data, "upload": upload, "headers": headers or {}})


def inspect_db(fixture, statement, args=()):
    with sqlite3.connect("file:" + (fixture.path / "db/wallos.db").as_posix() + "?mode=ro", uri=True) as connection:
        connection.row_factory = sqlite3.Row
        return [dict(row) for row in connection.execute(statement, args)]


def browser_acceptance(fixture, executable, spki):
    fixture.step = "browser-launch"
    with sync_playwright() as playwright:
        options = {"headless": True, "args": ["--no-proxy-server", "--ignore-certificate-errors-spki-list=" + spki]}
        if executable:
            options["executable_path"] = executable
        browser = playwright.chromium.launch(**options)
        try:
            contexts = [browser.new_context() for _ in USERS]
            pages = [context.new_page() for context in contexts]
            anonymous = browser.new_context()
            anonymous_page = anonymous.new_page()
            fixture.step = 'anonymous-page-load'
            anonymous_page.goto(ORIGIN + '/auth/', wait_until='domcontentloaded')
            fixture.check('invalid-upload-path-never-static-anonymous', fetch(anonymous_page, 'images/uploads/logos/private%20fallback.png')['status'] == 404)
            fixture.check('encoded-tab-path-denied-anonymous', fetch(anonymous_page, 'images/uploads/logos/invalid%09name.png')['status'] == 404)
            errors = []
            for page, user in zip(pages, USERS):
                page.on("pageerror", lambda _: errors.append("pageerror"))
                fixture.step = "oidc-deep-link-" + user
                page.goto(APP + "profile.php?acceptance=deep", wait_until="domcontentloaded")
                page.get_by_role("link", name=user + " (test only)", exact=True).click()
                page.wait_for_url(APP + "profile.php?acceptance=deep")
                page.wait_for_selector("#user")
                fixture.check("oidc-deep-link-" + user, page.locator("#user").inner_text() == user)
            users = inspect_db(fixture, "SELECT u.id,u.username,u.main_currency,h.subject,h.issuer FROM user u JOIN homelab_identity h ON h.user_id=u.id ORDER BY u.id")
            fixture.check("stable-subjects-and-ordinary-accounts", len(users) == 2 and all(row["id"] > 1 and row["issuer"] == ISSUER and row["subject"] == "test-sub-" + row["username"] for row in users))
            fixture.check("reserved-admin-has-no-member-identity", inspect_db(fixture, "SELECT COUNT(*) AS n FROM homelab_identity WHERE user_id=1")[0]["n"] == 0)
            fixture.check("signed-oidc-pkce-exchanged", fixture.exchanges == 2)
            for context in contexts:
                app_cookies = [cookie for cookie in context.cookies() if cookie["name"] == "wallos_session"]
                fixture.check("session-cookie-prefix-secure-" + str(len(fixture.checks)), len(app_cookies) == 1 and app_cookies[0]["path"] == "/apps/wallos/" and app_cookies[0]["secure"] and app_cookies[0]["httpOnly"] and app_cookies[0]["sameSite"] == "Lax")
            a, b = pages
            fixture.check('invalid-upload-path-never-static-authenticated', fetch(b, 'images/uploads/logos/private%20fallback.png')['status'] == 404)
            fixture.check('encoded-tab-path-denied-authenticated', fetch(b, 'images/uploads/logos/invalid%09name.png')['status'] == 404)
            for target in ["admin.php", "endpoints/admin/deleteuser.php", "endpoints/db/backup.php", "api/subscriptions/get_subscriptions.php", "endpoints/user/regenerateapikey.php", "endpoints/subscription/exportcalendar.php"]:
                fixture.check("server-denied-" + target, fetch(a, target)["status"] == 403)
            fixture.check("password-login-post-denied", fetch(a, "login.php", "POST", form={"username": "zhuqing", "password": "fixture-unused"})["status"] == 403)
            fixture.check("password-change-post-denied", fetch(a, "endpoints/user/save_user.php", "POST", form={"password": "fixture-unused"})["status"] == 403)
            fixture.check("zero-string-password-change-denied", fetch(a, "endpoints/user/save_user.php", "POST", form={"password": "0"})["status"] == 403)
            memberships = {}
            for row in users:
                owner = row["id"]
                memberships[row["username"]] = {"currency_id": row["main_currency"], "category_id": inspect_db(fixture, "SELECT id FROM categories WHERE user_id=? LIMIT 1", (owner,))[0]["id"], "payment_method_id": inspect_db(fixture, "SELECT id FROM payment_methods WHERE user_id=? LIMIT 1", (owner,))[0]["id"], "payer_user_id": inspect_db(fixture, "SELECT id FROM household WHERE user_id=? LIMIT 1", (owner,))[0]["id"]}
            png = base64.b64encode((ROOT / "images/icon/favicon-16x16.png").read_bytes()).decode()
            forms, subscriptions, avatars = {}, {}, {}
            for page, user in zip(pages, USERS):
                form = {"name": "fixture-private-" + user, "price": "5.25", "cycle": "3", "frequency": "1", "next_payment": "2030-01-01", "start_date": "2026-01-01", "notes": "fixture-only-" + user, "url": "", "logo-url": "", "notify_days_before": "1", "replacement_subscription_id": "0", "auto_renew": "1", **memberships[user]}
                forms[user] = form
                created = fetch(page, "endpoints/subscription/add.php", "POST", form=form, upload={"field": "logo", "bytes": png})
                fixture.check("own-create-and-upload-" + user, created["status"] == 200 and (created["json"] or {}).get("status") == "Success")
                subscriptions[user] = inspect_db(fixture, "SELECT id,logo FROM subscriptions WHERE name=?", (form["name"],))[0]
                own = fetch(page, "endpoints/subscription/get.php?id=" + str(subscriptions[user]["id"]))
                fixture.check("own-read-" + user, (own["json"] or {}).get("name") == form["name"])
                logo = fetch(page, "images/uploads/logos/" + subscriptions[user]["logo"])
                fixture.check("own-private-logo-no-store-" + user, logo["status"] == 200 and "no-store" in (logo["cache"] or ""))
                changed = fetch(page, "endpoints/subscription/add.php", "POST", form={**form, "id": subscriptions[user]["id"], "price": "7.50"})
                fixture.check("own-edit-" + user, changed["status"] == 200 and (changed["json"] or {}).get("status") == "Success")
                profile = {"firstname": user, "lastname": "", "email": user + "@integration.invalid", "avatar": "images/avatars/0.svg", "main_currency": memberships[user]["currency_id"], "language": "zh_cn"}
                avatar = fetch(page, "endpoints/user/save_user.php", "POST", form=profile, upload={"field": "profile_pic", "bytes": png})
                fixture.check("own-avatar-upload-" + user, avatar["status"] == 200 and (avatar["json"] or {}).get("success") is True)
                avatars[user] = inspect_db(fixture, "SELECT avatar FROM user WHERE username=?", (user,))[0]["avatar"]
                exported = fetch(page, "endpoints/subscriptions/export.php")
                other = USERS[1] if user == USERS[0] else USERS[0]
                fixture.check("own-export-private-" + user, form["name"] in exported["text"] and "fixture-private-" + other not in exported["text"])
            fixture.check("same-name-upload-files-cannot-collide", subscriptions[USERS[0]]["logo"] != subscriptions[USERS[1]]["logo"] and avatars[USERS[0]] != avatars[USERS[1]])
            other = subscriptions[USERS[0]]
            foreign = fetch(b, "endpoints/subscription/get.php?id=" + str(other["id"]))
            fixture.check("foreign-read-does-not-disclose", "fixture-private-zhuqing" not in foreign["text"] and other["logo"] not in foreign["text"])
            fixture.check("foreign-edit-rejected-before-upload", fetch(b, "endpoints/subscription/add.php", "POST", form={**forms[USERS[1]], "id": other["id"]}, upload={"field": "logo", "bytes": png})["status"] == 403)
            fetch(b, "endpoints/subscription/delete.php", "POST", data={"id": other["id"]})
            fixture.check("foreign-delete-does-not-change-owner-data", inspect_db(fixture, "SELECT name,price FROM subscriptions WHERE id=?", (other["id"],)) == [{"name": "fixture-private-zhuqing", "price": 7.5}])
            for kind in ["currency_id", "category_id", "payer_user_id", "payment_method_id"]:
                invalid = {**forms[USERS[1]], kind: memberships[USERS[0]][kind]}
                fixture.check("foreign-association-rejected-" + kind, fetch(b, "endpoints/subscription/add.php", "POST", form=invalid)["status"] == 403)
            fixture.check("foreign-logo-hidden", fetch(b, "images/uploads/logos/" + other["logo"])["status"] == 404)
            fixture.check("foreign-avatar-hidden", fetch(b, avatars[USERS[0]])["status"] == 404)
            forged_profile = {"firstname": "yaojia", "lastname": "", "email": "yaojia@integration.invalid", "avatar": avatars[USERS[0]], "main_currency": memberships[USERS[1]]["currency_id"], "language": "zh_cn"}
            fixture.check("foreign-avatar-selection-rejected", fetch(b, "endpoints/user/save_user.php", "POST", form=forged_profile)["status"] == 403)
            fixture.check("private-handler-query-cannot-replace-captured-file", fetch(b, "images/uploads/logos/" + other["logo"] + "?file=" + subscriptions[USERS[1]]["logo"])["status"] == 404)
            fixture.check("private-path-traversal-denied", fetch(b, "private_file.php?file=../db/wallos.db")["status"] == 404)
            fixture.step = "public-only-browser-cache"
            a.evaluate("async () => { await navigator.serviceWorker.ready; await caches.open('notes-test-cache').then(c => c.put('/apps/notes/test.css',new Response('public test'))); }")
            a.reload(wait_until="domcontentloaded")
            a.evaluate("async () => { await fetch('/apps/wallos/styles/styles.css'); }")
            entries = a.evaluate("async () => { const out={}; for (const name of await caches.keys()) out[name]=(await (await caches.open(name)).keys()).map(r=>r.url); return out; }")
            urls = [item for name, values in entries.items() if name.startswith("homelab-wallos-public-") for item in values]
            fixture.check("browser-cache-contains-only-public-assets", bool(urls) and all(item.startswith(APP) and ".php" not in item and "/uploads/" not in item for item in urls))
            fixture.check("other-app-cache-preserved", "notes-test-cache" in entries)
            contexts[0].set_offline(True)
            try:
                offline = a.evaluate("async () => { let privateBlocked=false; try { await fetch('/apps/wallos/profile.php'); } catch (_) { privateBlocked=true; } const asset=await fetch('/apps/wallos/styles/styles.css'); return {privateBlocked, asset:asset.status}; }")
                fixture.check("no-offline-private-pages", offline == {"privateBlocked": True, "asset": 200})
            finally:
                contexts[0].set_offline(False)
            fixture.step = "website-identity-change"
            a.goto(ORIGIN + "/auth/select?" + url.urlencode({"user": USERS[1], "rd": ORIGIN + "/"}), wait_until="domcontentloaded")
            fixture.check("website-switch-invalidates-old-app-session", fetch(a, "endpoints/subscriptions/export.php")["status"] == 401)
            a.goto(APP + "profile.php?acceptance=switched", wait_until="domcontentloaded")
            a.wait_for_url(APP + "profile.php?acceptance=switched")
            a.wait_for_selector("#user")
            fixture.check("same-browser-switch-is-new-identity", a.locator("#user").inner_text() == USERS[1])
            fixture.check("old-account-upload-unavailable-after-switch", fetch(a, "images/uploads/logos/" + other["logo"])["status"] == 404)
            a.goto(APP + "logout.php", wait_until="domcontentloaded")
            fixture.check("application-logout-clears-app-session", fetch(a, "endpoints/subscriptions/export.php")["status"] == 401)
            fixture.check("application-logout-keeps-website-session", any(cookie["name"] == "site_session" for cookie in contexts[0].cookies()))
            a.goto(ORIGIN + "/test/logout", wait_until="domcontentloaded")
            fixture.check("website-logout-denies-private-upload", fetch(a, "images/uploads/logos/" + subscriptions[USERS[1]]["logo"])["status"] == 401)
            fixture.check("website-logout-denies-api-even-with-spoofed-user", fetch(a, "endpoints/subscriptions/export.php", headers={"Remote-User": "yaojia", "X-Forwarded-User": "yaojia"})["status"] == 401)
            fixture.check("no-browser-page-errors", not errors)
        finally:
            browser.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--result-dir", default=str(ROOT / "test-results/integration"))
    parser.add_argument("--browser-executable")
    parser.add_argument("--docker-context", default="desktop-linux")
    args = parser.parse_args()
    result_dir = Path(args.result_dir).resolve()
    if not result_dir.is_relative_to((ROOT / "test-results").resolve()):
        parser.error("Results must remain within this repository's test-results directory")
    result_dir.mkdir(parents=True, exist_ok=True)
    fixture_path = result_dir / ("fixture-" + secrets.token_hex(5))
    fixture_path.mkdir()
    fixture = Fixture(fixture_path)
    name = "wallos-integration-" + secrets.token_hex(5)
    docker_prefix = ["docker", "--context", args.docker_context]
    servers, container_started = [], False
    summary = {"image": args.image, "status": "failed", "production_access": False, "test_data_only": True, "tls": "ephemeral CA for PHP; exact leaf SPKI for Chromium", "checks": fixture.checks}

    def docker(*arguments, check=True):
        result = subprocess.run([*docker_prefix, *arguments], capture_output=True, text=True, timeout=60)
        if check and result.returncode:
            raise RuntimeError("Docker command failed")
        return result

    try:
        for port in [18081, 18443, 19092, 19443]:
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", port))
        docker("image", "inspect", args.image, "--format", "{{.Id}}")
        (fixture_path / "db").mkdir()
        (fixture_path / "uploads").mkdir()
        (fixture_path / 'uploads/private fallback.png').write_bytes((ROOT / 'images/icon/favicon-16x16.png').read_bytes())
        (fixture_path / "client.secret").write_text(fixture.secret, encoding="utf-8")
        spki = fixture.certificate()
        (fixture_path / "authz.php").write_text("""<?php
$h=[];$c=curl_init('http://host.docker.internal:19092/api/authz/auth-request');
curl_setopt_array($c,[CURLOPT_RETURNTRANSFER=>true,CURLOPT_TIMEOUT=>5,CURLOPT_HTTPHEADER=>['Cookie: '.($_SERVER['HTTP_COOKIE']??'')],CURLOPT_HEADERFUNCTION=>function($c,$line)use(&$h){if(preg_match('/^(Remote-User|Remote-Groups):/i',$line))$h[]=trim($line);return strlen($line);}]);
$r=curl_exec($c);http_response_code($r===false?503:curl_getinfo($c,CURLINFO_RESPONSE_CODE));foreach($h as $line)header($line);curl_close($c);
""", encoding="utf-8")
        # libcurl resolves *.localhost to its own loopback even when /etc/hosts
        # maps it elsewhere. This test-only byte bridge preserves end-to-end TLS
        # and the exact issuer; no resolver override enters production code.
        (fixture_path / 'provider-bridge.php').write_text("""<?php
$server=stream_socket_server('tcp://127.0.0.1:19443');
while($client=@stream_socket_accept($server,-1)) {
    $upstream=@stream_socket_client('tcp://host.docker.internal:19443',$errno,$error,5);
    if(!$upstream){fclose($client);continue;}
    stream_set_blocking($client,false);stream_set_blocking($upstream,false);
    while(!feof($client)&&!feof($upstream)) {
        $read=[$client,$upstream];$write=null;$except=null;
        if(!stream_select($read,$write,$except,10))break;
        foreach($read as $source) {
            $bytes=fread($source,65536);if($bytes==='')break 2;
            $target=$source===$client?$upstream:$client;
            $offset=0;while($offset<strlen($bytes)){$n=fwrite($target,substr($bytes,$offset));if(!$n)break 3;$offset+=$n;}
        }
    }
    fclose($client);fclose($upstream);
}
""", encoding='utf-8')
        for port in [18443, 19092, 19443]:
            server = http.server.ThreadingHTTPServer(("0.0.0.0", port), Handler)
            server.daemon_threads = True
            server.fixture = fixture
            if port != 19092:
                tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                tls.load_cert_chain(fixture_path / "server.pem", fixture_path / "server.key")
                server.socket = tls.wrap_socket(server.socket, server_side=True)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            servers.append(server)
        fixture.step = "candidate-start"
        environment = {"WALLOS_BIND": "0.0.0.0", "WALLOS_PORT": "18081", "HOMELAB_ENABLED": "1", "HOMELAB_PUBLIC_URL": APP.rstrip("/"), "HOMELAB_ALLOWED_USERS": ",".join(USERS), "HOMELAB_AUTHZ_URL": "http://127.0.0.1:19092/api/authz/auth-request", "HOMELAB_OIDC_ISSUER": ISSUER, "HOMELAB_OIDC_CLIENT_ID": "wallos-test", "HOMELAB_OIDC_CLIENT_SECRET_FILE": "/run/homelab-test/client.secret", "HOMELAB_OIDC_CA_FILE": "/run/homelab-test/ca.pem", "HTTP_PROXY": "", "HTTPS_PROXY": "", "ALL_PROXY": "", "http_proxy": "", "https_proxy": "", "all_proxy": "", "NO_PROXY": "provider.test,localhost,127.0.0.1,host.docker.internal"}
        command = ["run", "-d", "--pull=never", "--name", name, "--label", "homelab.test=wallos-integration", "--memory", "384m", "--cpus", "0.5", "--pids-limit", "64", "--security-opt", "no-new-privileges:true", "--add-host", "provider.localhost:host-gateway", "-p", "127.0.0.1:18081:18081", "--mount", "type=bind,source=" + str(fixture_path / "db") + ",target=/var/www/html/db", "--mount", "type=bind,source=" + str(fixture_path / "uploads") + ",target=/var/www/html/images/uploads/logos", "--mount", "type=bind,source=" + str(fixture_path) + ",target=/run/homelab-test,readonly"]
        for key, value in environment.items():
            command.extend(["-e", key + "=" + value])
        docker(*command, args.image)
        container_started = True
        fixture.check('invalid-filename-regression-file-exists-and-readable', docker('exec', name, 'test', '-r', '/var/www/html/images/uploads/logos/private fallback.png', check=False).returncode == 0)
        docker("exec", "-d", name, "php", "-S", "127.0.0.1:19092", "/run/homelab-test/authz.php")
        docker('exec', '-d', name, 'php', '/run/homelab-test/provider-bridge.php')
        for attempt in range(45):
            try:
                connection = http.client.HTTPConnection("127.0.0.1", 18081, timeout=1)
                connection.request("GET", "/apps/wallos/health.php")
                healthy = connection.getresponse().status == 200
                connection.close()
                if healthy:
                    break
            except OSError:
                pass
            time.sleep(1)
        else:
            raise RuntimeError("Candidate health unavailable")
        browser_acceptance(fixture, args.browser_executable, spki)
        summary.update(status="passed", oidc_exchanges=fixture.exchanges)
    except Exception as error:
        stack = traceback.extract_tb(error.__traceback__)
        own_stack = [frame for frame in stack if Path(frame.filename).name == Path(__file__).name]
        summary.update(failed_step=fixture.step, error_type=type(error).__name__,
                       failure_line=own_stack[-1].lineno if own_stack else None,
                       network_error=(re.search(r'net::[A-Z_]+', str(error)).group(0) if re.search(r'net::[A-Z_]+', str(error)) else None),
                       os_errno=getattr(error, 'errno', None),
                       network_events=fixture.network[-40:])
    finally:
        cleanup_ok = True
        if container_started:
            label = docker("inspect", name, "--format", '{{index .Config.Labels "homelab.test"}}', check=False)
            if label.returncode == 0 and label.stdout.strip() == "wallos-integration":
                cleanup_ok = docker("rm", "-f", name, check=False).returncode == 0
            else:
                cleanup_ok = False
        for server in servers:
            server.shutdown()
            server.server_close()
        if cleanup_ok and fixture_path.is_relative_to(result_dir) and fixture_path.name.startswith("fixture-"):
            shutil.rmtree(fixture_path)
        summary["fixture_cleanup_complete"] = cleanup_ok and not fixture_path.exists()
        summary["completed_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
        (result_dir / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"status": summary["status"], "checks_passed": len(fixture.checks), "failed_step": summary.get("failed_step"), "error_type": summary.get("error_type"), "fixture_cleanup_complete": summary["fixture_cleanup_complete"]}))
    return 0 if summary["status"] == "passed" and summary["fixture_cleanup_complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
