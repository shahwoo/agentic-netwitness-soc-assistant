"""
NetWitness Connection Test
==========================
Run this from your project folder:

    uv run python test_nw.py

Or if you want to override the .env values temporarily:

    uv run python test_nw.py --host https://192.168.20.11 --user admin --pass NetWitness456$
"""

import sys
import base64
import argparse
import textwrap
from pathlib import Path

# ── Try to load credentials from .env ─────────────────────────
def load_env_creds():
    env_file = Path(__file__).parent / ".env"
    host = username = password = ""
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line.startswith("NW_HOST="):
                host = line.split("=", 1)[1].strip().strip("'\"").strip()
            elif line.startswith("NW_USERNAME="):
                username = line.split("=", 1)[1].strip().strip("'\"").strip()
            elif line.startswith("NW_PASSWORD="):
                raw = line.split("=", 1)[1].strip().strip("'\"").strip()
                try:
                    password = base64.b64decode(raw.encode()).decode("utf-8")
                except Exception:
                    password = raw  # not base64, use as-is
    return host, username, password


def banner(text):
    print(f"\n{'─'*60}")
    print(f"  {text}")
    print(f"{'─'*60}")


def ok(msg):  print(f"  ✅  {msg}")
def fail(msg): print(f"  ❌  {msg}")
def info(msg): print(f"  ℹ️   {msg}")


def run_tests(host: str, username: str, password: str):
    try:
        import requests
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except ImportError:
        print("ERROR: 'requests' not installed. Run: uv add requests")
        sys.exit(1)

    host = host.rstrip("/")

    # ── TEST 1: Basic reachability ────────────────────────────
    banner("TEST 1 — Can we reach the host?")
    try:
        r = requests.get(host, timeout=8, verify=False)
        ok(f"Host reachable — HTTP {r.status_code}")
    except requests.exceptions.ConnectionError as e:
        fail(f"Cannot connect to {host}")
        fail(f"Detail: {str(e)[:120]}")
        fail("Check: Is GP VPN running? Is the host correct?")
        print("\n⛔  Stopping — no point testing further without a reachable host.")
        return
    except requests.exceptions.Timeout:
        fail(f"Timed out reaching {host}")
        fail("Check: Is GP VPN running?")
        return
    except Exception as e:
        fail(f"Unexpected error: {e}")
        return

    # ── TEST 2: Auth endpoint exists ──────────────────────────
    banner("TEST 2 — Does the auth endpoint respond?")
    auth_url = f"{host}/rest/api/auth/userpass"
    info(f"POST {auth_url}")
    try:
        r = requests.post(
            auth_url,
            data={"username": "probe", "password": "probe"},
            headers={
                "Content-Type": "application/x-www-form-urlencoded; charset=ISO-8859-1",
                "Accept": "application/json;charset=UTF-8",
            },
            timeout=10, verify=False,
        )
        if r.status_code in (401, 403, 400):
            ok(f"Auth endpoint exists — HTTP {r.status_code} (expected with probe creds)")
        elif r.status_code == 200:
            ok(f"Auth endpoint returned 200 even with probe creds (no-auth mode?)")
        elif r.status_code == 404:
            fail(f"HTTP 404 — auth endpoint not found at this path")
            fail("The NW version may use a different URL structure")
        else:
            fail(f"Unexpected HTTP {r.status_code}: {r.text[:150]}")
    except Exception as e:
        fail(f"Auth endpoint error: {e}")
        return

    # ── TEST 3: Login with real credentials ───────────────────
    banner("TEST 3 — Login with your credentials")
    info(f"Username: {username}")
    info(f"Password: {'*' * len(password)} ({len(password)} chars)")
    token = ""
    refresh_token = ""
    try:
        r = requests.post(
            auth_url,
            data={"username": username, "password": password},
            headers={
                "Content-Type": "application/x-www-form-urlencoded; charset=ISO-8859-1",
                "Accept": "application/json;charset=UTF-8",
            },
            timeout=10, verify=False,
        )
        if r.status_code == 200:
            data = r.json()
            token = data.get("accessToken") or data.get("access_token") or ""
            refresh_token = data.get("refreshToken") or ""
            if token:
                ok(f"Login successful!")
                ok(f"Token prefix: {token[:30]}…")
                ok(f"Roles: {data.get('roles', '?')}")
            else:
                fail(f"Login returned 200 but no token — response: {str(data)[:200]}")
                return
        elif r.status_code == 401:
            fail("HTTP 401 — Wrong username or password")
            fail(f"Response: {r.text[:150]}")
            return
        elif r.status_code == 400:
            fail(f"HTTP 400 — Bad request: {r.text[:200]}")
            return
        else:
            fail(f"HTTP {r.status_code}: {r.text[:150]}")
            return
    except Exception as e:
        fail(f"Login error: {e}")
        return

    # ── TEST 4: Fetch incidents ───────────────────────────────
    banner("TEST 4 — Fetch incidents with token")
    endpoints = [
        "/rest/api/incidents",
        "/rest/api/respond/incidents",
        "/rest/api/v1/incidents",
        "/rest/api/v2/incidents",
    ]
    auth_styles = {
        "NetWitness-Token": {"NetWitness-Token": token},
        "Bearer":           {"Authorization": f"Bearer {token}"},
    }
    # Try with and without a since parameter (some NW versions require it)
    param_variants = [
        {"pageSize": 1, "pageNumber": 0, "since": "2020-01-01T00:00:00.000Z"},
        {"pageSize": 1, "pageNumber": 0},
    ]

    working_ep = None
    working_style = None

    for ep in endpoints:
        for style_name, auth_header in auth_styles.items():
            for params in param_variants:
                url = f"{host}{ep}"
                headers = {**auth_header, "Accept": "application/json;charset=UTF-8"}
                try:
                    r = requests.get(
                        url,
                        headers=headers,
                        params=params,
                        timeout=10, verify=False,
                    )
                    ct = r.headers.get("Content-Type", "")
                    is_json = "json" in ct or r.text.strip().startswith(("{", "["))
                    param_label = "with since" if "since" in params else "no since"

                    if r.status_code == 200 and is_json:
                        data = r.json()
                        total = data.get("totalItems", "?")
                        ok(f"HTTP 200 ✅  {ep}  [{style_name}] [{param_label}]  —  {total} incident(s)")
                        working_ep = ep
                        working_style = style_name
                        break  # found it — skip other param variants
                    elif r.status_code == 403:
                        fail(f"HTTP 403  {ep}  [{style_name}] [{param_label}]  — permission denied")
                    elif r.status_code == 401:
                        fail(f"HTTP 401  {ep}  [{style_name}] [{param_label}]  — token rejected")
                    elif r.status_code == 404:
                        info(f"HTTP 404  {ep}  [{style_name}]  — not found")
                        break  # 404 won't change with different params
                    elif r.status_code == 400:
                        fail(f"HTTP 400  {ep}  [{style_name}] [{param_label}]")
                        # Print full error so we can see what NW says
                        try:
                            err = r.json()
                            for e in err.get("errors", []):
                                fail(f"  → {e.get('message','?')}  field={e.get('field','')}")
                        except Exception:
                            fail(f"  → Raw: {r.text[:200]}")
                    else:
                        info(f"HTTP {r.status_code}  {ep}  [{style_name}] [{param_label}]")
                except Exception as e:
                    fail(f"Error on {ep} [{style_name}]: {str(e)[:80]}")
            if working_ep:
                break
        if working_ep:
            break

    # ── SUMMARY ───────────────────────────────────────────────
    banner("SUMMARY")
    if working_ep:
        ok(f"Working endpoint: {working_ep}")
        ok(f"Working auth style: {working_style}")
        print()
        print("  ➡️  Set these in the app:")
        print(f"     Incidents path:  {working_ep}")
        print(f"     Auth style:      {working_style}")
        print()
        print("  Or paste this into the sidebar → ⚙️ Manual Endpoint Config")
    else:
        fail("No working endpoint found.")
        fail("Most likely causes:")
        fail("  • Account lacks 'integration-server.api.access' permission")
        fail("  • NW uses a non-standard API path — try Endpoint Scanner in the app")
        fail("  • Token expired between Test 3 and Test 4 (unlikely but possible)")
        print()
        print("  ➡️  In NetWitness: Admin → Security → Roles → Administrators")
        print("     → Edit → ensure 'integration-server.api.access' is checked")

    print(f"\n{'─'*60}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NetWitness connection test")
    parser.add_argument("--host",  default="", help="https://192.168.x.x")
    parser.add_argument("--user",  default="", help="NW username")
    parser.add_argument("--pass",  default="", dest="password", help="NW password")
    args = parser.parse_args()

    env_host, env_user, env_pass = load_env_creds()

    host     = args.host     or env_host
    username = args.user     or env_user
    password = args.password or env_pass

    print("\n" + "═"*60)
    print("  NetWitness Connection Test")
    print("═"*60)
    print(f"  Host:     {host or '(not set)'}")
    print(f"  Username: {username or '(not set)'}")
    print(f"  Password: {'*' * len(password) or '(not set)'}")
    print(f"  Source:   {'CLI args' if args.host else '.env file'}")

    if not host or not username or not password:
        print("\n❌  Missing credentials.")
        print("   Option 1 — use .env file (should auto-load)")
        print("   Option 2 — run with flags:")
        print('   uv run python test_nw.py --host https://192.168.20.11 --user admin --pass "YourPassword"')
        sys.exit(1)

    run_tests(host, username, password)