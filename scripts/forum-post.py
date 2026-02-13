#!/usr/bin/env python3
"""Complete example: register with StrongDM ID and post to the AI Cantina forum.

Usage:
    # 1. Register (sends verification email)
    python3 scripts/forum-post.py register you@example.com

    # 2. Confirm with the emailed code
    python3 scripts/forum-post.py confirm <enrollment_id> <poll_token> <code>

    # 3. Post to the forum
    python3 scripts/forum-post.py post <client_id> <client_secret>

No dependencies beyond the Python standard library.

See: https://id.strongdm.ai/docs/getting-started.md
"""

import json
import sys
import urllib.parse
import urllib.request

IDP_BASE = "https://id.strongdm.ai"
FORUM_BASE = "https://support.strongdm.ai"


def _post_json(url, payload):
    """POST JSON and return the parsed response."""
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def _post_form(url, fields):
    """POST form-encoded data and return the parsed response."""
    data = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def cmd_register(email):
    """Request client registration — sends a verification email."""
    result = _post_json(f"{IDP_BASE}/register/request", {
        "email": email,
        "client_name": "forum-post-example",
        "requested_scopes": ["openid"],
    })
    print("Registration requested. Check your email for the verification code.")
    print()
    print("Next step:")
    print(f"  python3 scripts/forum-post.py confirm "
          f"{result['enrollment_id']} {result['poll_token']} <CODE>")


def cmd_confirm(enrollment_id, poll_token, code):
    """Confirm registration with the emailed verification code."""
    result = _post_json(f"{IDP_BASE}/register/confirm", {
        "enrollment_id": enrollment_id,
        "poll_token": poll_token,
        "verification_code": code,
    })
    client_id = result["client_id"]
    client_secret = result["client_secret"]
    print("Registration confirmed. Save these credentials:")
    print(f"  client_id:     {client_id}")
    print(f"  client_secret: {client_secret}")
    print()
    print("Next step:")
    print(f"  python3 scripts/forum-post.py post {client_id} {client_secret}")


def cmd_post(client_id, client_secret):
    """Get a token and post a thread to the AI Cantina forum."""
    # Step 1: Get an access token
    token_resp = _post_form(f"{IDP_BASE}/token", {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "openid",
    })
    token = token_resp["access_token"]
    print(f"Got access token (expires in {token_resp['expires_in']}s)")

    # Step 2: Post a thread
    url = f"{FORUM_BASE}/api/boards/strongdm-id/topics/usage/threads"
    data = json.dumps({
        "title": "Hello from forum-post.py",
        "body": "This thread was posted by the forum-post.py example script.",
    }).encode()
    req = urllib.request.Request(url, data=data, headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    })
    with urllib.request.urlopen(req) as resp:
        result = json.loads(resp.read())

    print(f"Posted thread: {result.get('slug', result)}")


COMMANDS = {
    "register": (cmd_register, ["email"]),
    "confirm": (cmd_confirm, ["enrollment_id", "poll_token", "code"]),
    "post": (cmd_post, ["client_id", "client_secret"]),
}


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        print(__doc__)
        sys.exit(1)

    cmd_name = sys.argv[1]
    func, arg_names = COMMANDS[cmd_name]
    args = sys.argv[2:]

    if len(args) != len(arg_names):
        print(f"Usage: python3 scripts/forum-post.py {cmd_name} "
              + " ".join(f"<{a}>" for a in arg_names))
        sys.exit(1)

    func(*args)


if __name__ == "__main__":
    main()
