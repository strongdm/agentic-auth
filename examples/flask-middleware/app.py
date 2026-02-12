"""
Example Flask application using StrongDM ID authentication.

This demonstrates:
- Basic authentication with require_auth()
- Scope-based access control with require_scope()
- Accessing token claims
- Public endpoints that don't require auth
"""

import os
from flask import Flask, jsonify, g
from strongdm_auth import StrongDMAuth

app = Flask(__name__)

# Initialize StrongDM auth middleware
auth = StrongDMAuth(
    app,
    issuer=os.getenv('STRONGDM_ISSUER', 'https://id.strongdm.ai'),
    audience=os.getenv('STRONGDM_AUDIENCE'),  # Optional: set if you have a specific audience
    introspection_enabled=os.getenv('STRONGDM_INTROSPECTION_ENABLED', '').lower() == 'true',
    client_id=os.getenv('STRONGDM_CLIENT_ID'),
    client_secret=os.getenv('STRONGDM_CLIENT_SECRET'),
)


@app.route('/')
def index():
    """Public endpoint - no authentication required."""
    return jsonify({
        "message": "Welcome to the StrongDM ID Flask example",
        "endpoints": {
            "/": "This page (public)",
            "/protected": "Requires authentication",
            "/agent-info": "Shows info about the authenticated agent",
            "/admin": "Requires admin scope",
        }
    })


@app.route('/protected')
@auth.require_auth()
def protected():
    """Protected endpoint - requires valid authentication."""
    agent = auth.get_current_agent()
    return jsonify({
        "message": "You are authenticated!",
        "subject": agent['subject'],
        "scopes": agent['scopes'],
    })


@app.route('/agent-info')
@auth.require_auth()
def agent_info():
    """Show detailed information about the authenticated agent."""
    claims = g.token_claims
    return jsonify({
        "subject": claims.get('sub'),
        "issuer": claims.get('iss'),
        "scopes": claims.get('scope', '').split(),
        "client_id": claims.get('client_id') or claims.get('azp'),
        "expires_at": claims.get('exp'),
        "issued_at": claims.get('iat'),
        "actor": claims.get('act'),  # Present if token is delegated
    })



@app.route('/admin')
@auth.require_scope('admin')
def admin():
    """Admin-only endpoint."""
    return jsonify({
        "message": "Welcome, admin!",
        "agent": g.token_claims.get('sub'),
    })


@app.route('/health')
def health():
    """Health check endpoint - public."""
    return jsonify({"status": "healthy"})


if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_DEBUG', '').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug)
