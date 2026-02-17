# StrongDM ID: 8 Ways Agents Use Identity

StrongDM ID is an identity service built for the agentic era. While it supports traditional OAuth/OIDC flows, its primary purpose is enabling **agents to authenticate, authorize, and trust other agents**.

## The Shift

**Old model:** Human → Browser → Service
**New model:** Human → Agent → Agent → Agent → Service

Every arrow needs identity and trust. StrongDM ID is the identity layer for those agent-to-agent arrows.

---

## Use Case 1: Agent Proves Identity to Another Agent

**Problem:** Agent A calls Agent B's API. B needs to verify A is legitimate, not a prompt-injected imposter or stolen credential.

**Solution:** OAuth client credentials with DPoP (Demonstrating Proof of Possession). Agent A gets a sender-constrained token that proves "I am Agent A, and this request came from my private key."

**How it works:**
```bash
# Agent A gets a DPoP-bound token
curl -X POST https://id.strongdm.ai/token \
  -H "DPoP: eyJ..." \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d "grant_type=client_credentials"

# Agent A calls Agent B with the bound token
curl -X POST https://agent-b.example.com/api \
  -H "Authorization: DPoP eyJ..." \
  -H "DPoP: eyJ..."  # Proof of possession

# Agent B verifies:
# 1. Token is valid (signature, expiry)
# 2. DPoP proof matches token's jkt claim
# 3. Request method/URI match DPoP claims
```

**Why it matters:** Tokens can't be stolen and replayed. The private key never leaves the agent.

---

## Use Case 2: Prove User Delegation

**Problem:** A human approved "sync my calendar" once. Now the agent needs to prove that delegation to downstream services—without the human present.

**Solution:** Token exchange (RFC 8693) with actor tokens. The agent carries a token that cryptographically proves "User X delegated scope Y to me."

**How it works:**
```bash
# Agent exchanges user's token for a scoped delegation token
curl -X POST https://id.strongdm.ai/token \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=$USER_TOKEN" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
  -d "scope=calendar:read" \
  -d "actor_token=$AGENT_TOKEN" \
  -d "actor_token_type=urn:ietf:params:oauth:token-type:access_token"

# Result: Token with claims showing both user (sub) and agent (act)
{
  "sub": "user@example.com",
  "act": {
    "sub": "cli_calendar_sync_agent"
  },
  "scope": "calendar:read"
}
```

**Why it matters:** Services can verify both WHO delegated AND which agent is acting. Audit trails are complete.

---

## Use Case 3: Constrained Agent Capabilities

**Problem:** The code review agent should see the repo but never push. The deployment agent should deploy but never access secrets directly.

**Solution:** Cedar policies evaluate agent identity + requested action. Scopes are enforced cryptographically in the token, not by trusting agent behavior.

**How it works:**
```bash
# Agent requests specific scopes
curl -X POST https://id.strongdm.ai/token \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d "grant_type=client_credentials" \
  -d "scope=repo:read"  # Can only request what policy allows

# Cedar policy (server-side):
permit(
  principal == Agent::"cli_code_review_agent",
  action in [Action::"repo:read", Action::"pr:comment"],
  resource in Repository::"acme-corp/*"
);

# This agent can NEVER get repo:write, even if it asks
```

**Why it matters:** Defense in depth. Even if an agent is compromised or "jailbroken," it can't exceed its cryptographically-enforced permissions.

---

## Use Case 4: Agent Spawns Agent with Narrowed Permissions

**Problem:** A parent orchestrator agent spawns worker agents. Workers should inherit a subset of the parent's permissions, not escalate.

**Solution:** Token exchange with scope narrowing. Child agents automatically get a subset of parent permissions.

**How it works:**
```bash
# Parent agent has scopes: repo:read, repo:write, deploy:staging
# Parent spawns a worker for read-only analysis

curl -X POST https://id.strongdm.ai/token \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=$PARENT_TOKEN" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
  -d "scope=repo:read"  # Narrowed from parent's permissions

# Worker gets token with ONLY repo:read
# Cannot request repo:write even though parent has it
```

**Why it matters:** Principle of least privilege, enforced automatically. Multi-agent workflows can't accidentally escalate.

---

## Use Case 5: Audit Trail of Agent Actions

**Problem:** Three agents touched a file. Which one introduced the bug? "Some AI did something" isn't acceptable for compliance.

**Solution:** Every agent has a unique, attributable identity. All token issuance, authorization decisions, and API calls are logged with agent identity.

**What's logged:**
```json
{
  "timestamp": "2026-01-29T10:15:00Z",
  "event": "token_issued",
  "client_id": "cli_code_review_agent",
  "sponsor_email": "developer@acme.com",
  "granted_scopes": ["repo:read", "pr:comment"],
  "token_binding": "dpop",
  "dpop_thumbprint": "sha256:abc123..."
}

{
  "timestamp": "2026-01-29T10:15:05Z",
  "event": "authorization_decision",
  "principal": "cli_code_review_agent",
  "action": "pr:comment",
  "resource": "repo:acme/backend/pr/123",
  "decision": "allow",
  "policy_id": "policy_code_review_agents"
}
```

**Why it matters:** Compliance, debugging, and accountability. You can answer "which agent did what, when, with whose permission."

---

## Use Case 6: Agent Accesses Legacy OAuth Services

**Problem:** Your agent needs to call a third-party API that expects standard OAuth tokens. It doesn't know about "agent identity."

**Solution:** StrongDM ID issues standard OAuth 2.0 / OIDC tokens. Legacy services see normal bearer tokens; the agent-native identity is preserved on our side.

**How it works:**
```bash
# Agent gets a standard access token
curl -X POST https://id.strongdm.ai/token \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d "grant_type=client_credentials" \
  -d "scope=api:read"

# Response is standard OAuth
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 3600
}

# Legacy service validates the JWT normally
# StrongDM ID tracks: this token belongs to cli_my_agent
```

**Why it matters:** Agents can integrate with existing infrastructure without requiring those systems to understand agent identity.

---

## Use Case 7: Cross-Vendor Agent Collaboration

**Problem:** Your Claude agent and a partner's GPT agent need to collaborate. Neither vendor should run a proprietary auth system.

**Solution:** StrongDM ID uses open standards (OAuth 2.0, OIDC, SPIFFE). Any compliant agent can participate regardless of vendor.

**Standards supported:**
- **OAuth 2.0** - Token issuance, client credentials, token exchange
- **OIDC** - Discovery, ID tokens, userinfo
- **SPIFFE/SVID** - Workload identity (X.509 and JWT)
- **DPoP** (RFC 9449) - Sender-constrained tokens
- **mTLS** (RFC 8705) - Certificate-bound tokens

**Why it matters:** No vendor lock-in. Agents from different providers can authenticate to each other using standard protocols.

---

## Use Case 8: Organizational Agent Identity

**Problem:** The agent isn't acting for a single user—it represents the company. It should have Acme Corp's identity, governed by Acme's policies.

**Solution:** Multi-realm support. Agents belong to organizational realms with org-level policies and audit trails.

**How it works:**
```bash
# Acme Corp's realm has its own policies
# Agent registered under Acme's realm
curl -X POST https://id.strongdm.ai/register/agent \
  -d '{
    "email": "platform-team@acme.com",
    "agent_name": "acme-deployment-bot",
    "realm": "acme-corp"
  }'

# Token includes realm claim
{
  "sub": "cli_acme_deployment_bot",
  "realm": "acme-corp",
  "scope": "deploy:prod"
}

# Acme's Cedar policies govern what this agent can do
# Other orgs' policies don't apply; Acme's agents are isolated
```

**Why it matters:** Enterprises need agents that represent the organization, not individuals. Governance stays with the org.

---

## What's NOT Production-Ready Yet

Two use cases need more work before we can recommend them:

### Real-Time Revocation Streaming
**Status:** 80% complete. Framework exists (SSF/CAEP), events are created, but delivery to subscribers isn't wired up.

**Current workaround:** Short-lived tokens (5-15 min) + token introspection endpoint.

### Custom Environment Attestation
**Status:** Cloud attestation works (AWS IAM, K8s service accounts, Azure MI, GCP). Custom "prove I'm running in a secure sandbox" needs extension.

**Current workaround:** Run agents in cloud environments that support native attestation.

---

## Quick Reference: Use Case → API

| Use Case | Primary APIs |
|----------|-------------|
| Agent proves identity | `POST /token` with DPoP |
| User delegation | `POST /token` (token exchange) |
| Constrained capabilities | `POST /token` (Cedar evaluates scopes) |
| Agent spawns agent | `POST /token` (token exchange, narrowed scope) |
| Audit trail | Automatic (all endpoints logged) |
| Legacy OAuth access | `POST /token` (standard OAuth response) |
| Cross-vendor collaboration | Standard OIDC discovery, SPIFFE federation |
| Organizational identity | `POST /register/agent` with realm |

---

For working code examples, see the [example implementations](./examples/) in this repository.
