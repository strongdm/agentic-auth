export default function Home() {
  return (
    <main style={{ padding: "2rem", fontFamily: "system-ui, sans-serif" }}>
      <h1>StrongDM ID Next.js Example</h1>
      <p>This API is protected by StrongDM ID authentication.</p>

      <h2>Available Endpoints</h2>
      <ul>
        <li>
          <code>/api/health</code> - Health check (public)
        </li>
        <li>
          <code>/api/protected</code> - Requires authentication
        </li>
        <li>
          <code>/api/agent-info</code> - Shows authenticated agent info
        </li>
        <li>
          <code>/api/admin</code> - Requires pctl:read scope
        </li>
      </ul>

      <h2>Usage</h2>
      <pre
        style={{
          background: "#f5f5f5",
          padding: "1rem",
          borderRadius: "4px",
          overflow: "auto",
        }}
      >
        {`# Get a token from StrongDM ID
TOKEN=$(curl -s -X POST https://id.strongdm.ai/token \\
  -u "$CLIENT_ID:$CLIENT_SECRET" \\
  -d "grant_type=client_credentials" | jq -r '.access_token')

# Call a protected endpoint
curl -H "Authorization: Bearer $TOKEN" http://localhost:3000/api/protected`}
      </pre>
    </main>
  );
}
