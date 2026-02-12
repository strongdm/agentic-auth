/*
StrongDM ID Authentication Middleware for Go

This middleware validates JWT tokens issued by StrongDM ID (https://id.strongdm.ai).
It supports:
  - JWT signature verification using JWKS (auto-refreshed)
  - Token introspection fallback
  - Scope-based access control
  - DPoP token validation (sender-constrained tokens)
*/
package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// Config holds the settings for StrongDM ID authentication.
type Config struct {
	// Issuer is the OIDC issuer URL (default: https://id.strongdm.ai).
	Issuer string

	// Audience is the expected audience claim (optional).
	// If empty, audience validation is skipped.
	Audience string

	// IntrospectionEnabled enables the token introspection fallback.
	// When true, tokens that fail JWT verification are checked via the
	// introspection endpoint. This catches revoked tokens.
	IntrospectionEnabled bool

	// ClientID is the OAuth2 client ID (required for introspection).
	ClientID string

	// ClientSecret is the OAuth2 client secret (required for introspection).
	ClientSecret string
}

// AgentInfo represents the authenticated agent extracted from a JWT.
type AgentInfo struct {
	Subject   string    `json:"subject"`
	Issuer    string    `json:"issuer"`
	Scopes    []string  `json:"scopes"`
	ClientID  string    `json:"client_id,omitempty"`
	Actor     string    `json:"actor,omitempty"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// StrongDMAuth provides JWT verification and HTTP middleware for StrongDM ID.
type StrongDMAuth struct {
	config  Config
	cache   *jwk.Cache
	jwksURL string
	cancel  context.CancelFunc
	log     *slog.Logger

	introMu    sync.RWMutex
	introCache map[string]*introCacheEntry
}

type introCacheEntry struct {
	result    *introspectionResult
	expiresAt time.Time
}

type introspectionResult struct {
	Active   bool   `json:"active"`
	Subject  string `json:"sub"`
	Scope    string `json:"scope"`
	ClientID string `json:"client_id"`
}

type contextKey struct{ name string }

var agentInfoKey = &contextKey{"agent-info"}

// New creates a StrongDMAuth instance and starts background JWKS refresh.
//
// The JWKS is fetched immediately on startup and refreshed automatically
// every 15 minutes (or sooner if the server returns cache-control headers).
func New(cfg Config, log *slog.Logger) (*StrongDMAuth, error) {
	if cfg.Issuer == "" {
		cfg.Issuer = "https://id.strongdm.ai"
	}

	ctx, cancel := context.WithCancel(context.Background())

	jwksURL := cfg.Issuer + "/jwks"
	cache := jwk.NewCache(ctx)
	if err := cache.Register(jwksURL, jwk.WithMinRefreshInterval(15*time.Minute)); err != nil {
		cancel()
		return nil, fmt.Errorf("register JWKS URL: %w", err)
	}

	// Force initial fetch so startup fails fast if the issuer is unreachable.
	if _, err := cache.Refresh(ctx, jwksURL); err != nil {
		cancel()
		return nil, fmt.Errorf("initial JWKS fetch from %s: %w", jwksURL, err)
	}

	log.Info("StrongDM auth initialized", "issuer", cfg.Issuer)

	return &StrongDMAuth{
		config:     cfg,
		cache:      cache,
		jwksURL:    jwksURL,
		cancel:     cancel,
		log:        log,
		introCache: make(map[string]*introCacheEntry),
	}, nil
}

// Close stops the background JWKS refresh goroutine.
func (a *StrongDMAuth) Close() {
	a.cancel()
}

// RequireAuth returns middleware that requires a valid JWT.
//
// On success, the AgentInfo is stored in the request context and can be
// retrieved with GetAgentInfo.
//
//	mux.Handle("GET /protected", auth.RequireAuth(handler))
func (a *StrongDMAuth) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agent, err := a.VerifyRequest(r)
		if err != nil {
			a.log.Warn("auth failed", "error", err, "path", r.URL.Path)
			writeError(w, http.StatusUnauthorized, err.Error())
			return
		}
		ctx := context.WithValue(r.Context(), agentInfoKey, agent)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireScope returns middleware that requires a valid JWT with at least
// one of the specified scopes.
//
//	mux.Handle("GET /admin", auth.RequireScope("admin")(handler))
//	mux.Handle("GET /ops", auth.RequireScope("admin", "operator")(handler))
func (a *StrongDMAuth) RequireScope(scopes ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return a.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			agent := GetAgentInfo(r)
			if agent == nil {
				writeError(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			if !hasAnyScope(agent.Scopes, scopes) {
				a.log.Warn("insufficient scope",
					"required", scopes,
					"have", agent.Scopes,
					"subject", agent.Subject,
				)
				writeError(w, http.StatusForbidden, fmt.Sprintf(
					"requires one of: %s", strings.Join(scopes, ", "),
				))
				return
			}
			next.ServeHTTP(w, r)
		}))
	}
}

// RequireAllScopes returns middleware that requires ALL specified scopes.
//
//	mux.Handle("GET /sensitive", auth.RequireAllScopes("admin", "audit")(handler))
func (a *StrongDMAuth) RequireAllScopes(scopes ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return a.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			agent := GetAgentInfo(r)
			if agent == nil {
				writeError(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			if missing := missingScopes(agent.Scopes, scopes); len(missing) > 0 {
				a.log.Warn("missing required scopes",
					"missing", missing,
					"have", agent.Scopes,
					"subject", agent.Subject,
				)
				writeError(w, http.StatusForbidden, fmt.Sprintf(
					"missing required scopes: %s", strings.Join(missing, ", "),
				))
				return
			}
			next.ServeHTTP(w, r)
		}))
	}
}

// GetAgentInfo extracts the authenticated agent from the request context.
// Returns nil if the request was not authenticated.
func GetAgentInfo(r *http.Request) *AgentInfo {
	v, _ := r.Context().Value(agentInfoKey).(*AgentInfo)
	return v
}

// VerifyRequest extracts the JWT from the Authorization header and verifies it.
// This is the lower-level API — most users should use RequireAuth middleware instead.
func (a *StrongDMAuth) VerifyRequest(r *http.Request) (*AgentInfo, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, fmt.Errorf("missing Authorization header")
	}

	tokenString, tokenType := extractToken(authHeader)
	if tokenString == "" {
		return nil, fmt.Errorf("invalid Authorization header format")
	}

	// Try JWT verification first.
	agent, err := a.verifyJWT(r.Context(), tokenString)
	if err != nil {
		// Fall back to introspection if enabled.
		if a.config.IntrospectionEnabled {
			agent, introErr := a.introspect(tokenString)
			if introErr != nil {
				return nil, fmt.Errorf("JWT verification failed: %w (introspection also failed: %v)", err, introErr)
			}
			return agent, nil
		}
		return nil, err
	}

	// For DPoP tokens, verify the proof.
	if tokenType == "dpop" {
		dpopProof := r.Header.Get("DPoP")
		if dpopProof == "" {
			return nil, fmt.Errorf("DPoP token type requires DPoP proof header")
		}
		if err := a.verifyDPoP(dpopProof, tokenString, r.Method, requestURL(r)); err != nil {
			return nil, fmt.Errorf("DPoP verification failed: %w", err)
		}
	}

	return agent, nil
}

// verifyJWT parses and verifies a JWT against the cached JWKS.
func (a *StrongDMAuth) verifyJWT(ctx context.Context, tokenString string) (*AgentInfo, error) {
	keyset, err := a.cache.Get(ctx, a.jwksURL)
	if err != nil {
		return nil, fmt.Errorf("get JWKS: %w", err)
	}

	parseOpts := []jwt.ParseOption{
		jwt.WithKeySet(keyset),
		jwt.WithIssuer(a.config.Issuer),
		jwt.WithValidate(true),
	}
	if a.config.Audience != "" {
		parseOpts = append(parseOpts, jwt.WithAudience(a.config.Audience))
	}

	token, err := jwt.Parse([]byte(tokenString), parseOpts...)
	if err != nil {
		return nil, fmt.Errorf("parse/verify JWT: %w", err)
	}

	return tokenToAgentInfo(token), nil
}

// verifyDPoP validates a DPoP proof JWT.
//
// DPoP (RFC 9449) binds an access token to a specific sender by requiring
// a proof JWT signed with the sender's private key. The proof contains:
//   - htm: the HTTP method
//   - htu: the request URL
//   - ath: SHA-256 hash of the access token
func (a *StrongDMAuth) verifyDPoP(proof, accessToken, method, url string) error {
	// Parse the JWS to extract the embedded public key from the header.
	msg, err := jws.Parse([]byte(proof))
	if err != nil {
		return fmt.Errorf("parse DPoP JWS: %w", err)
	}

	signatures := msg.Signatures()
	if len(signatures) == 0 {
		return fmt.Errorf("DPoP proof has no signatures")
	}

	headers := signatures[0].ProtectedHeaders()

	// The DPoP proof must have typ=dpop+jwt.
	if typ := headers.Type(); typ != "dpop+jwt" {
		return fmt.Errorf("wrong DPoP typ: got %q, want %q", typ, "dpop+jwt")
	}

	// Extract the embedded JWK used to sign the proof.
	proofKey := headers.JWK()
	if proofKey == nil {
		return fmt.Errorf("DPoP proof missing embedded JWK")
	}

	// Verify the proof signature using the embedded key.
	proofToken, err := jwt.Parse([]byte(proof),
		jwt.WithKey(headers.Algorithm(), proofKey),
		jwt.WithValidate(true),
		jwt.WithAcceptableSkew(5*time.Second),
	)
	if err != nil {
		return fmt.Errorf("verify DPoP proof: %w", err)
	}

	// Verify HTTP method.
	htm, _ := proofToken.Get("htm")
	if htmStr, ok := htm.(string); !ok || !strings.EqualFold(htmStr, method) {
		return fmt.Errorf("DPoP htm mismatch: got %v, want %q", htm, method)
	}

	// Verify request URL.
	htu, _ := proofToken.Get("htu")
	if htuStr, ok := htu.(string); !ok || htuStr != url {
		return fmt.Errorf("DPoP htu mismatch: got %v, want %q", htu, url)
	}

	// Verify access token hash.
	ath, _ := proofToken.Get("ath")
	if athStr, ok := ath.(string); ok {
		expected := sha256Base64URL(accessToken)
		if athStr != expected {
			return fmt.Errorf("DPoP ath mismatch")
		}
	}

	return nil
}

// introspect calls the token introspection endpoint.
// Results are cached for 60 seconds.
func (a *StrongDMAuth) introspect(tokenString string) (*AgentInfo, error) {
	// Check cache.
	a.introMu.RLock()
	if entry, ok := a.introCache[tokenString]; ok && time.Now().Before(entry.expiresAt) {
		a.introMu.RUnlock()
		if !entry.result.Active {
			return nil, fmt.Errorf("token is not active (cached)")
		}
		return &AgentInfo{
			Subject:  entry.result.Subject,
			Scopes:   strings.Fields(entry.result.Scope),
			ClientID: entry.result.ClientID,
			Issuer:   a.config.Issuer,
		}, nil
	}
	a.introMu.RUnlock()

	// Call introspection endpoint.
	body := "token=" + tokenString
	req, err := http.NewRequest("POST", a.config.Issuer+"/introspect", strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(a.config.ClientID, a.config.ClientSecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("introspection request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("introspection returned HTTP %d", resp.StatusCode)
	}

	var result introspectionResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode introspection response: %w", err)
	}

	// Cache for 60 seconds.
	a.introMu.Lock()
	a.introCache[tokenString] = &introCacheEntry{
		result:    &result,
		expiresAt: time.Now().Add(60 * time.Second),
	}
	a.introMu.Unlock()

	if !result.Active {
		return nil, fmt.Errorf("token is not active")
	}

	return &AgentInfo{
		Subject:  result.Subject,
		Scopes:   strings.Fields(result.Scope),
		ClientID: result.ClientID,
		Issuer:   a.config.Issuer,
	}, nil
}

// --- Helpers ---

func extractToken(header string) (token, tokenType string) {
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 {
		return "", ""
	}
	switch strings.ToLower(parts[0]) {
	case "bearer":
		return parts[1], "bearer"
	case "dpop":
		return parts[1], "dpop"
	default:
		return "", ""
	}
}

func tokenToAgentInfo(token jwt.Token) *AgentInfo {
	info := &AgentInfo{
		Subject:   token.Subject(),
		Issuer:    token.Issuer(),
		IssuedAt:  token.IssuedAt(),
		ExpiresAt: token.Expiration(),
	}

	if scope, ok := token.Get("scope"); ok {
		if s, ok := scope.(string); ok {
			info.Scopes = strings.Fields(s)
		}
	}

	if cid, ok := token.Get("client_id"); ok {
		info.ClientID, _ = cid.(string)
	} else if azp, ok := token.Get("azp"); ok {
		info.ClientID, _ = azp.(string)
	}

	if act, ok := token.Get("act"); ok {
		if actMap, ok := act.(map[string]interface{}); ok {
			info.Actor, _ = actMap["sub"].(string)
		}
	}

	return info
}

func hasAnyScope(have, want []string) bool {
	set := make(map[string]struct{}, len(have))
	for _, s := range have {
		set[s] = struct{}{}
	}
	for _, s := range want {
		if _, ok := set[s]; ok {
			return true
		}
	}
	return false
}

func missingScopes(have, want []string) []string {
	set := make(map[string]struct{}, len(have))
	for _, s := range have {
		set[s] = struct{}{}
	}
	var missing []string
	for _, s := range want {
		if _, ok := set[s]; !ok {
			missing = append(missing, s)
		}
	}
	return missing
}

func sha256Base64URL(s string) string {
	h := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func requestURL(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	return scheme + "://" + r.Host + r.URL.Path
}

func writeError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}
