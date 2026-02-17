/*
DPoP Client Example — Go (stdlib only, zero external dependencies)

Demonstrates how to:
 1. Generate an EC P-256 key pair
 2. Create a DPoP proof JWT
 3. Request a DPoP-bound access token from StrongDM ID
 4. Make an authenticated API call with a fresh DPoP proof

Run: go run main.go
*/
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func main() {
	issuer := envOr("STRONGDM_ISSUER", "https://id.strongdm.ai")
	clientID := os.Getenv("STRONGDM_CLIENT_ID")
	clientSecret := os.Getenv("STRONGDM_CLIENT_SECRET")

	if clientID == "" || clientSecret == "" {
		fmt.Fprintln(os.Stderr, "Set STRONGDM_CLIENT_ID and STRONGDM_CLIENT_SECRET")
		os.Exit(1)
	}

	// Step 1: Generate a fresh EC P-256 key pair
	fmt.Println("Generating EC P-256 key pair...")
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fatalf("generate key: %v", err)
	}

	thumbprint := jwkThumbprint(&privKey.PublicKey)
	fmt.Printf("JWK thumbprint: %s\n", thumbprint)

	// Step 2: Request a DPoP-bound access token
	tokenURL := issuer + "/token"
	fmt.Printf("\nRequesting DPoP token from %s...\n", tokenURL)

	proof := createDPoPProof(privKey, "POST", tokenURL, "")

	form := url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {"openid"},
	}

	req, _ := http.NewRequest("POST", tokenURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", proof)
	req.SetBasicAuth(clientID, clientSecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fatalf("token request: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	// Handle DPoP nonce requirement
	if resp.StatusCode == 400 {
		var errResp map[string]any
		json.Unmarshal(body, &errResp)
		if errResp["error"] == "use_dpop_nonce" {
			nonce := resp.Header.Get("DPoP-Nonce")
			if nonce != "" {
				fmt.Println("Server requires DPoP nonce, retrying...")
				proof = createDPoPProof(privKey, "POST", tokenURL, "")
				req, _ = http.NewRequest("POST", tokenURL, strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.Header.Set("DPoP", proof)
				req.SetBasicAuth(clientID, clientSecret)
				resp2, err := http.DefaultClient.Do(req)
				if err != nil {
					fatalf("token retry: %v", err)
				}
				defer resp2.Body.Close()
				body, _ = io.ReadAll(resp2.Body)
				resp = resp2
			}
		}
	}

	if resp.StatusCode != 200 {
		fatalf("token error (HTTP %d): %s", resp.StatusCode, body)
	}

	var tokenResp map[string]any
	json.Unmarshal(body, &tokenResp)

	accessToken, _ := tokenResp["access_token"].(string)
	tokenType, _ := tokenResp["token_type"].(string)
	expiresIn, _ := tokenResp["expires_in"].(float64)

	fmt.Printf("Token type: %s\n", tokenType)
	fmt.Printf("Expires in: %.0fs\n", expiresIn)
	if len(accessToken) > 40 {
		fmt.Printf("Token (first 40 chars): %s...\n", accessToken[:40])
	}

	// Step 3: Verify cnf.jkt matches our key
	claims := decodeJWTPayload(accessToken)
	if cnf, ok := claims["cnf"].(map[string]any); ok {
		jkt, _ := cnf["jkt"].(string)
		fmt.Printf("\nToken cnf.jkt: %s\n", jkt)
		fmt.Printf("Our thumbprint: %s\n", thumbprint)
		if jkt == thumbprint {
			fmt.Println("Thumbprint matches — token is bound to our key")
		} else {
			fmt.Println("WARNING: thumbprint mismatch")
		}
	}

	// Step 4: Example API call (uncomment and set your URL)
	// apiURL := "https://your-api.example.com/protected"
	// fmt.Printf("\nCalling %s with DPoP proof...\n", apiURL)
	// apiResp := callWithDPoP(privKey, accessToken, "GET", apiURL)
	// fmt.Printf("Response: HTTP %d\n", apiResp.StatusCode)
}

// createDPoPProof builds and signs a DPoP proof JWT using the stdlib.
func createDPoPProof(key *ecdsa.PrivateKey, method, targetURL, accessToken string) string {
	pub := &key.PublicKey

	// JWK header with public key
	header := map[string]any{
		"typ": "dpop+jwt",
		"alg": "ES256",
		"jwk": map[string]any{
			"kty": "EC",
			"crv": "P-256",
			"x":   base64RawURL(pub.X.Bytes(), 32),
			"y":   base64RawURL(pub.Y.Bytes(), 32),
		},
	}

	payload := map[string]any{
		"jti": randomID(),
		"htm": method,
		"htu": targetURL,
		"iat": time.Now().Unix(),
	}

	// Include access token hash for API calls
	if accessToken != "" {
		h := sha256.Sum256([]byte(accessToken))
		payload["ath"] = base64.RawURLEncoding.EncodeToString(h[:])
	}

	return signJWT(key, header, payload)
}

// callWithDPoP makes an HTTP request with a DPoP-bound access token.
func callWithDPoP(key *ecdsa.PrivateKey, accessToken, method, targetURL string) *http.Response {
	proof := createDPoPProof(key, method, targetURL, accessToken)

	req, _ := http.NewRequest(method, targetURL, nil)
	req.Header.Set("Authorization", "DPoP "+accessToken)
	req.Header.Set("DPoP", proof)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fatalf("api request: %v", err)
	}
	return resp
}

// jwkThumbprint computes the RFC 7638 JWK thumbprint for an EC public key.
func jwkThumbprint(pub *ecdsa.PublicKey) string {
	// Canonical JWK representation (alphabetical order of members)
	canonical := fmt.Sprintf(
		`{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}`,
		base64RawURL(pub.X.Bytes(), 32),
		base64RawURL(pub.Y.Bytes(), 32),
	)
	h := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// signJWT creates a JWS Compact Serialization (header.payload.signature).
func signJWT(key *ecdsa.PrivateKey, header, payload map[string]any) string {
	hBytes, _ := json.Marshal(header)
	pBytes, _ := json.Marshal(payload)

	h := base64.RawURLEncoding.EncodeToString(hBytes)
	p := base64.RawURLEncoding.EncodeToString(pBytes)
	signingInput := h + "." + p

	hash := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		fatalf("sign: %v", err)
	}

	// ES256 signature is r || s, each padded to 32 bytes
	sig := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// decodeJWTPayload decodes a JWT payload without signature verification.
func decodeJWTPayload(token string) map[string]any {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var claims map[string]any
	json.Unmarshal(raw, &claims)
	return claims
}

// base64RawURL encodes bytes with zero-padding to the specified length.
func base64RawURL(b []byte, padTo int) string {
	padded := make([]byte, padTo)
	copy(padded[padTo-len(b):], b)
	return base64.RawURLEncoding.EncodeToString(padded)
}

func randomID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}
