/*
SPIFFE Client Example — Go (stdlib only)

Demonstrates how to:
 1. Fetch the SPIFFE trust bundle from StrongDM ID
 2. Obtain a Bearer token via client_credentials
 3. Request a JWT-SVID (SPIFFE Verifiable Identity Document)
 4. Decode and inspect the JWT-SVID claims

Run: go run main.go
*/
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

func main() {
	issuer := envOr("STRONGDM_ISSUER", "https://id.strongdm.ai")
	clientID := os.Getenv("STRONGDM_CLIENT_ID")
	clientSecret := os.Getenv("STRONGDM_CLIENT_SECRET")
	audience := envOr("SPIFFE_AUDIENCE", "example-service")

	if clientID == "" || clientSecret == "" {
		fmt.Fprintln(os.Stderr, "Set STRONGDM_CLIENT_ID and STRONGDM_CLIENT_SECRET")
		os.Exit(1)
	}

	// Step 1: Fetch trust bundle
	bundleURL := issuer + "/.well-known/spiffe-trust-bundle"
	fmt.Printf("Fetching trust bundle from %s...\n", bundleURL)

	bundleResp, err := http.Get(bundleURL)
	if err != nil {
		fatalf("fetch trust bundle: %v", err)
	}
	defer bundleResp.Body.Close()
	bundleBody, _ := io.ReadAll(bundleResp.Body)

	if bundleResp.StatusCode == 404 {
		fmt.Println("SPIFFE trust bundle endpoint not found (404) — SPIFFE may not be enabled")
		os.Exit(1)
	}
	if bundleResp.StatusCode != 200 {
		fatalf("trust bundle HTTP %d: %s", bundleResp.StatusCode, bundleBody)
	}

	var bundle map[string]any
	json.Unmarshal(bundleBody, &bundle)
	if keys, ok := bundle["keys"].([]any); ok {
		fmt.Printf("Trust bundle contains %d key(s)\n", len(keys))
	}

	// Step 2: Get a Bearer token
	fmt.Printf("\nGetting Bearer token from %s/token...\n", issuer)

	tokenForm := url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {"openid"},
	}
	tokenReq, _ := http.NewRequest("POST", issuer+"/token", strings.NewReader(tokenForm.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenReq.SetBasicAuth(clientID, clientSecret)

	tokenResp, err := http.DefaultClient.Do(tokenReq)
	if err != nil {
		fatalf("token request: %v", err)
	}
	defer tokenResp.Body.Close()
	tokenBody, _ := io.ReadAll(tokenResp.Body)

	if tokenResp.StatusCode != 200 {
		fatalf("token error HTTP %d: %s", tokenResp.StatusCode, tokenBody)
	}

	var tokenResult map[string]any
	json.Unmarshal(tokenBody, &tokenResult)
	bearerToken, _ := tokenResult["access_token"].(string)
	if bearerToken == "" {
		fatalf("no access_token in response")
	}
	if len(bearerToken) > 40 {
		fmt.Printf("Bearer token obtained (first 40 chars): %s...\n", bearerToken[:40])
	}

	// Step 3: Request JWT-SVID
	svidURL := issuer + "/svid/jwt"
	fmt.Printf("\nRequesting JWT-SVID from %s...\n", svidURL)

	svidBody, _ := json.Marshal(map[string]any{
		"audience": []string{audience},
	})
	svidReq, _ := http.NewRequest("POST", svidURL, bytes.NewReader(svidBody))
	svidReq.Header.Set("Content-Type", "application/json")
	svidReq.Header.Set("Authorization", "Bearer "+bearerToken)

	svidResp, err := http.DefaultClient.Do(svidReq)
	if err != nil {
		fatalf("svid request: %v", err)
	}
	defer svidResp.Body.Close()
	svidRaw, _ := io.ReadAll(svidResp.Body)

	if svidResp.StatusCode == 404 {
		fmt.Println("JWT-SVID endpoint not found (404) — SPIFFE may not be enabled")
		os.Exit(1)
	}
	if svidResp.StatusCode != 200 {
		fatalf("svid error HTTP %d: %s", svidResp.StatusCode, svidRaw)
	}

	var svidResult map[string]any
	json.Unmarshal(svidRaw, &svidResult)

	// The SVID may be in "svid" or "token" field
	svidToken, _ := svidResult["svid"].(string)
	if svidToken == "" {
		svidToken, _ = svidResult["token"].(string)
	}
	if svidToken == "" {
		fatalf("no svid/token in response: %s", svidRaw)
	}

	if len(svidToken) > 40 {
		fmt.Printf("JWT-SVID obtained (first 40 chars): %s...\n", svidToken[:40])
	}

	// Step 4: Decode and inspect claims
	claims := decodeJWTPayload(svidToken)
	if claims != nil {
		fmt.Printf("\nJWT-SVID claims:\n")
		fmt.Printf("  sub (SPIFFE ID): %v\n", claims["sub"])
		fmt.Printf("  aud:             %v\n", claims["aud"])
		fmt.Printf("  iss:             %v\n", claims["iss"])
		fmt.Printf("  exp:             %v\n", claims["exp"])

		if sub, ok := claims["sub"].(string); ok && strings.HasPrefix(sub, "spiffe://") {
			fmt.Println("\n  Subject is a valid SPIFFE ID")
		} else {
			fmt.Printf("\n  WARNING: subject '%v' is not a spiffe:// URI\n", claims["sub"])
		}
	}
}

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
