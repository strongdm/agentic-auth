/*
Example client demonstrating the full StrongDM ID lifecycle in Go:

 1. Register a new OIDC client with id.strongdm.ai
 2. Confirm registration with the emailed verification code
 3. Get a JWT via client_credentials grant
 4. Call an authenticated API with the token

Usage:

	go run ./client register you@example.com
	go run ./client confirm <enrollment_id> <poll_token> <code>
	go run ./client token <client_id> <client_secret>
	go run ./client call <client_id> <client_secret> <url>
*/
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

var idpURL = func() string {
	if v := os.Getenv("STRONGDM_ISSUER"); v != "" {
		return v
	}
	return "https://id.strongdm.ai"
}()

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: client <register|confirm|token|call> ...")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "register":
		if len(os.Args) != 3 {
			fmt.Fprintln(os.Stderr, "usage: client register <email>")
			os.Exit(1)
		}
		cmdRegister(os.Args[2])
	case "confirm":
		if len(os.Args) != 5 {
			fmt.Fprintln(os.Stderr, "usage: client confirm <enrollment_id> <poll_token> <code>")
			os.Exit(1)
		}
		cmdConfirm(os.Args[2], os.Args[3], os.Args[4])
	case "token":
		if len(os.Args) != 4 {
			fmt.Fprintln(os.Stderr, "usage: client token <client_id> <client_secret>")
			os.Exit(1)
		}
		cmdToken(os.Args[2], os.Args[3])
	case "call":
		if len(os.Args) != 5 {
			fmt.Fprintln(os.Stderr, "usage: client call <client_id> <client_secret> <url>")
			os.Exit(1)
		}
		cmdCall(os.Args[2], os.Args[3], os.Args[4])
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}

// cmdRegister starts OIDC client self-registration.
func cmdRegister(email string) {
	body := map[string]any{
		"email":            email,
		"client_name":      "go-example",
		"requested_scopes": []string{"openid"},
	}

	result := postJSON(idpURL+"/register/request", body, "")
	printJSON(result)

	enrollmentID, _ := result["enrollment_id"].(string)
	pollToken, _ := result["poll_token"].(string)
	fmt.Fprintf(os.Stderr, "\nCheck email for verification code, then run:\n")
	fmt.Fprintf(os.Stderr, "  go run ./client confirm %s %s <CODE>\n", enrollmentID, pollToken)
}

// cmdConfirm finishes registration and prints the client credentials.
func cmdConfirm(enrollmentID, pollToken, code string) {
	body := map[string]any{
		"enrollment_id":     enrollmentID,
		"poll_token":        pollToken,
		"verification_code": code,
	}

	result := postJSON(idpURL+"/register/confirm", body, "")
	printJSON(result)

	clientID, _ := result["client_id"].(string)
	clientSecret, _ := result["client_secret"].(string)
	fmt.Fprintf(os.Stderr, "\nSave these credentials! Get a token with:\n")
	fmt.Fprintf(os.Stderr, "  go run ./client token %s %s\n", clientID, clientSecret)
}

// cmdToken gets a JWT via client_credentials grant.
func cmdToken(clientID, clientSecret string) {
	data := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"scope":         {"openid"},
	}

	resp, err := http.PostForm(idpURL+"/token", data)
	if err != nil {
		fatalf("token request: %v", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		fatalf("token error (HTTP %d): %s", resp.StatusCode, raw)
	}

	var result map[string]any
	json.Unmarshal(raw, &result)
	printJSON(result)

	if token, ok := result["access_token"].(string); ok {
		fmt.Fprintf(os.Stderr, "\nToken (first 40 chars): %s...\n", token[:min(40, len(token))])
	}
}

// cmdCall gets a token and makes an authenticated GET request.
func cmdCall(clientID, clientSecret, targetURL string) {
	// Step 1: Get token.
	data := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"scope":         {"openid"},
	}

	tokenResp, err := http.PostForm(idpURL+"/token", data)
	if err != nil {
		fatalf("token request: %v", err)
	}
	defer tokenResp.Body.Close()

	tokenRaw, _ := io.ReadAll(tokenResp.Body)
	if tokenResp.StatusCode != http.StatusOK {
		fatalf("token error (HTTP %d): %s", tokenResp.StatusCode, tokenRaw)
	}

	var tokenResult map[string]any
	json.Unmarshal(tokenRaw, &tokenResult)
	accessToken, _ := tokenResult["access_token"].(string)
	if accessToken == "" {
		fatalf("no access_token in response")
	}
	fmt.Fprintf(os.Stderr, "Got token, calling %s ...\n", targetURL)

	// Step 2: Call the API.
	req, _ := http.NewRequest("GET", targetURL, nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	fmt.Printf("%s\n", raw)
	fmt.Fprintf(os.Stderr, "HTTP %d\n", resp.StatusCode)
}

// --- Helpers ---

func postJSON(url string, body map[string]any, token string) map[string]any {
	data, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", url, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fatalf("request to %s: %v", url, err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		fatalf("HTTP %d from %s: %s", resp.StatusCode, url, raw)
	}

	var result map[string]any
	if err := json.Unmarshal(raw, &result); err != nil {
		fatalf("decode response: %v (body: %s)", err, raw)
	}
	return result
}

func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Unused but shows how to POST authenticated JSON (e.g., creating content).
func postAuthenticatedJSON(targetURL, token string, body map[string]any) map[string]any {
	data, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", targetURL, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fatalf("request to %s: %v", targetURL, err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		fatalf("HTTP %d from %s: %s", resp.StatusCode, targetURL, raw)
	}

	var result map[string]any
	json.Unmarshal(raw, &result)
	return result
}
