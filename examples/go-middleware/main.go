/*
Example Go application using StrongDM ID authentication.

This demonstrates:
  - Basic authentication with RequireAuth
  - Scope-based access control with RequireScope
  - Accessing token claims via GetAgentInfo
  - Public endpoints that don't require auth
*/
package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	auth, err := New(Config{
		Issuer:               envOr("STRONGDM_ISSUER", "https://id.strongdm.ai"),
		Audience:             os.Getenv("STRONGDM_AUDIENCE"),
		IntrospectionEnabled: os.Getenv("STRONGDM_INTROSPECTION_ENABLED") == "true",
		ClientID:             os.Getenv("STRONGDM_CLIENT_ID"),
		ClientSecret:         os.Getenv("STRONGDM_CLIENT_SECRET"),
	}, log)
	if err != nil {
		log.Error("init auth", "error", err)
		os.Exit(1)
	}
	defer auth.Close()

	mux := http.NewServeMux()

	// Public routes — no authentication required.
	mux.HandleFunc("GET /", handleIndex)
	mux.HandleFunc("GET /health", handleHealth)

	// Protected routes — require a valid StrongDM ID token.
	mux.Handle("GET /protected", auth.RequireAuth(http.HandlerFunc(handleProtected)))
	mux.Handle("GET /agent-info", auth.RequireAuth(http.HandlerFunc(handleAgentInfo)))

	// Scope-restricted routes.
	mux.Handle("GET /admin", auth.RequireScope("admin")(http.HandlerFunc(handleAdmin)))

	addr := ":" + envOr("PORT", "8080")
	log.Info("listening", "addr", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Error("serve", "error", err)
	}
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"message": "Welcome to the StrongDM ID Go example",
		"endpoints": map[string]string{
			"/":          "This page (public)",
			"/health":    "Health check (public)",
			"/protected": "Requires authentication",
			"/agent-info": "Shows info about the authenticated agent",
			"/admin":     "Requires admin scope",
		},
	})
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]string{"status": "healthy"})
}

func handleProtected(w http.ResponseWriter, r *http.Request) {
	agent := GetAgentInfo(r)
	writeJSON(w, map[string]any{
		"message": "You are authenticated!",
		"subject": agent.Subject,
		"scopes":  agent.Scopes,
	})
}

func handleAgentInfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, GetAgentInfo(r))
}

func handleAdmin(w http.ResponseWriter, r *http.Request) {
	agent := GetAgentInfo(r)
	writeJSON(w, map[string]any{
		"message": "Welcome, admin!",
		"subject": agent.Subject,
		"scopes":  agent.Scopes,
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
