package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var oauthConf = &oauth2.Config{
	ClientID:     os.Getenv("CLIENT_ID"),
	ClientSecret: os.Getenv("CLIENT_SECRETS"),
	Endpoint:     google.Endpoint,
	RedirectURL:  "http://localhost:8000/auth/google/callback",
	Scopes: []string{
		"https://www.googleapis.com/auth/userinfo.email",
		"https://www.googleapis.com/auth/userinfo.profile",
	},
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", handleLogin)
	mux.HandleFunc("GET /auth/google/callback", handleCallback)
	srv := http.Server{Addr: ":8080", Handler: mux}
	if err := srv.ListenAndServe(); err != nil {
		os.Exit(1)
	}
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(
		w,
		&http.Cookie{
			Name:     "authState",
			Value:    "aaaa",
			MaxAge:   int(time.Hour),
			HttpOnly: true,
		},
	)
	http.Redirect(w, r, oauthConf.AuthCodeURL("aaaa"), http.StatusFound)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	authState, err := r.Cookie("authState")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if r.URL.Query().Get("state") != authState.Value {
		fmt.Errorf("parameter = %v, state = %v", r.URL.Query().Get("state"), authState.Value)
		return
	}

	t, err := oauthConf.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusGatewayTimeout)
		return
	}
	client := oauthConf.Client(r.Context(), t)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusGatewayTimeout)
		return
	}
	var data map[string]any
	json.Unmarshal(body, &data)
	message := fmt.Sprintf("name=%v, email=%v, id=%v", data["name"], data["email"], data["id"])
	w.Write([]byte(message))
}
