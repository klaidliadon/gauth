package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/klaidliadon/gauth"
)

func main() {
	const address = ":3000"
	var (
		id     string
		secret string
	)
	flag.StringVar(&id, "client-id", os.Getenv("GID"), "Google Client ID")
	flag.StringVar(&secret, "client-secret", os.Getenv("GSECRET"), "Google Client Secret")
	flag.Parse()
	if id == "" || secret == "" {
		os.Exit(1)
	}
	a := gauth.New(id, secret)
	http.Handle("/google/logout", a.LogoutHandler("/"))
	http.Handle("/google/login", a.LoginHandler())
	http.Handle("/google/callback", a.CallbackHandler("/"))
	http.Handle("/", a.ConditionalHandler(false, "/profile", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<!doctype html><html><head><title>Login</title></head><body><a href="/google/login" class="button">Login with Google</a></body></html>`)
	})))
	http.Handle("/profile", a.ConditionalHandler(true, "/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<p>You are logged in as %s!</p><form action="/google/logout" method="post"><input type="submit" value="Logout"></form>`, a.WhoAmI(r))
	})))
	err := http.ListenAndServe(address, nil)
	if err != nil {
		os.Exit(1)
	}
}
