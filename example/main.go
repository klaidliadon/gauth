package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/klaidliadon/gauth"
)

func main() {
	const address = "localhost:3000"
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
	var a = gauth.New(gauth.Config{
		Id:       id,
		Secret:   secret,
		Login:    "/google/login",
		Callback: "/google/callback",
		Logout:   "/google/logout",
	})

	http.Handle(a.LogoutHandler("/"))
	http.Handle(a.LoginHandler())
	http.Handle(a.CallbackHandler("/"))

	http.Handle("/", a.NotLoggedHandler("/profile", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<!doctype html><html><head><title>Login</title></head><body><a href="/google/login" class="button">Login with Google</a></body></html>`)
	})))

	http.Handle("/profile", a.LoggedHandler("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<p>You are logged in as %s!</p><form action="/google/logout" method="post"><input type="submit" value="Logout"></form>`, a.WhoAmI(r))
	})))

	if err := http.ListenAndServe(address, nil); err != nil {
		os.Exit(1)
	}
}
