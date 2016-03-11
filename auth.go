package gauth

import (
	"net/http"

	"github.com/dghubble/ctxh"
	"github.com/dghubble/gologin"
	glogin "github.com/dghubble/gologin/google"
	"github.com/dghubble/sessions"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	goauth "golang.org/x/oauth2/google"
)

const (
	name = "google-auth"
	key  = "google-email"
)

func New(id, secret string) Auth {
	return Auth{
		config: oauth2.Config{
			ClientID:     id,
			ClientSecret: secret,
			RedirectURL:  "http://humanity.against.cards/google/callback",
			Endpoint:     goauth.Endpoint,
			Scopes:       []string{"profile", "email"},
		},
		sessions: sessions.NewCookieStore([]byte("horse battery staple"), nil),
	}
}

type Auth struct {
	config   oauth2.Config
	sessions *sessions.CookieStore
}

func (a *Auth) LoginHandler() http.Handler {
	return ctxh.NewHandler(glogin.StateHandler(
		gologin.DebugOnlyCookieConfig,
		glogin.LoginHandler(&a.config, nil),
	))
}

func (a *Auth) LogoutHandler(redirectURL string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			a.sessions.Destroy(w, name)
		}
		http.Redirect(w, r, "/", http.StatusFound)
	})
}

func (a *Auth) CallbackHandler(redirectURL string) http.Handler {
	return ctxh.NewHandler(glogin.StateHandler(
		gologin.DebugOnlyCookieConfig,
		glogin.CallbackHandler(&a.config, ctxh.ContextHandlerFunc(func(ctx context.Context, w http.ResponseWriter, r *http.Request) {
			googleUser, err := glogin.UserFromContext(ctx)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			session := a.sessions.New(name)
			session.Values[key] = googleUser.Email
			session.Save(w)
			http.Redirect(w, r, redirectURL, http.StatusFound)
		}), nil),
	))
}

func (a *Auth) ConditionalHandler(logged bool, redirectURL string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := a.sessions.Get(r, name); logged && err != nil || !logged && err == nil {
			http.Redirect(w, r, redirectURL, http.StatusFound)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func (a *Auth) WhoAmI(r *http.Request) string {
	s, err := a.sessions.Get(r, name)
	if err != nil {
		return ""
	}
	return s.Values[key].(string)
}
