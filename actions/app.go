package actions

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/gobuffalo/buffalo"
	"github.com/gobuffalo/envy"
	forcessl "github.com/gobuffalo/mw-forcessl"
	paramlogger "github.com/gobuffalo/mw-paramlogger"
	"github.com/gobuffalo/x/sessions"
	"github.com/unrolled/secure"

	"github.com/gobuffalo/buffalo-pop/pop/popmw"
	contenttype "github.com/gobuffalo/mw-contenttype"
	tokenauth "github.com/gobuffalo/mw-tokenauth"
	"github.com/patrick/awesome_spreadsheet_api/models"
	"github.com/rs/cors"
)

// ENV is used to help switch settings based on where the
// application is being run. Default is "development".
var ENV = envy.Get("GO_ENV", "development")
var app *buffalo.App

// App is where all routes and middleware for buffalo
// should be defined. This is the nerve center of your
// application.
//
// Routing, middleware, groups, etc... are declared TOP -> DOWN.
// This means if you add a middleware to `app` *after* declaring a
// group, that group will NOT have that new middleware. The same
// is true of resource declarations as well.
//
// It also means that routes are checked in the order they are declared.
// `ServeFiles` is a CATCH-ALL route, so it should always be
// placed last in the route declarations, as it will prevent routes
// declared after it to never be called.
func App() *buffalo.App {
	if app == nil {
		app = buffalo.New(buffalo.Options{
			Env:          ENV,
			SessionStore: sessions.Null{},
			PreWares: []buffalo.PreWare{
				cors.Default().Handler,
			},
			SessionName: "_awesome_spreadsheet_api_session",
		})

		// Redirection automatique en SSL
		app.Use(forceSSL())

		// Log des parametres envoye par les requettes http
		app.Use(paramlogger.ParameterLogger)

		// Definition du content-type dans le header de chaque requete
		app.Use(contenttype.Set("application/json"))

		// Wraps chaque requete dans une transaction
		// c.Value("tx").(*pop.Connection)
		app.Use(popmw.Transaction(models.DB))

		// Utilisation du middleware tokenauth pour
		// gerer l'authentification par JWT (JSON Web Token).
		jwtHandler := tokenauth.New(tokenauth.Options{
			GetKey: func(signingMethod jwt.SigningMethod) (interface{}, error) {
				// Les requetes reçu doivent avoir un header avec :	Autorization: Bearer <jwt>
				// La signature de la jwt doit etre genere avec la cle prive
				return getPublicKey()
			},
			SignMethod: jwt.SigningMethodHS256,
		})

		app.Use(jwtHandler)
		app.Use(Authorize)

		app.GET("/", HomeHandler)

		app.POST("/signin", AuthCreate)
		app.DELETE("/signout", AuthDestroy)
		//app.POST("/users", UsersCreate)
		// app.GET("/users/new", UsersNew)
		// app.GET("/signin", AuthNew)

		app.Middleware.Skip(jwtHandler, HomeHandler, AuthCreate)
		app.Middleware.Skip(Authorize, HomeHandler, AuthCreate, AuthDestroy)
	}

	return app
}

// forceSSL will return a middleware that will redirect an incoming request
// if it is not HTTPS. "http://example.com" => "https://example.com".
// This middleware does **not** enable SSL. for your application. To do that
// we recommend using a proxy: https://gobuffalo.io/en/docs/proxy
// for more information: https://github.com/unrolled/secure/
func forceSSL() buffalo.MiddlewareFunc {
	return forcessl.Middleware(secure.Options{
		SSLRedirect:     ENV == "production",
		SSLProxyHeaders: map[string]string{"X-Forwarded-Proto": "https"},
	})
}
