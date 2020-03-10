package actions

import (
	"database/sql"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-redis/redis"
	"github.com/gobuffalo/buffalo"
	"github.com/gobuffalo/envy"
	"github.com/gobuffalo/pop"
	"github.com/gobuffalo/validate"
	"github.com/patrick/awesome_spreadsheet_api/models"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

const (

	// Temps d'expiration d'un JWT en seconde
	JWT_EXPIRATION_TIME = 1800
)

// AuthCreate attempts to log the user in with an existing account.
func AuthCreate(c buffalo.Context) error {
	u := &models.User{}
	if err := c.Bind(u); err != nil {
		return errors.WithStack(err)
	}

	tx := c.Value("tx").(*pop.Connection)

	// find a user with the email
	err := tx.Where("email = ?", strings.ToLower(strings.TrimSpace(u.Email))).First(u)

	// helper function to handle bad attempts
	bad := func() error {
		c.Set("user", u)
		verrs := validate.NewErrors()
		verrs.Add("email", "invalid email/password")
		c.Set("errors", verrs)
		return c.Render(http.StatusUnprocessableEntity, r.JSON(map[string]string{"message": "Non c'est pas sa, c'est <<test@test.fr>> et <<test>> mais ne le dit à personne hein."}))
	}

	if err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			// couldn't find an user with the supplied email address.
			return bad()
		}
		return errors.WithStack(err)
	}

	// confirm that the given password matches the hashed password from the db
	err = bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(u.Password))
	if err != nil {
		return bad()
	}

	// Connexion a redis
	client := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "", // no password set
		DB:       0,  // use default DB
	})
	defer client.Close()

	// Recuperation de la cle public
	publicKey, err := getPublicKey()
	if err != nil {
		return errors.WithStack(err)
	}

	// Creation de la JWT en HS256 (Cle public commune avec le client)
	token := generateSimpleToken(u.ID.String())
	tokenString, err := token.SignedString(publicKey)
	if err != nil {
		return errors.WithStack(err)
	}

	// Ajout du token dans Redis parce que pk pas enfaite
	if err := client.Set(u.ID.String(), tokenString, 0).Err(); err != nil {
		return errors.WithStack(err)
	}

	// Ajoute le JWT dans le header de la reponse
	c.Response().Header().Add("Set-Authorization", tokenString)

	// Renvoi des infos sur l'utilisateur
	return c.Render(http.StatusOK, r.JSON(map[string]string{"username": u.Email}))
}

// AuthDestroy clears the session and logs a user out
func AuthDestroy(c buffalo.Context) error {

	// Connexion a redis
	client := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "", // no password set
		DB:       0,  // use default DB
	})
	defer client.Close()

	// Recuperation des claims du token
	claims := c.Value("claims").(jwt.MapClaims)
	idUser := claims["sub"].(string)

	if idUser == "" {
		return c.Render(http.StatusUnprocessableEntity, r.JSON(map[string]string{"error": "Aucune session active"}))
	}

	// Suppression du token
	client.Del(idUser)

	// Redirection
	return c.Render(http.StatusNoContent, nil)
}

func Authorize(next buffalo.Handler) buffalo.Handler {
	return func(c buffalo.Context) error {
		// Connexion a redis
		client := redis.NewClient(&redis.Options{
			Addr:     "localhost:6379",
			Password: "", // no password set
			DB:       0,  // use default DB
		})
		defer client.Close()

		// Recuperation des claims du token
		claims := c.Value("claims").(jwt.MapClaims)
		idUserClaimed := claims["sub"].(string)

		if idUserClaimed == "" {
			return c.Render(http.StatusUnprocessableEntity, r.JSON(map[string]string{"error": "La session demandée est invalide"}))
		}

		// Recuperation du token definit lors de la connexion
		userToken := client.Get(idUserClaimed).Val()

		if userToken == "" {
			return c.Render(http.StatusUnprocessableEntity, r.JSON(map[string]string{"error": "La session demandée n'existe plus"}))

		}

		// Recuperation de la cle public
		publicKey, err := getPublicKey()
		if err != nil {
			return errors.WithStack(err)
		}

		// Regeneration de la JWT en HS256 (Cle public commune avec le client)
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString(publicKey)
		if err != nil {
			return errors.WithStack(err)
		}

		// Assure que le token ne proviennent pas d'une session deconnecte
		if tokenString != userToken {
			return c.Render(http.StatusUnprocessableEntity, r.JSON(map[string]string{"error": "Session illegal"}))
		}

		// Validation du parametre Autorization du Header
		authorization := c.Request().Header.Get("Authorization")
		if authorization == "" {
			return c.Render(http.StatusUnprocessableEntity, r.JSON(map[string]string{"error": "Token fournit invalide " + authorization}))
		}

		// Generation d'un jwt avec une nouvelle periode d'expiration
		lifeTime := time.Now().Add(time.Minute * JWT_EXPIRATION_TIME).Unix()

		newToken := generateSimpleToken(claims["sub"].(string), claims["iat"].(int64), claims["nbf"].(int64), lifeTime)
		newTokenString, err := newToken.SignedString(publicKey)
		c.Response().Header().Add("Set-Authorization", newTokenString)

		return next(c)
	}

}

// Genere un nouveau token simple avec seulement quatre claims generique (sub,nbf,iat,exp)
// Ordre des unixTimeBasedClaims : [0] -> nbf, [1] -> iat, [2] -> exp
func generateSimpleToken(sub string, unixTimeBasedClaims ...int64) *jwt.Token {

	// Creation du Claim (body du JWT)
	claims := jwt.MapClaims{}
	claims["sub"] = sub

	if len(unixTimeBasedClaims) >= 1 {
		claims["nbf"] = unixTimeBasedClaims[0]
	} else {
		claims["nbf"] = time.Now().Unix()
	}

	if len(unixTimeBasedClaims) >= 2 {
		claims["iat"] = unixTimeBasedClaims[1]
	} else {
		claims["iat"] = time.Now().Unix()
	}

	if len(unixTimeBasedClaims) == 3 {
		claims["exp"] = unixTimeBasedClaims[1]
	} else {
		claims["exp"] = time.Now().Add(time.Minute * 30).Unix()
	}

	claims["iat"] = time.Now().Unix()
	claims["exp"] = time.Now().Add(time.Second * JWT_EXPIRATION_TIME).Unix()

	// Creation de la JWT en HS256 (Cle public commune avec le client)
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

}

// Recupere la cle public au format SSH RSA a partir de
// l'emplacement indique par la var env JWT_PUBLIC_KEY
func getPublicKey() (interface{}, error) {
	secretPath, err := envy.MustGet("JWT_PUBLIC_KEY")
	dat, err := ioutil.ReadFile(secretPath)
	if err != nil {
		return nil, err
	}
	return dat, nil
}
