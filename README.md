# API REST en Golang

Utilisation de Golang avec le framework web Buffalo.
Ici on utilise un back sous la forme d'une API.
L'authentification ce fait au travers de Tokens (JWT) et la durabililté des sessions est entretenu par un serveur REDIS, enregistrant l'etat de chaque utilisateur present sur le site
La base de données est en SQLite3 pour limiter la concentration des données sur un seul endroit (serveur SQL commun à tous les sites). Egalement, cela evite les attaques type nmap/recherche de serveur SQL vu qu'aucun acces à la base n'est possible depuis l'exterieur

## Authentification

Le JWT est generée avec l'algorithme HS256. Il utilise une clé publique devant être fournit à chaque appel client. Cette clé est générée via openSSH, puis le lien vers le fichier .rem est fournit en parametre à l'application BuffaloGO par le biais de la variable d'environnement *JWT_PUBLIC_KEY*. La récupération de cette clé dans l'application ce fait via la fonction **getPublicKey** du fichier **auth.go**

Les claims de base de la JWT contiennent :

+ sub: Subject -> UID de l'utilisateur
+ nbf: Not Before -> Timestamp de génération du token, empechant la validation de celui-ci si l'appel est fait avant ce ts
+ iat: Initialised At -> Timestamp d'initialisation du token
+ exp: Expiraton -> Timestamp donnant l'heure d'expiration du token

Lorsque le client ce connecte, le JWT est générée et la session est sauvegardé dans le serveur REDIS. A chaque appel de l'API, une demande est faite à ce serveur pour s'assurer que la connexion n'est pas frauduleuse

A chaque appel du client, un nouveau JWT est généré pour éviter qu'il ce fasse Timeout. Ce nouveau token est envoyé dans le Header de la requete avec **Set-Authorization**, celui-ci doit être récupérer par le client et renvoyer avec la prochaine requete sous peine de ce faire rejeter par le serveur.

## Création du projet

Il nous faut :

+ Le projet Buffalo en structure API
+ Le module de connexion utilisateur de Buffalo pour la création et l'utilisation d'utilisateur
+ Le module JWT de Buffalo pour la génération est l'utilisation des token
+ go-redis pour la communication avec le serveur REDIS