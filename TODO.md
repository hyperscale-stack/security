* faire un `AuthenticationManager` ou un `ProviderManager` qui liste les providers à utilisé et vérifie si un `Filter` match via `Provider.IsSupported()` et appel `Provider.Authenticate()` si c'est supporté
* Faire le systeme de filter ex: `BearerAuthenticationFilter`, `OAuth2AuthenticationFilter`, `HTTPBasicAuthenticationFilter`, `HTTPDigestAuthenticationFilter`, etc...
* faire un autre module `security-service-provider` pour utilisé ça via go-application
* faire un middleware `Authentication()` pour detecter via les Filters le type d'auth
* faire un middleware `Authorize()` qui sera utilisé sur une route pour vérifier que l'auth trouvé via un filter est authenticated et validate
* * faire un system d'options pour `Authorize()`, ex: `Authorize(HasRole("ADMIN"))` ???


TODO
====


- [ ] Filters 
 - [x] AccessTokenFilter
 - [x] BearerFilter
 - [x] HTTPBasicFilter
 - [ ] HTTPDigestFilter
