# Hyperscale Security — Rapport d'architecture

> Destinataire : ChatGPT (lead architecte Go)
> Auteur : Claude Code (exploration du dépôt `github.com/hyperscale-stack/security`)
> Date : 2026-05-18

## 1. Vision & objectifs du projet

`hyperscale-stack/security` est une librairie Go destinée à devenir l'équivalent de **Spring Security** (Java) ou **Symfony Security/ACL** (PHP) pour l'écosystème Go. Les objectifs déclarés (cf. `TODO.md` + README) :

- Fournir un framework **authentification + autorisation** générique, pluggable, et orienté DX.
- Être **transport-agnostic** : utilisable derrière n'importe quel routeur HTTP (net/http, gorilla/mux, chi, gin, echo…), et à terme **gRPC**.
- S'appuyer sur des **interfaces standard `net/http`** pour ne pas verrouiller l'utilisateur sur un framework.
- Découpage clair :
  - **Filters** = extraction de credentials depuis la requête
  - **Providers** = validation des credentials (DAO, OAuth2, …)
  - **Options** = règles d'autorisation composables (`HasRole("ADMIN")`, …)
- Composabilité via middlewares chaînables (compatible `alice`, `chi.Use`, etc.).

**État actuel : MVP fonctionnel mais incomplet.** Le squelette est bien posé, l'API publique est cohérente, mais plusieurs pièces majeures (gRPC, OAuth2 flows complets, AuthenticationManager unifié, JWT, persistance OAuth2 réelle, exemple à jour) manquent ou sont à reprendre. Détails en §10.

---

## 2. Métadonnées du module

| Élément | Valeur |
|---|---|
| Module | `github.com/hyperscale-stack/security` |
| Go version | **1.25.0** |
| Licence | MIT |
| Branche par défaut | `master` |
| Génération de mocks | `mockery v2` (déclaré comme `tool` dans go.mod) |
| Lint | `golangci-lint v2.6.2` (27 linters actifs) |
| CI | GitHub Actions (`.github/workflows/go.yml`), coverage → Coveralls |
| Dépendances directes | `gilcrest/alice`, `hyperscale-stack/secure`, `rs/zerolog`, `stretchr/testify`, `golang.org/x/crypto` |

Le `Makefile` expose `build / test / coverage / coverage-html / bench / lint / generate / release` (avec `git flow`).

---

## 3. Arborescence des packages

```
security/
├── user/                                  # Contrat User (interface)
├── password/                              # Hasher (interface) + BCryptHasher
├── http/header/                           # Helper parsing Authorization header
├── authentication/                        # Cœur de l'auth
│   ├── filter.go                          # Interface Filter
│   ├── provider.go                        # Interface Provider
│   ├── filter_handler.go                  # Middleware "FilterHandler" (extraction)
│   ├── handler.go                         # Middleware "Handler" (validation)
│   ├── bearer_filter.go                   # Filter: Authorization: Bearer xxx
│   ├── access_token_filter.go             # Filter: ?access_token=xxx
│   ├── http_basic_filter.go               # Filter: Authorization: Basic base64(u:p)
│   ├── credential/
│   │   ├── credential.go                  # Interface Credential
│   │   ├── context.go                     # FromContext / ToContext
│   │   ├── token_credential.go            # TokenCredential (Bearer / access_token)
│   │   └── username_password_credential.go# UsernamePasswordCredential (Basic / form)
│   └── provider/
│       ├── dao/
│       │   ├── user_provider.go           # Interface UserProvider (LoadUserByUsername)
│       │   └── dao_authentication_provider.go
│       └── oauth2/
│           ├── client.go                  # Client + DefaultClient + ClientSecretMatcher
│           ├── authorize.go               # AuthorizeInfo (auth code grant)
│           ├── access.go                  # AccessInfo (access token grant)
│           ├── storage.go                 # Interfaces Storage* (Client/Access/Refresh/Authorize/User)
│           ├── oauth2_authentication_provider.go
│           ├── storage/in_memory_storage.go
│           └── token/
│               ├── generator.go           # Interface Generator
│               └── random/                # RandomTokenGenerator + Configuration (mapstructure)
├── authorization/
│   ├── option.go                          # type Option func(creds) bool
│   ├── has_role_option.go                 # HasRole("ADMIN")
│   └── authorize_handler.go               # Middleware AuthorizeHandler(opts...)
├── example/oauth2/main.go                 # ⚠️ obsolète (cf. §10)
├── internal/integrations/                 # Tests d'intégration
├── build/                                 # Artefacts coverage
├── generate.go                            # go:generate mockery
├── Makefile / go.mod / .golangci.yml / .mockery.yaml / README.md / TODO.md
└── .github/                               # workflows + dependabot
```

Lignes de code : ~7 200 LOC total, dont ~2 100 LOC de tests et le reste mocks + prod.

---

## 4. Modèle conceptuel

Le pipeline d'une requête HTTP authentifiée suit **4 étages** :

```
        ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
HTTP ─▶ │ Filter   │ ─▶ │ Provider │ ─▶ │ Authorize│ ─▶ │ Handler  │
        │ Handler  │    │  Handler │    │  Handler │    │  métier  │
        └──────────┘    └──────────┘    └──────────┘    └──────────┘
         extraction      validation      contrôle
         credentials     credentials     d'accès
```

1. **FilterHandler** : itère sur les filters dans l'ordre fourni. Le premier qui parvient à injecter un `Credential` dans le `context` court-circuite les suivants et passe au middleware suivant.
2. **Handler** : récupère le `Credential` du contexte, sélectionne le bon `Provider` via `IsSupported()`, appelle `Authenticate()`. Si erreur ⇒ `401`. Sinon le credential est marqué `IsAuthenticated() = true` et porte un `user.User`.
3. **AuthorizeHandler** : vérifie présence du credential + `IsAuthenticated()` (sinon `401`), puis évalue les `Option`s en AND ; un seul `false` ⇒ `403`.
4. **Handler métier** : code applicatif final qui peut récupérer le `Credential`/`User` via `credential.FromContext(r.Context())`.

Tout passe par `context.Context` (clés non-exportées `credentialCtxKey{}`, `accessTokenCtxKey{}`, `clientCtxKey{}`) — pas de globales, pas de magie.

---

## 5. API publique détaillée

### 5.1 `user`

```go
type User interface {
    GetRoles() []string
    GetPassword() string
    GetUsername() string
    IsExpired() bool
    IsLocked() bool
    IsEnabled() bool
    IsCredentialsExpired() bool
}

type PasswordSalt interface {
    GetSalt() string
    SaltPassword(password, salt string) string
}

type UserPasswordSalt interface { User; PasswordSalt }
```

> Note : aucune implémentation fournie — c'est volontaire, l'utilisateur branche son ORM/DB. Le mock `MockUser` est généré automatiquement.

### 5.2 `password`

```go
type Hasher interface {
    Hash(password string) (string, error)
    Verify(hashed, password string) bool
}

func NewBCryptHasher(cost int) Hasher
```

Une seule implémentation aujourd'hui (`bcrypt`). À étendre éventuellement : argon2id, scrypt.

### 5.3 `authentication/credential`

```go
type Credential interface {
    GetPrincipal() interface{}        // username | token
    GetCredentials() interface{}      // password | nil
    IsAuthenticated() bool
    SetAuthenticated(bool)
    SetUser(user.User)
    GetUser() user.User
}

// Helpers context
func FromContext(ctx context.Context) Credential
func ToContext(ctx context.Context, c Credential) context.Context

// Implémentations
func NewTokenCredential(token string) *TokenCredential
func NewUsernamePasswordCredential(user, pwd string) *UsernamePasswordCredential
```

⚠️ `interface{}` pour `Principal`/`Credentials` est un héritage Spring. À discuter : on perd la type-safety. Cf. §11.

### 5.4 `authentication` (filters, providers, middlewares)

```go
type Filter interface {
    OnFilter(r *http.Request) *http.Request
}

type Provider interface {
    Authenticate(r *http.Request, c credential.Credential) (*http.Request, error)
    IsSupported(c credential.Credential) bool
}

// Filters fournis
func NewBearerFilter() Filter        // Authorization: Bearer <token>
func NewAccessTokenFilter() Filter   // ?access_token=<token>
func NewHTTPBasicFilter() Filter     // Authorization: Basic base64(u:p)
// TODO : HTTPDigestFilter

// Middlewares
func FilterHandler(filters ...Filter) func(http.Handler) http.Handler
func Handler(providers ...Provider) func(http.Handler) http.Handler
```

### 5.5 `authentication/provider/dao`

```go
type UserProvider interface {
    LoadUserByUsername(username string) (user.User, error)
}

func NewDaoAuthenticationProvider(h password.Hasher, up UserProvider) *DaoAuthenticationProvider
```

Flow : `LoadUserByUsername` → si `UserPasswordSalt` ⇒ `SaltPassword(pwd, salt)` → `hasher.Verify(user.GetPassword(), saltedPwd)`.

### 5.6 `authentication/provider/oauth2`

API la plus riche du repo (~300 LOC + storage).

```go
type Client interface {
    GetID() string
    GetSecret() string
    GetRedirectURI() string
    GetUserData() interface{}
}
type ClientSecretMatcher interface {
    SecretMatches(secret string) bool          // constant-time
}
type DefaultClient struct { ID, Secret, RedirectURI string; UserData interface{} }

type AccessToken interface {
    GetClient() Client
    GetToken() string
    IsExpired() bool
    GetUserID() string
}

// Modèles
type AuthorizeInfo struct { Client; Code; ExpiresIn; Scope; RedirectURI; State; CreatedAt; CodeChallenge /* PKCE */ }
type AccessInfo    struct { Client; AuthorizeData; AccessData; AccessToken; RefreshToken; ExpiresIn; Scope; UserData; CreatedAt }

// Storage (composé)
type ClientProvider    interface { SaveClient, LoadClient, RemoveClient }
type AccessProvider    interface { SaveAccess,  LoadAccess,  RemoveAccess }
type RefreshProvider   interface { SaveRefresh, LoadRefresh, RemoveRefresh }
type AuthorizeProvider interface { SaveAuthorize, LoadAuthorize, RemoveAuthorize }
type UserProvider      interface { LoadUser(id string) (user.User, error) }
type StorageProvider   interface { ClientProvider; AccessProvider; RefreshProvider; AuthorizeProvider }

// Token generator
type token.Generator interface {
    GenerateAccessToken(generateRefresh bool) (accessToken, refreshToken string, err error)
}
func random.NewTokenGenerator(*random.Configuration) token.Generator
// Configuration : AccessTokenSize / RefreshTokenSize (tags mapstructure)

// Provider OAuth2
func NewOAuth2AuthenticationProvider(
    tokenGenerator token.Generator,
    userStorage      UserProvider,
    clientStorage    ClientProvider,
    accessStorage    AccessProvider,
    refreshStorage   RefreshProvider,
    authorizeStorage AuthorizeProvider,
) *OAuth2AuthenticationProvider
```

Comportement de `Authenticate` :
- `*TokenCredential` ⇒ `accessStorage.LoadAccess` → check `IsExpired` → `userStorage.LoadUser(token.UserData.(string))` → injecte `AccessInfo` + `Client` dans le context.
- `*UsernamePasswordCredential` ⇒ traité comme **client credentials** : `clientStorage.LoadClient(principal)` puis `SecretMatches(creds)`. Le client est injecté dans le context, le credential est marqué authentifié ⚠️ **uniquement si match**, mais aucune erreur retournée si non-match (silent fail — bug, cf. §11).
- autre ⇒ `ErrBadAuthenticationFormat`.

Storage in-memory fourni (`storage.NewInMemoryStorage()`, basé sur `sync.Map`) — pour dev/tests seulement.

### 5.7 `authorization`

```go
type Option func(creds credential.Credential) bool

func HasRole(role string) Option
func AuthorizeHandler(options ...Option) func(http.Handler) http.Handler
```

Sémantique : credentials absents OU non-authentifiés ⇒ `401`. Au moins une option `false` ⇒ `403`.

### 5.8 `http/header`

```go
func ExtractAuthorizationValue(scheme, headerValue string) (value string, ok bool)
```

Helper case-insensitive sur le scheme.

---

## 6. Patterns d'architecture utilisés

| Pattern | Où | Pourquoi |
|---|---|---|
| **Chain of Responsibility** | `FilterHandler`, `Handler` | Plusieurs sources d'auth (Bearer/Basic/access_token) testées en cascade |
| **Strategy** | `Provider` (DAO, OAuth2, …) | Choix dynamique de la stratégie d'auth selon le type de credential |
| **Functional Options** | `AuthorizeHandler(HasRole("…"), …)` | Composition d'autorisations sans héritage |
| **Plugin / Hexagonal** | `password.Hasher`, `dao.UserProvider`, `oauth2.StorageProvider`, `token.Generator` | Aucune dépendance dure à un backend (DB, cache, JWT…) |
| **Context propagation** | `credential.ToContext` / `AccessTokenToContext` / `ClientToContext` | Pas de globales, request-scoped, compatible cancellation |
| **Interface segregation** | `ClientProvider` / `AccessProvider` / … recomposés en `StorageProvider` | Permet stockages partiels (ex: refresh dans Redis, autorize dans Postgres) |
| **Defensive crypto** | `subtle.ConstantTimeCompare`, BCrypt | Timing-attack resistance |
| **Generated mocks** | `mockery v2` + tag `// nolint` sur force-asserts | Tests sans wiring manuel |

---

## 7. CI / Tooling

- **GitHub Actions** : build `-race`, mocks, tests, golangci-lint, upload Coveralls.
- **Dependabot** : weekly sur go.mod + actions (assigné `@euskadi31`).
- **Make** : `build / test / coverage / coverage-html / bench / lint / generate / release` (git-flow).
- **golangci-lint** (v2.6.2, 27 linters) : gocyclo max 18 ; ignore `mock_*.go` ; tests désactivés du lint.
- **mockery** : in-package, naming `Mock{{.InterfaceName}}`, fichiers `mock_<snake>.go`, recursive sur tout le module.

---

## 8. Couverture de tests

21 fichiers `_test.go` (~2 126 LOC) couvrant :

| Package | Tests |
|---|---|
| `password` | bcrypt hash/verify |
| `authentication` | filters (Bearer/Basic/AccessToken), `FilterHandler`, `Handler` |
| `authentication/credential` | TokenCredential, UsernamePasswordCredential, context |
| `authentication/provider/dao` | DAO provider (load + verify) |
| `authentication/provider/oauth2` | Client, AccessInfo, AuthorizeInfo, OAuth2 provider, in-memory storage |
| `authorization` | `HasRole`, `AuthorizeHandler` |
| `http/header` | ExtractAuthorizationValue |
| `internal/integrations` | Scénarios bout-en-bout OAuth2 |

Packages **non couverts** : `user/` (interfaces uniquement, normal), `example/` (obsolète, ne compile pas).

---

## 9. Exemple d'usage (cible)

Tel qu'imaginé par l'API actuelle :

```go
hasher := password.NewBCryptHasher(bcrypt.DefaultCost)

// 1) Branche les sources de credentials
filters := authentication.FilterHandler(
    authentication.NewBearerFilter(),
    authentication.NewAccessTokenFilter(),
    authentication.NewHTTPBasicFilter(),
)

// 2) Valide les credentials avec les providers
auth := authentication.Handler(
    dao.NewDaoAuthenticationProvider(hasher, myUserRepo),
    oauth2.NewOAuth2AuthenticationProvider(
        random.NewTokenGenerator(&random.Configuration{}),
        myOAuthUserStore, myClientStore, myAccessStore, myRefreshStore, myAuthzStore,
    ),
)

// 3) Protège une route
adminOnly := authorization.AuthorizeHandler(
    authorization.HasRole("ADMIN"),
)

mux := http.NewServeMux()
mux.Handle("/admin", filters(auth(adminOnly(adminHandler))))
mux.Handle("/login", filters(auth(loginHandler))) // sans autorisation, juste auth
```

⚠️ L'exemple `example/oauth2/main.go` du repo ne correspond plus à l'API : voir §10.

---

## 10. État réel & dette / écarts

| Sujet | Statut | Détail |
|---|---|---|
| Filters HTTP | ✅ Bearer, Basic, AccessToken | ❌ Digest non implémenté (cf. TODO.md) |
| Providers | ✅ DAO, OAuth2 (partiel) | ❌ Pas de JWT provider, pas de LDAP, pas de session/cookie |
| Authorization options | ✅ `HasRole` | ❌ Manque `HasAnyRole`, `HasScope`, `IsAuthenticated`, `IsAnonymous`, `HasPermission`, expressions arbitraires (SpEL-like) |
| AuthenticationManager unifié | ✅ Implémenté de fait par `Handler(...)` | ⚠️ Le `TODO.md` le réclame encore — sémantique à clarifier (séquentiel vs first-match) |
| `Handler` semantics | ⚠️ Bug subtil | Itère sur **tous** les providers supportés (au lieu de s'arrêter au premier success). Si plusieurs matchent, le dernier écrase l'état. Devrait être `break` après succès. |
| OAuth2 client creds | ⚠️ Silent fail | `authenticateByClient` n'appelle `SetAuthenticated(true)` que si `SecretMatches`, mais **ne retourne pas d'erreur** sinon ⇒ requête passe sans auth, et l'`AuthorizeHandler` répond 401. Comportement acceptable mais à logger / expliciter. |
| OAuth2 flows | ⚠️ Modèles présents (`AuthorizeInfo`, `AccessInfo`, PKCE field), endpoints absents | Pas de handlers `/oauth2/authorize`, `/oauth2/token`, `/oauth2/revoke`, `/oauth2/introspect` |
| Refresh token rotation | ❌ Non implémenté |
| Storage persistant | ❌ Seul `InMemoryStorage` existe | À fournir : Redis / SQL / Bun / ent |
| Exemple | 🔴 **Cassé** | `example/oauth2/main.go` importe `github.com/gorilla/mux` qui n'est **pas** dans `go.mod`, et appelle `NewOAuth2AuthenticationProvider(tokenGenerator, storageProvider)` (2 args) alors que la signature actuelle en attend **6**. À régénérer. |
| gRPC | ❌ Non commencé | Aucun interceptor `grpc.UnaryServerInterceptor` / `StreamServerInterceptor`. Pourtant un des objectifs (transport-agnostic). |
| Service-provider (`go-application`) | ❌ Non commencé | Cf. TODO.md (`security-service-provider`) |
| Errors API | ⚠️ Erreurs `var Err… = errors.New(…)` mais pas de typed errors ni de wrapping vers HTTP code | Pas de stratégie de mapping erreur → status code centralisée |
| Logging | `zerolog.Ctx(ctx)` correctement utilisé | Une coquille : `"deocde http basic auth failed"` dans `http_basic_filter.go:66` |
| Mocks | ✅ Générés (`mockery v2`) | OK |
| Internationalisation des messages | ❌ Hardcodé `"Access denied"` | À externaliser si lib publique |

---

## 11. Recommandations pour ChatGPT (lead architect)

Points à arbitrer en priorité :

### 11.1 Type-safety du `Credential`
`GetPrincipal() interface{}` / `GetCredentials() interface{}` est un héritage Spring. Avec Go 1.25 on peut faire mieux :
- soit **génériques** : `Credential[P, C any]` (mais alors le contexte typé devient lourd),
- soit **type-asserter** strict avec un set fini d'implémentations exportées + helpers (`AsToken(c) (string, bool)`, `AsUserPass(c) (u, p string, ok bool)`).

### 11.2 Sémantique de `Handler`
Décider : *first-match wins* (recommandé, idiomatique) ou *all-providers-run* (actuel, fragile). Aujourd'hui le code itère sans break — bug latent en cas de multi-provider.

### 11.3 Découpler du `net/http` pour viser gRPC
Le `Filter`/`Provider` est calqué sur `*http.Request`. Pour gRPC il faut un niveau d'indirection :

```go
type Request interface {
    Context() context.Context
    Header(key string) string
    Query(key string) string
    WithContext(ctx context.Context) Request
}
```

Puis des adapters `httpRequest{r *http.Request}` et `grpcRequest{md metadata.MD}`. Sinon dupliquer toute la chaîne pour gRPC.

Alternative : garder un *core* `Authenticator` qui ne manipule que `context.Context` + une *abstraction de carrier* (header map), et binder dans des modules `transport/http` et `transport/grpc`.

### 11.4 API d'autorisation
`Option func(c Credential) bool` est limitée — pas d'accès à la requête, pas de retour d'erreur explicite, pas d'asynchrone (RBAC distant). Suggestion :

```go
type Decision int
const ( Permit Decision = iota; Deny; Abstain )

type Voter interface {
    Vote(ctx context.Context, c Credential, attr Attributes) (Decision, error)
}
```

…et un `AccessDecisionManager` (affirmative/consensus/unanimous) — c'est le modèle Spring Security et il scale très bien.

### 11.5 OAuth2
Si OAuth2 est un *first-class citizen*, alors :
- soit s'appuyer sur une lib mature (`go-oauth2/oauth2`, `ory/fosite`) et n'écrire que l'adapter,
- soit cadrer **OIDC + PKCE + DPoP** dès la v1 et fournir les endpoints (`/authorize`, `/token`, `/introspect`, `/revoke`, `/.well-known/openid-configuration`).

L'état intermédiaire actuel (modèles présents, endpoints absents) est piégeux pour les utilisateurs.

### 11.6 JWT / sessions
Aucun support natif aujourd'hui. Demandes les plus probables des early adopters. Prévoir un `JWTAuthenticationProvider` + un `SessionFilter` (cookie + store).

### 11.7 Erreurs HTTP
Centraliser le mapping `error → status code` (ex: `errors.As` sur des types sentinelles `*UnauthorizedError`, `*ForbiddenError`, etc.) au lieu de `http.Error(w, "Access denied", 401)` codé en dur dans chaque middleware. Améliore la DX (handlers d'erreurs custom, formats JSON…).

### 11.8 DX / packaging
- Fournir des **presets** : `security.New().WithBasic().WithBearer().WithOAuth2(...).Build()` pour réduire la boilerplate.
- Documenter avec un cookbook (`docs/`) plutôt que de viser un manuel de référence.
- Mettre à jour l'exemple (cassé aujourd'hui) — c'est la première chose que les évaluateurs regardent.

### 11.9 Hygiène
- Corriger la typo `"deocde http basic auth failed"`.
- `_ = storageProvider.SaveClient(...)` dans l'exemple (errcheck).
- Ajouter un *contract test* `var _ Provider = (*…)(nil)` partout (déjà fait sur OAuth2).
- Renommer `nolint:forcetypeassert` en assertions safe quand c'est trivial.

---

## 12. TL;DR pour le lead

> Une base saine, conceptuellement alignée avec Spring Security (Filter Chain + Provider + Authorization), implémentée idiomatiquement Go (interfaces, context, middlewares `net/http`). **MVP authentification HTTP Basic + Bearer + OAuth2 partiel + RBAC simple opérationnel**, ~7 kLOC, tests présents, CI propre. **Manques structurants** : type-safety du Credential, sémantique `Handler` à figer (bug), abstraction transport pour viser gRPC, OAuth2 flows complets, JWT, storage persistant, et un exemple à jour. Avant d'investir sur de nouvelles features, **stabiliser l'API publique** (Credential, Authentication, Option/Voter) et **mettre l'exemple/doc en cohérence** sont les deux chantiers les plus rentables.

---

*Pointeurs utiles dans le code :*
- Chaîne complète : [authentication/filter_handler.go:14](authentication/filter_handler.go#L14) → [authentication/handler.go:14](authentication/handler.go#L14) → [authorization/authorize_handler.go:14](authorization/authorize_handler.go#L14)
- OAuth2 provider : [authentication/provider/oauth2/oauth2_authentication_provider.go:36](authentication/provider/oauth2/oauth2_authentication_provider.go#L36)
- TODO officiel : [TODO.md](TODO.md)
- Exemple obsolète : [example/oauth2/main.go](example/oauth2/main.go)
