# exoclass-laravel-sso

Sign a visitor into a Laravel subsystem using the ExoClass session they already
have.

ExoClass sets a Laravel Sanctum session cookie on `.exoclass.com`. Every
subsystem under that domain — ExoSend, ExoSign, RA Portal — can therefore see
that cookie, but none of them can read it: it is encrypted by ExoClass and only
ExoClass can say whether it is still valid and who it belongs to. This package
does the asking, and nothing else. It forwards the cookie to ExoClass, hands
your app a verified identity, and lets your app decide what that identity is
allowed to do locally.

Status: **v0.1 core** — configuration, transport, identity and contracts.
Middleware, global logout and the test kit land in the next task.

## What it does and does not do

| The package | Your app |
| --- | --- |
| Forwards the cookie to `users/current` with the headers ExoClass insists on | Implements `IdentityResolver` |
| Distinguishes "no session" from "we could not ask" | Decides which local account an identity maps to |
| Parses the answer into `ExoClassIdentity` | Creates or refuses local users |
| Fetches the user's role at a given provider | Owns roles, tenancy, and the picker page |
| Keeps the cookie out of every log line | Registers the middleware and the cookie exemption |

The package never touches your user table, your roles or your tenancy. It has no
migrations and no Filament, Livewire or Eloquent dependency.

## Install

The repository is private, so Composer needs the VCS entry:

```json
{
    "repositories": [
        { "type": "vcs", "url": "git@github.com:racademy/exoclass-laravel-sso.git" }
    ]
}
```

```bash
composer require racademy/exoclass-laravel-sso:^0.1
php artisan vendor:publish --tag=exoclass-sso-config
```

## Configuration

Everything is `EXOCLASS_SSO_*` in `.env`, and `enabled` ships **false** in every
environment: turn it on only after ExoClass lists your bare host in
`SANCTUM_STATEFUL_DOMAINS` and `CORS_ALLOWED_ORIGINS`, and after a live probe
from your host has come back 200.

| Key | Default | What it is for |
| --- | --- | --- |
| `enabled` | `false` | Master switch. Off means behaviour identical to no package at all. |
| `api_url` | `https://api.exoclass.com/api/v1` | ExoClass API root, without the locale segment. |
| `locale` | `lt` | Locale segment: `{api_url}/{locale}/users/current`. Overridable per call. |
| `session_cookie_name` | `exoclass_session` | Per environment: `sta_exoclass_session` on staging, `local_exoclass_session` locally. |
| `xsrf_cookie_name` | `EXO-XSRF-TOKEN` | Per environment: `STA-XSRF-TOKEN`, `LOCAL-XSRF-TOKEN`. |
| `stateful_referer` | bare origin of `APP_URL` | Sent as `Referer` **and** `Origin`. Without it ExoClass answers 401 — see below. |
| `probe_ttl` | `120` | Seconds a failed guest probe is remembered, so a signed-out visitor cannot make every page view hit ExoClass. |
| `liveness_ttl` | `600` | Seconds between re-validations of an SSO session whose cookie value has not changed. |
| `suppress_minutes` | `5` | Minutes a global logout suppresses auto re-SSO. |
| `probe_timeout_ms` | `1500` | Hard ceiling on the interactive probe. |
| `probe_retry_times` | `1` | Attempts, not re-tries. A 401 is never retried. |
| `login_url` | `https://exoclass.com/lt/login` | Where the "Sign in with ExoClass" button goes. |
| `login_redirect_param` | `null` | Set to `redirect` once the ExoClass UI honours a return URL. |
| `choice_route` | `null` | Your app's picker route, used when a resolver answers `ChoiceRequired`. |

Two settings are worth dwelling on, because both have already cost a team a day:

**`stateful_referer` is not decoration.** Laravel's HTTP client sends no
`Referer` of its own. Without one, ExoClass's
`EnsureFrontendRequestsAreStateful` decides the forwarded call is stateless,
never consults the session guard, and answers 401 — with a perfectly valid
cookie in hand. The value must be the bare origin (`https://send.exoclass.com`,
no path, no trailing slash) and ExoClass must list that exact host in
`SANCTUM_STATEFUL_DOMAINS`.

**Cookie names are configuration, never constants.** Each ExoClass environment
names its cookies differently. Pin them per environment in `.env`; a constant
here would silently disable SSO on staging.

## The contract

Implement one interface. The package proves who the visitor is; you decide what
that means.

```php
use ExoClass\Sso\Contracts\IdentityResolver;
use ExoClass\Sso\Identity\ExoClassIdentity;
use ExoClass\Sso\Resolution\{Authenticated, Candidate, ChoiceRequired, Denied, Resolution, ResolutionContext};

final class ExoSendIdentityResolver implements IdentityResolver
{
    public function resolve(ExoClassIdentity $identity, ResolutionContext $context): Resolution
    {
        // Employers this app actually knows, and where the user may administer.
        $eligible = collect($identity->employers)
            ->filter(fn ($employer) => Organization::query()
                ->where('exoclass_provider_id', (string) $employer->id)
                ->where('is_active', true)
                ->exists())
            ->filter(fn ($employer) => $identity->hasRoleAt($employer->externalKey, 'provider', 'administrator'))
            ->values();

        return match ($eligible->count()) {
            0 => new Denied('no eligible organization for this ExoClass account'),
            1 => new Authenticated($this->materialize($identity, $eligible->first())),
            default => ChoiceRequired::fromList($eligible
                ->map(fn ($employer) => new Candidate((string) $employer->id, $employer->name))
                ->all()),
        };
    }

    public function resolveChoice(ExoClassIdentity $identity, string $candidateKey): Resolution
    {
        // The key came from a browser. Re-derive the candidates and reject
        // anything that is not in the fresh list — never trust the key alone.
        $resolution = $this->resolve($identity, ResolutionContext::choice());

        if (! $resolution instanceof ChoiceRequired || ! in_array($candidateKey, $resolution->keys(), true)) {
            return new Denied('the chosen organization is not one this account may enter');
        }

        return new Authenticated($this->materializeByProviderId($identity, (int) $candidateKey));
    }
}
```

Three rules for an implementation:

1. **Fail closed.** Anything you cannot positively justify is `Denied`, never
   `Authenticated`.
2. **Re-derive on `resolveChoice()`.** The candidate key arrives from the
   browser; the eligibility check must run again against the live identity.
3. **Be callable twice.** Auto-login, button return and the picker all land in
   the same method, and the outcomes must match.

## Roles, and why there are two calls

Unscoped `users/current` lists every employer but returns a flat `roles[]` with
**no provider attribution** — "is this person an administrator at employer
#1042" is simply not in the answer. `rolesFor($providerExternalKey)` makes the
scoped call (`X-Provider-Key`) that can answer it, and memoizes the result per
identity, so checking three candidates costs three extra round trips and
checking one twice costs one.

```php
$identity = app(IdentityFetcher::class)->fetch(
    new SessionCredential(config('exoclass-sso.session_cookie_name'), $rawCookieValue)
);

$identity->user->email;                                  // who
$identity->employers;                                    // where they work
$identity->rolesFor('c0ffee00-…');                       // what they are, there
$identity->hasRoleAt('c0ffee00-…', 'provider', 'administrator');
```

## Failure modes

Only one of them is a verdict:

| Exception | Means | What a caller must do |
| --- | --- | --- |
| `UnauthorizedException` | ExoClass said 401 | Treat the visitor as a guest. Authoritative. |
| `UnavailableException` | timeout, 5xx, connection error, any other status | Fail soft: render the login page, keep existing sessions, never log anyone out. |
| `MalformedResponseException` | 2xx with a body we cannot trust | Same as unavailable, plus a loud log line — the contract has drifted. |

"We could not ask" is never "the session is dead". An ExoClass outage must not
sign your users out.

## Secrets

The cookie value and the XSRF token never reach a log, an exception message, a
stack trace or a `dd()`. Everything the package logs goes through
`LogSanitizer`, which redacts by header name *and* scrubs the live secret out of
every remaining string — including an upstream error body that reflects the
cookie back at us. `SessionCredential::__debugInfo()` shows the cookie name and
`[redacted]`. There is a test that greps the written log file for the secret and
fails if it finds it; deleting the sanitizer makes it fail.

## Fixtures

`fixtures/users-current-unscoped.json` and `fixtures/users-current-scoped.json`
pin the two answer shapes, and the contract tests parse them. Both are currently
marked `"_source": "synthetic"` — hand-built from ExoClass's own
`UserApiMap` / `ProviderApiMap` / `RoleApiMap`. They are replaced by responses
recorded from ExoClass staging with a real session before the live gate.

## Development

```bash
composer install
vendor/bin/pest
vendor/bin/pint --test
vendor/bin/phpstan analyse --memory-limit=1G
```

CI runs the suite on PHP 8.3 and 8.4 against Laravel 12 and 13.

## Licence

Private and proprietary — see `LICENSE.md`.
