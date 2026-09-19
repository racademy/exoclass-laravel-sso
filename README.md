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

Status: **v0.1.0** — configuration, transport, identity, contracts, middleware,
global logout, the choice flow and the test kit. ExoSend is the first consumer;
ExoSign and RA Portal follow.

## What it does and does not do

| The package | Your app |
| --- | --- |
| Forwards the cookie to `users/current` with the headers ExoClass insists on | Implements `IdentityResolver` |
| Distinguishes "no session" from "we could not ask" | Decides which local account an identity maps to |
| Parses the answer into `ExoClassIdentity` | Creates or refuses local users |
| Fetches the user's role at a given provider | Owns roles, tenancy, and the picker page |
| Keeps the cookie out of every log line | Registers the middleware and the cookie exemption |
| Decides when to ask, and when not to | Renders the picker and the refusal page |
| Ends the ExoClass session on logout | Performs its own local sign-out |

The package never touches your user table, your roles or your tenancy. It has no
migrations and no Filament, Livewire or Eloquent dependency.

## Integrating a new subsystem

Ten steps. Step 5 is the one that fails silently if you get it wrong, step 4 is
the one that used to and no longer can, and step 10 is the one that keeps a
broken integration off production.

### 1. Install

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
```

Until `v0.1.0` is tagged there is no version to resolve, so the first consumers
track the branch:

```bash
composer require racademy/exoclass-laravel-sso:dev-main
```

### 2. Publish the config

```bash
php artisan vendor:publish --tag=exoclass-sso-config
```

### 3. Set the environment

Every key is `EXOCLASS_SSO_*`, and **`ENABLED` stays `false`** until step 10
passes. The cookie names differ per ExoClass environment — this is the row that
makes a copied `.env` work in production and quietly do nothing on staging.

| Variable | production | staging | local |
| --- | --- | --- | --- |
| `EXOCLASS_SSO_ENABLED` | `false` → `true` after the gate | same | `false` |
| `EXOCLASS_SSO_API_URL` | `https://api.exoclass.com/api/v1` | the staging API host, from ExoClass ops | your local ExoClass |
| `EXOCLASS_SSO_SESSION_COOKIE_NAME` | `exoclass_session` | `sta_exoclass_session` | `local_exoclass_session` |
| `EXOCLASS_SSO_XSRF_COOKIE_NAME` | `EXO-XSRF-TOKEN` | `STA-XSRF-TOKEN` | `LOCAL-XSRF-TOKEN` |
| `EXOCLASS_SSO_STATEFUL_REFERER` | `https://send.exoclass.com` | your staging host | your local host |
| `EXOCLASS_SSO_COOKIE_DOMAIN` | `.exoclass.com` | `.exoclass.com` | your shared local domain |
| `EXOCLASS_SSO_CHOICE_ROUTE` | your picker route name | same | same |

### 4. Exempt the cookies from encryption — already done for you

`EncryptCookies` tries to decrypt every cookie; the ExoClass ones were signed
with ExoClass's key, so decryption fails, and Laravel's answer to a cookie it
cannot decrypt is to replace it with `null`. No exception, no log line —
`$request->cookie(...)` simply returns null forever, and the integration looks
perfectly healthy while doing nothing.

That is too quiet a failure to leave to a checklist, so the package registers
the exemption itself, from its service provider, using the cookie names your
config actually has:

```php
// ExoClassSsoServiceProvider::boot()
EncryptCookies::except(CookieExemptions::names($config));
```

**There is nothing to add to `bootstrap/app.php`.** If your app keeps one
explicit list of exempt cookies anyway, `CookieExemptions::names()` returns the
two names and is safe to call from inside `withMiddleware()` — that closure runs
before the framework loads configuration, so the helper falls back to the
environment there rather than fataling the app (an earlier version of it read
config unconditionally and took the whole app down at boot).

Do not add the package's own `exoclass_sso_suppressed` cookie to any exemption
list: Laravel signs and reads it, and exempting it would let a visitor forge one.

### 5. Register the middleware, in the right place

It must run **after** the session has started and cookies have been decrypted,
and **before** your auth guard redirects a guest. Put it in the group, not in
the auth chain — the login page itself has to be able to sign somebody in.

```php
// A Filament panel: ->middleware(), NOT ->authMiddleware().
// authMiddleware only runs on already-authenticated requests, so SSO would
// never fire for the guest it exists to sign in.
$panel
    ->middleware([
        EncryptCookies::class,
        AddQueuedCookiesToResponse::class,
        StartSession::class,
        AuthenticateSession::class,
        ShareErrorsFromSession::class,
        VerifyCsrfToken::class,
        SubstituteBindings::class,
        DisableBladeIconComponents::class,
        DispatchServingFilamentEvent::class,
        'exoclass-sso',
    ])
```

```php
// A plain Laravel app: append it to the web group.
->withMiddleware(function (Middleware $middleware) {
    $middleware->appendToGroup('web', ExoClassSessionAuthenticate::class);
})
```

Never register it on `/api/*`. API clients carry tokens, not browser sessions,
and the classifier skips them anyway — but a token route has no business
depending on this.

### 6. Implement `IdentityResolver` and bind it

The package deliberately leaves this contract unbound, so an app that forgets
it fails loudly rather than quietly resolving nobody.

```php
// AppServiceProvider::register()
$this->app->bind(IdentityResolver::class, ExoSendIdentityResolver::class);
```

See [The contract](#the-contract) below for what it has to do.

### 7. Add a choice route, if a visitor can map to more than one thing

When the resolver answers `ChoiceRequired`, the middleware stashes the
candidates and redirects to `exoclass-sso.choice_route`. The page renders them
and posts the key back to `CompleteChoice`:

```php
Route::get('/choose-organization', function () {
    return view('sso.choose', ['candidates' => SsoSession::candidates(session())]);
})->name('sso.choose');

Route::post('/choose-organization', function (Request $request, CompleteChoice $choice) {
    $resolution = $choice->handle($request, (string) $request->input('key'));

    if ($resolution instanceof Authenticated) {
        return redirect()->to(SsoSession::pullIntendedUrl(session()) ?? '/admin');
    }

    return back()->withErrors(['key' => __('That organization is not available to you.')]);
})->name('sso.choose.submit');
```

With no `choice_route` configured the middleware logs an error and falls
through to the password form — a visitor who could have had a choice gets the
login page instead of a redirect loop.

### 8. Bind the logout

A session established by SSO logs out **globally**; a password session logs out
locally, exactly as before.

```php
final class LogoutController
{
    public function __invoke(Request $request, GlobalLogout $globalLogout): RedirectResponse
    {
        if (SsoSession::isSso($request->session())) {
            $globalLogout->handle($request);
        }

        Auth::logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return redirect()->route('login');
    }
}
```

`GlobalLogout` never throws and never blocks the local sign-out. In Filament,
bind your controller over `Filament\Auth\Http\Controllers\LogoutController`, or
bind a custom `LogoutResponse`.

### 9. Write the three tests

Every consumer owes these three, and the kit makes each of them short.

```php
use ExoClass\Sso\Testing\ExoClassSsoFake;

it('signs an ExoClass provider admin straight in', function () {
    $sso = ExoClassSsoFake::fake()->scoped($providerKey);
    Organization::factory()->create(['exoclass_provider_id' => '1042']);

    $sso->withExoClassCookie($this, 'any-value')->get('/admin')->assertOk();

    $sso->assertProbed();
    expect(auth()->user()->email)->toBe('mentorius@robotikosakademija.lt');
});

it('refuses an ExoClass user with no organization here, and keeps their ExoClass session', function () {
    $sso = ExoClassSsoFake::fake();   // no organization seeded

    $response = $sso->withExoClassCookie($this, 'any-value')->get('/admin')->assertForbidden();

    expect($response->headers->getCookies())->not->toContain(/* the ExoClass cookie */);
});

it('ends the ExoClass session when a SSO user logs out', function () {
    $sso = ExoClassSsoFake::fake()->logoutOk();

    $sso->withExoClassCookie($this, 'any-value', 'an-xsrf-token')
        ->actingAs($user)
        ->withSession([SsoSession::AUTHENTICATED => true])
        ->post('/logout');

    $sso->assertLogoutForwardedWithXsrf('an-xsrf-token');
});
```

Add a fourth if you can: one test **without** `withExoClassCookie` that sets the
cookie by hand, proving the exemption is live in your app's real middleware
stack. The helper applies it for you, which is convenient and hides step 4.

### 10. Probe live before flipping the flag

ExoClass must list your bare host in `SANCTUM_STATEFUL_DOMAINS` **and**
`CORS_ALLOWED_ORIGINS`, and be `config:cache`d, or every call comes back 401
with a perfectly valid cookie. Prove it from the host itself, with a real
browser cookie:

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
  -H "Cookie: sta_exoclass_session=<value from a browser>" \
  -H "Referer: https://<this app's host>" \
  -H "Origin: https://<this app's host>" \
  -H "Accept: application/json" \
  https://<exoclass staging api>/api/v1/lt/users/current
```

`200` → flip `EXOCLASS_SSO_ENABLED=true` on that environment.
`401` → the host is not stateful upstream yet. Nothing in this package can fix
that, and turning the flag on will not help.


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
| `probe_timeout_ms` | `1500` | Hard ceiling on the interactive probe, honoured to the millisecond (not rounded up to a second). |
| `probe_retry_times` | `1` | Attempts, not re-tries. A 401 is never retried. |
| `login_url` | `https://exoclass.com/lt/login` | Where the "Sign in with ExoClass" button goes. |
| `login_redirect_param` | `null` | Set to `redirect` once the ExoClass UI honours a return URL. |
| `choice_route` | `null` | Your app's picker route, used when a resolver answers `ChoiceRequired`. |
| `cookie_domain` | `.exoclass.com` | The domain the shared cookie lives on, used to delete it on a global logout. A wrong domain deletes nothing. |
| `ignore_paths` | the classifier's defaults | Paths that may never cost an upstream call. Setting it **replaces** the defaults. |
| `denied_view` | `null` | View rendered with 403 when the resolver refuses. Null uses your app's own 403 page. |
| `local_login_route` | `null` | Where to send a visitor whose SSO session was just torn down. Null sends them back to the page they asked for. |

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
$identity->providerInfo;                                 // who the answer was about, or null
```

**The scoped answer is verified, not assumed.** ExoClass does not reject an
`X-Provider-Key` it cannot resolve: `UserController::currentUser` throws away
the result of `resolveIdFromExternalKey()` and falls through to the unfiltered
branch, answering **200 with every employer and the union of the user's roles
across all of them**. A stale key, a re-keyed or deleted provider, a staging key
sent at a production `api_url`, or a numeric employer id passed where the uuid
belongs would each turn `hasRoleAt()` into a *yes* for a provider the user has
no relationship with.

So `rolesFor()` believes a role list only when the answer's own `provider_info`
names the provider that was asked about, and throws
`MalformedResponseException` otherwise. Likewise a blank provider key is
refused outright — dropping the header would silently ask the unscoped
question. Asking unscoped must be an explicit `null`.

## When the middleware asks, and what it does with the answer

The whole policy is one table, and every row of it has a test.

| Situation | What happens |
| --- | --- |
| flag off, or not a navigation | through, nothing asked |
| guest, no ExoClass cookie | through, nothing asked |
| guest, suppression cookie from a logout | through, nothing asked |
| guest, a probe already failed this window | through, nothing asked |
| guest, upstream 401 | mark the probe, through |
| guest, upstream unreachable or unparseable | warn, through — the login page must render |
| guest, resolver throws | log, through — never take the page down |
| guest, `Authenticated` | sign in, continue where they were going |
| guest, `ChoiceRequired` | stash candidates, redirect to the picker |
| guest, `Denied` | 403, ExoClass cookie left intact, mark the probe |
| signed in with a password | nothing, ever |
| SSO session, cookie unchanged and fresh | nothing, no call |
| SSO session, cookie changed | re-validate now |
| SSO session, liveness window closed | re-validate |
| re-validation: 401 or cookie gone | local sign-out, redirect |
| re-validation: somebody else is signed into ExoClass | re-resolve: sign in as them, or sign out |
| re-validation: upstream unreachable | keep the session, back off |

**Only a request that will render a page may cost an upstream call.** One
navigation drags dozens of asset, Livewire and XHR requests behind it, and a
probe on each of them would turn every page view into dozens of `users/current`
calls — for a signed-out visitor, forever, on a public page. `RequestClassifier`
is that rule; `ignore_paths` is how you extend it.

**Only a 401 is a verdict.** A timeout is not a logout. An ExoClass outage
leaves the login page rendering and every established session intact.

**An established session is re-validated on a hybrid trigger.** A changed cookie
value is the fast signal — ExoClass rotates it on its own logout and on an
account switch, so the change is caught on the next navigation. The
`liveness_ttl` is the backstop for the opposite case: a server-side ExoClass
logout while the visitor only browses here, so the browser is never handed a new
cookie and the value never changes. Neither path ever tears a session down on a
value difference alone — only an authoritative 401, a vanished cookie, or a
different person upstream does that.

**The session never holds the cookie.** Only a SHA-256 fingerprint of it, which
answers "same cookie as last time?" and nothing else.

## Logout

A session established by SSO logs out globally (`GlobalLogout`); a password
session logs out locally. The action ends the upstream session, then does three
things that must happen even when that call fails:

1. queue the suppression cookie, so the logout sticks;
2. clear the SSO session keys;
3. delete the shared cookie on its configured domain.

The suppression cookie is the load-bearing step. Destroy the session and the
browser still carries the `.exoclass.com` cookie — because the upstream logout
soft-failed, or because the deletion has not reached the browser yet — and the
very next request would sign the visitor straight back in. They click "log out"
and stay logged in, with no way to tell why. It is a cookie rather than a
session key precisely because logout invalidates the session.


## Failure modes

Only one of them is a verdict:

| Exception | Means | What a caller must do |
| --- | --- | --- |
| `UnauthorizedException` | ExoClass said 401 | Treat the visitor as a guest. Authoritative. |
| `UnavailableException` | timeout, 5xx, connection error, any other status | Fail soft: render the login page, keep existing sessions, never log anyone out. |
| `MalformedResponseException` | 2xx with a body we cannot trust | Same as unavailable, plus a loud log line — the contract has drifted. |

"We could not ask" is never "the session is dead". An ExoClass outage must not
sign your users out.

## Testing your integration

`ExoClassSsoFake` installs an HTTP fake shaped like ExoClass and gives you the
assertions worth making.

| Call | Stages |
| --- | --- |
| `ExoClassSsoFake::fake()` | installs the fake, answering with the packaged unscoped fixture |
| `->unscoped($payload)` | the identity body |
| `->scoped($providerKey, $payload = null)` | the roles held at that provider |
| `->unauthorized()` | 401 — the one authoritative answer |
| `->unavailable($status = 503)` | an answer with nothing usable in it |
| `->unreachable()` | a timeout or dropped connection |
| `->malformed()` | a 200 the package cannot trust |
| `->logoutOk()` / `->logoutFails()` | how `auth/logout` answers |
| `->withExoClassCookie($this, $value, $xsrf = null)` | gives the next request the cookie, and applies the exemption |
| `->assertProbed($times = 1)` | the identity was asked for exactly that often |
| `->assertNotProbed()` | nothing was asked at all |
| `->assertLogoutForwardedWithXsrf($xsrf = null)` | the logout carried the token ExoClass's CSRF gate demands |
| `->assertNothingLeaked($logPath)` | no credential it handed out reached the log |

A provider key the fake does not know answers with the **unscoped** body,
because that is what ExoClass does with a key it cannot resolve. A stricter fake
would let your tests pass while production granted access nobody granted.


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

The unscoped fixture deliberately carries a `provider_info` block filled with
nulls, because that is what upstream emits when it scoped the answer to nobody
— and an unresolvable `X-Provider-Key` produces exactly that body. It is the
only thing distinguishing it from a genuinely scoped answer, which is why the
package refuses it.

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
