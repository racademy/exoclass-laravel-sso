<?php

declare(strict_types=1);
use ExoClass\Sso\Http\RequestClassifier;

/*
|--------------------------------------------------------------------------
| ExoClass session SSO
|--------------------------------------------------------------------------
|
| Auto-login from an existing ExoClass Laravel-Sanctum session shared on
| `.exoclass.com`. The host app reads the ExoClass session cookie and this
| package validates it SERVER-SIDE via `GET {api_url}/{locale}/users/current`.
| The cookie is never decrypted locally — only ExoClass's verdict counts.
|
| Cookie and XSRF names are PER ENVIRONMENT (they mirror ExoClass's own
| `SESSION_COOKIE` / `SESSION_XSRF_COOKIE_NAME`), so they are configuration and
| never constants:
|
|   prod     exoclass_session        / EXO-XSRF-TOKEN
|   staging  sta_exoclass_session    / STA-XSRF-TOKEN
|   local    local_exoclass_session  / LOCAL-XSRF-TOKEN
|
*/

return [

    /*
    | Master switch. Ships FALSE in every environment: flip it only after the
    | live verification gate (ExoClass must list this app's bare host in
    | SANCTUM_STATEFUL_DOMAINS and CORS_ALLOWED_ORIGINS first).
    */
    'enabled' => (bool) env('EXOCLASS_SSO_ENABLED', false),

    /*
    | ExoClass API root, WITHOUT the locale segment. Paths are built as
    | `{api_url}/{locale}/users/current`.
    */
    'api_url' => env('EXOCLASS_SSO_API_URL', 'https://api.exoclass.com/api/v1'),

    'locale' => env('EXOCLASS_SSO_LOCALE', 'lt'),

    'session_cookie_name' => env('EXOCLASS_SSO_SESSION_COOKIE_NAME', 'exoclass_session'),

    'xsrf_cookie_name' => env('EXOCLASS_SSO_XSRF_COOKIE_NAME', 'EXO-XSRF-TOKEN'),

    /*
    | The bare origin (scheme + host, NO path, NO trailing slash) sent as both
    | `Referer` and `Origin` on every forwarded call. Laravel's HTTP client
    | sends no Referer of its own, and without one ExoClass's
    | `EnsureFrontendRequestsAreStateful` classifies the call as stateless and
    | answers 401 (RA Portal finding H-3). ExoClass must list this exact bare
    | host in SANCTUM_STATEFUL_DOMAINS.
    */
    'stateful_referer' => (static function (): string {
        $explicit = env('EXOCLASS_SSO_STATEFUL_REFERER');

        if (is_string($explicit) && trim($explicit) !== '') {
            return rtrim(trim($explicit), '/');
        }

        $appUrl = env('APP_URL', 'http://localhost');
        $appUrl = is_string($appUrl) && trim($appUrl) !== '' ? trim($appUrl) : 'http://localhost';

        $scheme = parse_url($appUrl, PHP_URL_SCHEME);
        $host = parse_url($appUrl, PHP_URL_HOST);
        $port = parse_url($appUrl, PHP_URL_PORT);

        if (! is_string($scheme) || ! is_string($host)) {
            return rtrim($appUrl, '/');
        }

        return $scheme.'://'.$host.(is_int($port) ? ':'.$port : '');
    })(),

    /*
    | Seconds a FAILED guest probe is remembered, so a visitor without an
    | ExoClass session cannot make every page view hit the upstream.
    */
    'probe_ttl' => (int) env('EXOCLASS_SSO_PROBE_TTL', 120),

    /*
    | Seconds between liveness re-validations of an SSO session whose cookie
    | value has not changed. A changed cookie value re-validates immediately.
    */
    'liveness_ttl' => (int) env('EXOCLASS_SSO_LIVENESS_TTL', 600),

    /*
    | Minutes the post-logout suppression cookie lives, so a global logout is
    | not undone by an instant auto re-SSO on the very next request.
    */
    'suppress_minutes' => (int) env('EXOCLASS_SSO_SUPPRESS_MINUTES', 5),

    /*
    | Latency policy for the INTERACTIVE probe: a cold guest page must never
    | block on a flaky upstream, so one attempt and a hard timeout — not the
    | background 3x backoff.
    */
    'probe_timeout_ms' => (int) env('EXOCLASS_SSO_PROBE_TIMEOUT_MS', 1500),

    'probe_retry_times' => (int) env('EXOCLASS_SSO_PROBE_RETRY_TIMES', 1),

    /*
    | Where the "Sign in with ExoClass" button sends a guest.
    */
    'login_url' => env('EXOCLASS_SSO_LOGIN_URL', 'https://exoclass.com/lt/login'),

    /*
    | Query parameter the ExoClass UI honours to come back here after login.
    | NULL until the ExoClass UI ships it — with null the button sends a plain
    | login URL and the user returns manually.
    */
    'login_redirect_param' => env('EXOCLASS_SSO_LOGIN_REDIRECT_PARAM'),

    /*
    | Named route of the host app's organization picker, used when the resolver
    | answers ChoiceRequired. NULL until the host app registers one.
    */
    'choice_route' => env('EXOCLASS_SSO_CHOICE_ROUTE'),

    /*
    | The domain the ExoClass session cookie lives on. Used ONLY to delete that
    | cookie from the browser on a global logout: a `Cookie::forget` with the
    | wrong domain silently deletes nothing, because the browser matches the
    | deletion cookie against the domain the original was set on.
    */
    'cookie_domain' => env('EXOCLASS_SSO_COOKIE_DOMAIN', '.exoclass.com'),

    /*
    | Requests that may never cost an upstream call — assets, machine endpoints
    | and Livewire round trips. Setting this REPLACES the defaults in
    | RequestClassifier::DEFAULT_IGNORED_PATHS rather than adding to them, so an
    | operator who narrows the list can see exactly what is exempt.
    */
    'ignore_paths' => RequestClassifier::DEFAULT_IGNORED_PATHS,

    /*
    | View rendered with HTTP 403 when the app's resolver denies a visitor who
    | IS signed into ExoClass. Null falls back to the host app's own 403 page.
    | The view receives `reason`, the resolver's operator-facing string — which
    | is why it is short, stable and free of anything secret.
    */
    'denied_view' => env('EXOCLASS_SSO_DENIED_VIEW'),

    /*
    | Where to send a visitor whose SSO session was just torn down (ExoClass
    | logged them out upstream). A route name or a URL; null redirects them back
    | to the page they asked for, and lets the app's own auth middleware decide
    | whether that page needs a login.
    */
    'local_login_route' => env('EXOCLASS_SSO_LOCAL_LOGIN_ROUTE'),

];
