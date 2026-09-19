<?php

declare(strict_types=1);

use ExoClass\Sso\Contracts\IdentityFetcher;
use ExoClass\Sso\Contracts\IdentityResolver;
use ExoClass\Sso\ExoClassSsoServiceProvider;
use ExoClass\Sso\Http\ExoClassSessionClient;
use ExoClass\Sso\Http\Middleware\ExoClassSessionAuthenticate;
use ExoClass\Sso\Http\RequestClassifier;
use ExoClass\Sso\Identity\UsersCurrentIdentityFetcher;
use ExoClass\Sso\Resolution\Authenticated;
use ExoClass\Sso\Support\CookieExemptions;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Facade;
use Illuminate\Support\Facades\Http;

/**
 * Re-evaluate the shipped config file with a given environment, the way a host
 * app's `config:cache` would.
 *
 * @param  array<string, string>  $env
 * @return array<string, mixed>
 */
function configWithEnv(array $env = []): array
{
    foreach ($env as $key => $value) {
        $_ENV[$key] = $_SERVER[$key] = $value;
        putenv("{$key}={$value}");
    }

    try {
        /** @var array<string, mixed> $config */
        $config = require __DIR__.'/../../config/exoclass-sso.php';

        return $config;
    } finally {
        foreach (array_keys($env) as $key) {
            unset($_ENV[$key], $_SERVER[$key]);
            putenv($key);
        }
    }
}

it('ships exactly the agreed key set, no more and no less', function () {
    expect(array_keys(configWithEnv()))->toBe([
        'enabled',
        'api_url',
        'locale',
        'session_cookie_name',
        'xsrf_cookie_name',
        'stateful_referer',
        'probe_ttl',
        'liveness_ttl',
        'suppress_minutes',
        'probe_timeout_ms',
        'probe_retry_times',
        'login_url',
        'login_redirect_param',
        'choice_route',
        'cookie_domain',
        'ignore_paths',
        'denied_view',
        'local_login_route',
    ]);
});

it('ships dark, with the agreed defaults', function () {
    $config = configWithEnv();

    expect($config['enabled'])->toBeFalse()
        ->and($config['api_url'])->toBe('https://api.exoclass.com/api/v1')
        ->and($config['locale'])->toBe('lt')
        ->and($config['session_cookie_name'])->toBe('exoclass_session')
        ->and($config['xsrf_cookie_name'])->toBe('EXO-XSRF-TOKEN')
        ->and($config['probe_ttl'])->toBe(120)
        ->and($config['liveness_ttl'])->toBe(600)
        ->and($config['suppress_minutes'])->toBe(5)
        ->and($config['probe_timeout_ms'])->toBe(1500)
        ->and($config['probe_retry_times'])->toBe(1)
        ->and($config['login_url'])->toBe('https://exoclass.com/lt/login')
        ->and($config['login_redirect_param'])->toBeNull()
        ->and($config['choice_route'])->toBeNull()
        ->and($config['cookie_domain'])->toBe('.exoclass.com')
        ->and($config['ignore_paths'])->toBe(RequestClassifier::DEFAULT_IGNORED_PATHS)
        ->and($config['denied_view'])->toBeNull()
        ->and($config['local_login_route'])->toBeNull();
});

it('derives the stateful referer as the BARE origin of APP_URL', function (string $appUrl, string $expected) {
    expect(configWithEnv(['APP_URL' => $appUrl])['stateful_referer'])->toBe($expected);
})->with([
    'plain host' => ['https://send.exoclass.com', 'https://send.exoclass.com'],
    'trailing slash' => ['https://send.exoclass.com/', 'https://send.exoclass.com'],
    'with a path' => ['https://send.exoclass.com/admin/login', 'https://send.exoclass.com'],
    'with a port' => ['http://localhost:8080', 'http://localhost:8080'],
]);

it('lets an explicit stateful referer override APP_URL', function () {
    $config = configWithEnv([
        'APP_URL' => 'https://send.exoclass.com',
        'EXOCLASS_SSO_STATEFUL_REFERER' => 'https://proxy.exoclass.com/',
    ]);

    expect($config['stateful_referer'])->toBe('https://proxy.exoclass.com');
});

it('reads every knob from an EXOCLASS_SSO_ prefixed variable', function () {
    $config = configWithEnv([
        'EXOCLASS_SSO_ENABLED' => 'true',
        'EXOCLASS_SSO_API_URL' => 'https://sta-api.exoclass.com/api/v1',
        'EXOCLASS_SSO_LOCALE' => 'en',
        'EXOCLASS_SSO_SESSION_COOKIE_NAME' => 'sta_exoclass_session',
        'EXOCLASS_SSO_XSRF_COOKIE_NAME' => 'STA-XSRF-TOKEN',
        'EXOCLASS_SSO_PROBE_TTL' => '30',
        'EXOCLASS_SSO_LIVENESS_TTL' => '90',
        'EXOCLASS_SSO_SUPPRESS_MINUTES' => '10',
        'EXOCLASS_SSO_PROBE_TIMEOUT_MS' => '900',
        'EXOCLASS_SSO_PROBE_RETRY_TIMES' => '2',
        'EXOCLASS_SSO_LOGIN_URL' => 'https://sta.exoclass.com/lt/login',
        'EXOCLASS_SSO_LOGIN_REDIRECT_PARAM' => 'redirect',
        'EXOCLASS_SSO_CHOICE_ROUTE' => 'filament.admin.auth.organization',
    ]);

    expect($config['enabled'])->toBeTrue()
        ->and($config['api_url'])->toBe('https://sta-api.exoclass.com/api/v1')
        ->and($config['locale'])->toBe('en')
        ->and($config['session_cookie_name'])->toBe('sta_exoclass_session')
        ->and($config['xsrf_cookie_name'])->toBe('STA-XSRF-TOKEN')
        ->and($config['probe_ttl'])->toBe(30)
        ->and($config['liveness_ttl'])->toBe(90)
        ->and($config['suppress_minutes'])->toBe(10)
        ->and($config['probe_timeout_ms'])->toBe(900)
        ->and($config['probe_retry_times'])->toBe(2)
        ->and($config['login_url'])->toBe('https://sta.exoclass.com/lt/login')
        ->and($config['login_redirect_param'])->toBe('redirect')
        ->and($config['choice_route'])->toBe('filament.admin.auth.organization');
});

it('merges the config into the host app and offers it for publishing', function () {
    expect(config('exoclass-sso.probe_ttl'))->toBe(120);

    $published = ExoClassSsoServiceProvider::pathsToPublish(ExoClassSsoServiceProvider::class, 'exoclass-sso-config');

    expect($published)->toHaveCount(1)
        ->and(array_key_first($published))->toEndWith('config/exoclass-sso.php')
        ->and(reset($published))->toEndWith('config/exoclass-sso.php');
});

it('registers a middleware alias, so wiring a panel reads like wiring a panel', function () {
    $router = app(Router::class);

    expect($router->getMiddleware())->toHaveKey('exoclass-sso')
        ->and($router->getMiddleware()['exoclass-sso'])->toBe(ExoClassSessionAuthenticate::class);
});

it('binds the transport and the default fetcher, but never the app-owned resolver', function () {
    expect(app(ExoClassSessionClient::class))->toBeInstanceOf(ExoClassSessionClient::class)
        ->and(app(ExoClassSessionClient::class))->toBe(app(ExoClassSessionClient::class))
        ->and(app(IdentityFetcher::class))->toBeInstanceOf(UsersCurrentIdentityFetcher::class)
        ->and(app()->bound(IdentityResolver::class))->toBeFalse();
});

it('exempts the ExoClass cookies from encryption without the host app remembering to', function () {
    // Nothing called EncryptCookies::except() here. The package did it at boot,
    // because this is the step that fails silently when an integrator skips it.
    Http::fake(['*users/current' => Http::response(identityPayload())]);
    ssoResolver()->answerWith(fn () => new Authenticated(ssoUser(7)));

    harness()
        ->withUnencryptedCookies(['sta_exoclass_session' => 'RAW-EXOCLASS-COOKIE-VALUE-7f3a'])
        ->get('/dashboard')
        ->assertOk()
        ->assertSee('dashboard for 7');
});

it('names the cookies before the app has a config repository at all', function () {
    // `bootstrap/app.php`'s withMiddleware() closure runs inside an
    // afterResolving(Kernel::class) callback — BEFORE LoadConfiguration and
    // RegisterFacades. A README step that reads config there takes the whole
    // app down with "Target class [config] does not exist".
    $application = Facade::getFacadeApplication();
    Facade::clearResolvedInstances();
    Facade::setFacadeApplication(null);

    try {
        expect(CookieExemptions::names())->toBe(['exoclass_session', 'EXO-XSRF-TOKEN']);
    } finally {
        Facade::setFacadeApplication($application);
    }
});
