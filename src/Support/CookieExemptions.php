<?php

declare(strict_types=1);

namespace ExoClass\Sso\Support;

use ExoClass\Sso\ExoClassSsoServiceProvider;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Support\Env;
use Illuminate\Support\Facades\Config;
use Throwable;

/**
 * The cookies the host app must tell Laravel not to touch.
 *
 * This is the single most common way an integration fails silently, and the
 * failure mode gives you nothing to go on. `EncryptCookies` tries to decrypt
 * every cookie on every request. The ExoClass cookies were signed by ExoClass
 * with ExoClass's key, so decryption fails — and Laravel's answer to a cookie
 * it cannot decrypt is to replace it with NULL and carry on. No exception, no
 * log line. `$request->cookie('exoclass_session')` simply returns null forever,
 * SSO never fires, and everything else about the app looks perfectly healthy.
 *
 * The package registers the exemption itself, from
 * {@see ExoClassSsoServiceProvider::boot()}, so no integrator can
 * forget it. This helper stays public for an app that keeps one explicit list
 * of its own:
 *
 *     ->withMiddleware(function (Middleware $middleware) {
 *         $middleware->encryptCookies(except: CookieExemptions::names());
 *     })
 *
 * That closure runs BEFORE the framework loads configuration or registers
 * facades, so this must survive a container with no `config` in it at all —
 * hence the env fallback below. Reading config unconditionally there does not
 * fail softly: it fatals the whole app before the first request.
 *
 * Both names are per environment, so they are read from config rather than
 * hard-coded — a literal here would work in production and quietly disable SSO
 * on staging.
 *
 * Our OWN cookies are not in this list and must not be: Laravel signs and reads
 * the suppression cookie itself, and exempting it would let a visitor forge one.
 */
final class CookieExemptions
{
    /**
     * @return list<string>
     */
    public static function names(?Repository $config = null): array
    {
        $config ??= self::repository();

        $names = $config instanceof Repository
            ? [
                $config->get('exoclass-sso.session_cookie_name'),
                $config->get('exoclass-sso.xsrf_cookie_name'),
            ]
            : [
                // No config repository yet, so the environment is all there is.
                // Under `config:cache` Laravel does not even load `.env`, and
                // these fall back to the production defaults — which is the
                // second reason the provider registers the real, config-derived
                // names itself rather than leaving this to a boot-time closure.
                Env::get('EXOCLASS_SSO_SESSION_COOKIE_NAME', 'exoclass_session'),
                Env::get('EXOCLASS_SSO_XSRF_COOKIE_NAME', 'EXO-XSRF-TOKEN'),
            ];

        return array_values(array_filter(
            array_map(static fn (mixed $name): string => is_string($name) ? trim($name) : '', $names),
            static fn (string $name): bool => $name !== '',
        ));
    }

    /**
     * The config repository, or null when there is not one yet — which is the
     * normal state inside `withMiddleware()`, not an error.
     */
    private static function repository(): ?Repository
    {
        try {
            $config = Config::getFacadeRoot();
        } catch (Throwable) {
            return null;
        }

        return $config instanceof Repository ? $config : null;
    }
}
