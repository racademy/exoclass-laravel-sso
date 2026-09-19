<?php

declare(strict_types=1);

namespace ExoClass\Sso\Support;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Support\Facades\Config;

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
 * In `bootstrap/app.php`:
 *
 *     ->withMiddleware(function (Middleware $middleware) {
 *         $middleware->encryptCookies(except: CookieExemptions::names());
 *     })
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
        $config ??= Config::getFacadeRoot();

        $names = [
            $config->get('exoclass-sso.session_cookie_name'),
            $config->get('exoclass-sso.xsrf_cookie_name'),
        ];

        return array_values(array_filter(
            array_map(static fn (mixed $name): string => is_string($name) ? trim($name) : '', $names),
            static fn (string $name): bool => $name !== '',
        ));
    }
}
