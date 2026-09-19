<?php

declare(strict_types=1);

namespace ExoClass\Sso\Http;

use ExoClass\Sso\Support\CookieExemptions;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Http\Request;

/**
 * Lifts the ExoClass credential off an incoming request.
 *
 * The cookie names are read from config on every call rather than cached,
 * because they differ per environment and a cached name is how staging quietly
 * stops doing SSO.
 *
 * If this keeps returning null on a host where the browser demonstrably sends
 * the cookie, the app forgot the encryption exemption: Laravel's
 * `EncryptCookies` tries to decrypt every cookie it sees, fails on a foreign
 * one it did not sign, and hands the request a NULL — the SSO never fires and
 * nothing is logged anywhere. See {@see CookieExemptions}.
 */
final readonly class CredentialReader
{
    public function __construct(private Repository $config) {}

    /**
     * The credential this request carries, or null when the visitor has no
     * ExoClass session cookie at all.
     */
    public function from(Request $request): ?SessionCredential
    {
        $cookieValue = $this->cookie($request, $this->sessionCookieName());

        if ($cookieValue === null) {
            return null;
        }

        return new SessionCredential(
            $this->sessionCookieName(),
            $cookieValue,
            $this->xsrfToken($request),
        );
    }

    /**
     * The XSRF token paired with the session cookie, needed for the
     * state-changing upstream logout and for nothing else.
     */
    public function xsrfToken(Request $request): ?string
    {
        return $this->cookie($request, $this->xsrfCookieName());
    }

    public function sessionCookieName(): string
    {
        $name = trim((string) $this->config->get('exoclass-sso.session_cookie_name', ''));

        return $name === '' ? 'exoclass_session' : $name;
    }

    public function xsrfCookieName(): string
    {
        $name = trim((string) $this->config->get('exoclass-sso.xsrf_cookie_name', ''));

        return $name === '' ? 'EXO-XSRF-TOKEN' : $name;
    }

    private function cookie(Request $request, string $name): ?string
    {
        $value = $request->cookie($name);

        return is_string($value) && trim($value) !== '' ? $value : null;
    }
}
