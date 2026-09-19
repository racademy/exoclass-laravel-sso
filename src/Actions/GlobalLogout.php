<?php

declare(strict_types=1);

namespace ExoClass\Sso\Actions;

use ExoClass\Sso\Http\CredentialReader;
use ExoClass\Sso\Http\ExoClassSessionClient;
use ExoClass\Sso\Http\SessionCredential;
use ExoClass\Sso\Session\SsoSession;
use ExoClass\Sso\Session\SuppressionCookie;
use ExoClass\Sso\Support\SsoLogger;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cookie;
use Throwable;

/**
 * Logging out here logs the visitor out of ExoClass (decision D-5).
 *
 * That is the only coherent reading of a shared session: the visitor did not
 * sign into this app, they signed into ExoClass, and a "log out" that left that
 * session alive would put them straight back in on the next click.
 *
 * Four things happen, in an order chosen so that the last three still happen
 * when the first one fails:
 *
 *   1. End the upstream session   — POST auth/logout with the cookie and the
 *                                   browser's paired XSRF token.
 *   2. Suppress re-SSO            — ALWAYS, whatever the upstream said. This is
 *                                   finding H-10 and it is the load-bearing
 *                                   step: a failed upstream logout is exactly
 *                                   the case where the shared cookie survives.
 *   3. Clear the SSO session keys — nothing left that could re-establish it.
 *   4. Delete the shared cookie   — on its own domain, or the browser ignores
 *                                   the deletion entirely.
 *
 * It never throws. A logout that can fail is a logout users cannot trust.
 *
 * The caller still performs its own sign-out (`Auth::logout()`, session
 * invalidation): this action owns the ExoClass half of it and deliberately
 * leaves the app's own auth alone.
 */
final readonly class GlobalLogout
{
    public function __construct(
        private ExoClassSessionClient $client,
        private CredentialReader $credentials,
        private Repository $config,
        private SsoLogger $logger,
    ) {}

    public function handle(Request $request): void
    {
        $credential = $this->credentials->from($request);

        if ($credential !== null) {
            $this->endUpstreamSession($credential);
        }

        // Before anything else can go wrong: the marker that makes the logout
        // stick even if everything above did go wrong.
        SuppressionCookie::queue($this->config);

        SsoSession::clear($request->session());

        Cookie::queue(Cookie::forget(
            $this->credentials->sessionCookieName(),
            '/',
            $this->cookieDomain(),
        ));
    }

    private function endUpstreamSession(SessionCredential $credential): void
    {
        if ($credential->xsrfToken === null) {
            // ExoClass's CSRF gate would refuse the call, so there is nothing to
            // gain by making it — but there is something to say. The usual cause
            // is the XSRF cookie missing from the app's encryption exemptions,
            // and an operator staring at "logout worked, but they are still
            // signed into ExoClass" has no other way to find that out.
            $this->logger->warning(
                'ExoClass SSO cannot forward the logout: no XSRF cookie on this request. '
                .'Add both names from CookieExemptions::names() to the app\'s encryptCookies(except:) list.',
                ['xsrf_cookie' => $this->credentials->xsrfCookieName()],
                $credential->redactable(),
            );

            return;
        }

        try {
            $this->client->logout($credential, $credential->xsrfToken);
        } catch (Throwable $exception) {
            // The transport already soft-fails a 4xx/5xx; this catches anything
            // it did not expect. Sign-out must complete regardless.
            $this->logger->warning('ExoClass SSO global logout failed; signing out locally anyway.', [
                'exception' => $exception::class,
                'reason' => $exception->getMessage(),
            ], $credential->redactable());
        }
    }

    private function cookieDomain(): ?string
    {
        $domain = $this->config->get('exoclass-sso.cookie_domain');

        return is_string($domain) && trim($domain) !== '' ? trim($domain) : null;
    }
}
