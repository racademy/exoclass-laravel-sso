<?php

declare(strict_types=1);

namespace ExoClass\Sso\Session;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cookie;
use Symfony\Component\HttpFoundation\Cookie as SymfonyCookie;

/**
 * The short-lived marker that makes a logout stick (RA Portal finding H-10).
 *
 * Without it, sign-out is a revolving door: the local session is destroyed, the
 * browser still carries the `.exoclass.com` cookie — because the upstream
 * logout soft-failed, or because the deletion has not reached the browser yet —
 * and the very next request auto-logs the visitor straight back in. They click
 * "log out" and stay logged in, forever, with no way to tell why.
 *
 * It is a COOKIE and not a session key on purpose: logout invalidates the
 * session, which would take a session-stored marker with it.
 *
 * It belongs to THIS app, on THIS host (no domain, so it is host-only), and its
 * presence alone is the signal — the browser drops it at expiry, so there is no
 * timestamp to compare and nothing to keep in sync.
 */
final class SuppressionCookie
{
    public const NAME = 'exoclass_sso_suppressed';

    public static function make(int $minutes): SymfonyCookie
    {
        return Cookie::make(
            name: self::NAME,
            value: '1',
            minutes: max(1, $minutes),
            path: '/',
            domain: null,
            httpOnly: true,
        );
    }

    /**
     * Queue the marker for the response. Called on every logout, whatever the
     * upstream said: a failed global logout is exactly when it matters most.
     */
    public static function queue(Repository $config): void
    {
        Cookie::queue(self::make((int) $config->get('exoclass-sso.suppress_minutes', 5)));
    }

    public static function presentOn(Request $request): bool
    {
        $value = $request->cookie(self::NAME);

        return is_string($value) && $value !== '';
    }
}
