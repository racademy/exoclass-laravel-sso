<?php

declare(strict_types=1);

namespace ExoClass\Sso\Session;

use ExoClass\Sso\Http\SessionCredential;
use ExoClass\Sso\Identity\ExoClassIdentity;
use ExoClass\Sso\Resolution\Candidate;
use ExoClass\Sso\Resolution\ChoiceRequired;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Session\Session;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Auth;

/**
 * Everything this package remembers between two requests, and the one rule
 * governing it: THE COOKIE VALUE IS NEVER PART OF IT.
 *
 * The session is written to a store the app chose — a file, Redis, a database
 * table, a cookie — and read back by anything that can reach it. RA Portal
 * stored the raw ExoClass cookie there to compare it later, which works, but it
 * copies a live credential into a second place for the lifetime of the session.
 * A SHA-256 fingerprint answers the only question that is actually asked ("is
 * this the same cookie as last time?") and answers nothing else: it cannot be
 * replayed, forwarded or stolen back into a valid request.
 *
 * Keys live under one `exoclass_sso` prefix so a logout can drop the lot, and
 * so an operator reading a session dump can see at a glance what came from
 * here.
 */
final class SsoSession
{
    /** Prefix owning every key this package writes. */
    public const NAMESPACE = 'exoclass_sso';

    /** True when THIS session was established by SSO rather than by a password. */
    public const AUTHENTICATED = self::NAMESPACE.'.authenticated';

    /** SHA-256 of the ExoClass cookie value this session was last validated with. */
    public const FINGERPRINT = self::NAMESPACE.'.fingerprint';

    /** The ExoClass user id behind this session — the cheap account-switch check. */
    public const EXOCLASS_USER_ID = self::NAMESPACE.'.exoclass_user_id';

    /** Unix timestamp of the last successful upstream validation (liveness). */
    public const CHECKED_AT = self::NAMESPACE.'.checked_at';

    /** Unix timestamp of the last FAILED guest probe (the NFR-2 throttle). */
    public const PROBED_AT = self::NAMESPACE.'.probed_at';

    /** Candidates offered to the visitor by the app's picker. */
    public const CANDIDATES = self::NAMESPACE.'.candidates';

    /** Where the visitor was going before the picker interrupted them. */
    public const INTENDED = self::NAMESPACE.'.intended';

    /**
     * The one-way function standing between a session store and a live
     * credential. `hash_equals` compares the results, so a change is detected
     * without the value ever being kept.
     */
    public static function fingerprint(#[\SensitiveParameter] string $cookieValue): string
    {
        return hash('sha256', $cookieValue);
    }

    /**
     * Sign the visitor in and record what this session is: whose it is, which
     * cookie proved it, and when that proof was last checked.
     */
    public static function establish(
        Request $request,
        Authenticatable $user,
        SessionCredential $credential,
        ExoClassIdentity $identity,
    ): void {
        Auth::login($user);

        $session = $request->session();

        // Session fixation: the visitor arrived with an id they may have been
        // handed by somebody else. Regeneration migrates the data, so the keys
        // below survive — and must therefore be written AFTER it, not before.
        $session->regenerate();

        $session->put(self::AUTHENTICATED, true);
        $session->put(self::FINGERPRINT, self::fingerprint($credential->cookieValue));
        $session->put(self::EXOCLASS_USER_ID, $identity->user->id);
        $session->put(self::CHECKED_AT, self::now());

        // We just validated upstream: an older negative probe and a pending
        // choice are both stale now.
        $session->forget([self::PROBED_AT, self::CANDIDATES]);
    }

    /**
     * Was this session established by SSO? A password session answers false and
     * is therefore never re-validated upstream — the app owns it entirely.
     */
    public static function isSso(Session $session): bool
    {
        return $session->get(self::AUTHENTICATED) === true;
    }

    public static function exoClassUserId(Session $session): ?int
    {
        $id = $session->get(self::EXOCLASS_USER_ID);

        return is_int($id) ? $id : null;
    }

    public static function storedFingerprint(Session $session): ?string
    {
        $fingerprint = $session->get(self::FINGERPRINT);

        return is_string($fingerprint) && $fingerprint !== '' ? $fingerprint : null;
    }

    /**
     * Does the credential on this request match the one the session was
     * validated with?
     */
    public static function fingerprintMatches(Session $session, SessionCredential $credential): bool
    {
        $known = self::storedFingerprint($session);

        return $known !== null && hash_equals($known, self::fingerprint($credential->cookieValue));
    }

    public static function rememberFingerprint(Session $session, SessionCredential $credential): void
    {
        $session->put(self::FINGERPRINT, self::fingerprint($credential->cookieValue));
    }

    public static function markChecked(Session $session): void
    {
        $session->put(self::CHECKED_AT, self::now());
    }

    /**
     * Has the liveness window elapsed since the last upstream validation?
     */
    public static function isFresh(Session $session, int $ttl): bool
    {
        return self::within($session->get(self::CHECKED_AT), $ttl);
    }

    public static function markProbed(Session $session): void
    {
        $session->put(self::PROBED_AT, self::now());
    }

    /**
     * A guest whose probe already failed inside the TTL is not asked about
     * again. This is what keeps a signed-out visitor browsing a public page
     * from turning every navigation into an upstream call.
     */
    public static function isThrottled(Session $session, int $ttl): bool
    {
        return self::within($session->get(self::PROBED_AT), $ttl);
    }

    /**
     * Stash what the picker page needs. The candidates are stored flat (no
     * objects) because a session store has to serialize them and an app may
     * have chosen the cookie driver.
     */
    public static function putChoice(Session $session, ChoiceRequired $choice, ?string $intendedUrl = null): void
    {
        $session->put(self::CANDIDATES, array_map(
            static fn (Candidate $candidate): array => $candidate->toArray(),
            $choice->candidates,
        ));

        if ($intendedUrl !== null && $intendedUrl !== '') {
            $session->put(self::INTENDED, $intendedUrl);
        }
    }

    /**
     * The candidates the picker should render, back as objects.
     *
     * @return list<Candidate>
     */
    public static function candidates(Session $session): array
    {
        $stored = $session->get(self::CANDIDATES);

        if (! is_array($stored)) {
            return [];
        }

        $candidates = [];

        foreach ($stored as $candidate) {
            if (! is_array($candidate)) {
                continue;
            }

            $key = $candidate['key'] ?? null;
            $label = $candidate['label'] ?? null;
            $meta = $candidate['meta'] ?? [];

            if (! is_string($key) || ! is_string($label) || trim($key) === '' || trim($label) === '') {
                continue;
            }

            /** @var array<string, scalar|null> $meta */
            $meta = is_array($meta) ? $meta : [];

            $candidates[] = new Candidate($key, $label, $meta);
        }

        return $candidates;
    }

    public static function intendedUrl(Session $session): ?string
    {
        $url = $session->get(self::INTENDED);

        return is_string($url) && $url !== '' ? $url : null;
    }

    public static function pullIntendedUrl(Session $session): ?string
    {
        $url = self::intendedUrl($session);

        $session->forget(self::INTENDED);

        return $url;
    }

    /**
     * Drop everything this package put here. Used by the global logout, which
     * must leave nothing behind that could re-establish the session.
     */
    public static function clear(Session $session): void
    {
        $session->forget(self::NAMESPACE);
    }

    private static function now(): int
    {
        return Carbon::now()->getTimestamp();
    }

    private static function within(mixed $timestamp, int $ttl): bool
    {
        if (! is_int($timestamp) || $timestamp <= 0 || $ttl <= 0) {
            return false;
        }

        return (self::now() - $timestamp) < $ttl;
    }
}
