<?php

declare(strict_types=1);

use ExoClass\Sso\Actions\GlobalLogout;
use ExoClass\Sso\Resolution\Authenticated;
use ExoClass\Sso\Session\SsoSession;
use ExoClass\Sso\Session\SuppressionCookie;
use ExoClass\Sso\Support\CookieExemptions;
use Illuminate\Cookie\Middleware\EncryptCookies;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Request as ClientRequest;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\Http;
use Symfony\Component\HttpFoundation\Cookie as SymfonyCookie;

const LOGOUT_COOKIE = 'RAW-EXOCLASS-COOKIE-VALUE-7f3a';

/**
 * A request as it reaches a logout controller: the ExoClass cookie, its paired
 * XSRF token, and an SSO session.
 */
function logoutRequest(?string $cookie = LOGOUT_COOKIE, ?string $xsrf = 'XSRF-TOKEN-VALUE'): Request
{
    $request = Request::create('/logout', 'POST');

    if ($cookie !== null) {
        $request->cookies->set('sta_exoclass_session', $cookie);
    }

    if ($xsrf !== null) {
        $request->cookies->set('STA-XSRF-TOKEN', $xsrf);
    }

    $session = new Store('exoclass-sso-test', new ArraySessionHandler(60));
    $session->put(SsoSession::AUTHENTICATED, true);
    $session->put(SsoSession::FINGERPRINT, SsoSession::fingerprint(LOGOUT_COOKIE));
    $session->put(SsoSession::EXOCLASS_USER_ID, 48211);
    $session->put('locale', 'lt');
    $request->setLaravelSession($session);

    return $request;
}

/**
 * @return array<string, SymfonyCookie>
 */
function queuedCookies(): array
{
    $queued = [];

    foreach (Cookie::getQueuedCookies() as $cookie) {
        $queued[$cookie->getName()] = $cookie;
    }

    return $queued;
}

it('ends the ExoClass session itself, with the browser XSRF token', function () {
    Http::fake(['*auth/logout' => Http::response(status: 204)]);

    app(GlobalLogout::class)->handle(logoutRequest());

    Http::assertSent(function (ClientRequest $request): bool {
        expect($request->url())->toBe('https://api.exoclass.test/api/v1/lt/auth/logout')
            ->and($request->method())->toBe('POST')
            ->and($request->header('Cookie'))->toBe(['sta_exoclass_session='.LOGOUT_COOKIE])
            ->and($request->header('X-XSRF-TOKEN'))->toBe(['XSRF-TOKEN-VALUE'])
            ->and($request->header('Referer'))->toBe(['https://send.exoclass.test']);

        return true;
    });
});

it('suppresses re-SSO and deletes the shared cookie on the way out', function () {
    Http::fake(['*auth/logout' => Http::response(status: 204)]);

    app(GlobalLogout::class)->handle(logoutRequest());

    $queued = queuedCookies();

    expect($queued)->toHaveKey(SuppressionCookie::NAME)
        ->and($queued[SuppressionCookie::NAME]->getExpiresTime())->toBeGreaterThan(time())
        ->and($queued[SuppressionCookie::NAME]->getPath())->toBe('/')
        ->and($queued[SuppressionCookie::NAME]->getDomain())->toBeNull()
        ->and($queued)->toHaveKey('sta_exoclass_session')
        // A deletion the browser will accept: same path, same domain, expired.
        ->and($queued['sta_exoclass_session']->getValue())->toBeNull()
        ->and($queued['sta_exoclass_session']->getPath())->toBe('/')
        ->and($queued['sta_exoclass_session']->getDomain())->toBe('.exoclass.com')
        ->and($queued['sta_exoclass_session']->getExpiresTime())->toBeLessThan(time());
});

it('clears what it put in the session and nothing else', function () {
    Http::fake(['*auth/logout' => Http::response(status: 204)]);
    $request = logoutRequest();

    app(GlobalLogout::class)->handle($request);

    $session = $request->session();

    expect(SsoSession::isSso($session))->toBeFalse()
        ->and(SsoSession::storedFingerprint($session))->toBeNull()
        ->and($session->get('locale'))->toBe('lt');
});

it('signs out locally even when ExoClass refuses the logout', function (int $status) {
    $log = captureLog();
    Http::fake(['*auth/logout' => Http::response('nope', $status)]);
    $request = logoutRequest();

    app(GlobalLogout::class)->handle($request);

    // The whole point of H-10: a soft-failed global logout is exactly when the
    // shared cookie survives, and the suppression cookie is all that stops the
    // next request from signing the visitor straight back in.
    expect(queuedCookies())->toHaveKey(SuppressionCookie::NAME)
        ->and(SsoSession::isSso($request->session()))->toBeFalse()
        ->and(file_get_contents($log))->toContain('logout')
        ->and(file_get_contents($log))->not->toContain(LOGOUT_COOKIE);
})->with(['a CSRF rejection' => [419], 'an outage' => [503]]);

it('signs out locally even when ExoClass cannot be reached at all', function () {
    Http::fake(fn () => throw new ConnectionException('Connection timed out'));
    $request = logoutRequest();

    app(GlobalLogout::class)->handle($request);

    expect(queuedCookies())->toHaveKey(SuppressionCookie::NAME)
        ->and(SsoSession::isSso($request->session()))->toBeFalse();
});

it('does not bother ExoClass when there is no cookie to end a session with', function () {
    Http::fake();

    app(GlobalLogout::class)->handle(logoutRequest(cookie: null));

    Http::assertNothingSent();
    expect(queuedCookies())->toHaveKey(SuppressionCookie::NAME);
});

it('says out loud why a logout could not be forwarded when the XSRF cookie is missing', function () {
    $log = captureLog();
    Http::fake();

    app(GlobalLogout::class)->handle(logoutRequest(xsrf: null));

    // ExoClass would reject it as a CSRF failure anyway, and the real cause is
    // almost always a missing cookie exemption — so say that, do not guess.
    Http::assertNothingSent();
    expect(file_get_contents($log))->toContain('XSRF')
        ->and(queuedCookies())->toHaveKey(SuppressionCookie::NAME);
});

it('keeps a visitor out for the suppression window after they log out', function () {
    EncryptCookies::except(CookieExemptions::names());
    Http::fake([
        '*auth/logout' => Http::response(status: 204),
        '*users/current' => Http::response(identityPayload()),
    ]);
    $user = ssoUser(7);
    ssoResolver()->answerWith(fn () => new Authenticated($user));

    $logout = harness()
        ->withUnencryptedCookies(['sta_exoclass_session' => LOGOUT_COOKIE, 'STA-XSRF-TOKEN' => 'XSRF-TOKEN-VALUE'])
        ->actingAs($user)
        ->withSession(ssoSessionState(LOGOUT_COOKIE))
        ->get('/logout')
        ->assertOk();

    $suppression = collect($logout->headers->getCookies())
        ->first(fn (SymfonyCookie $cookie): bool => $cookie->getName() === SuppressionCookie::NAME);

    expect($suppression)->toBeInstanceOf(SymfonyCookie::class);
    assert($suppression instanceof SymfonyCookie);

    // The browser now carries the marker Laravel just encrypted for it.
    harness()
        ->withUnencryptedCookies(['sta_exoclass_session' => LOGOUT_COOKIE])
        ->withCookies([SuppressionCookie::NAME => (string) $suppression->getValue()])
        ->get('/dashboard')
        ->assertOk()
        ->assertSee('dashboard for a guest');

    Http::assertSentCount(1);
});

it('names the cookies the host app must keep Laravel from mangling', function () {
    expect(CookieExemptions::names())->toBe(['sta_exoclass_session', 'STA-XSRF-TOKEN']);
});

it('proves the exemption is not optional: without it there is no credential', function () {
    // No EncryptCookies::except() here. Laravel finds a cookie it did not sign,
    // fails to decrypt it, and hands the request a null — SSO silently never
    // fires, with nothing in any log to explain why.
    Http::fake();
    ssoResolver()->answerWith(fn () => new Authenticated(ssoUser(7)));

    harness()
        ->withUnencryptedCookies(['sta_exoclass_session' => LOGOUT_COOKIE])
        ->get('/dashboard')
        ->assertOk()
        ->assertSee('dashboard for a guest');

    Http::assertNothingSent();
});
