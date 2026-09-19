<?php

declare(strict_types=1);

use ExoClass\Sso\Http\CredentialReader;
use ExoClass\Sso\Resolution\Candidate;
use ExoClass\Sso\Resolution\ChoiceRequired;
use ExoClass\Sso\Session\SsoSession;
use ExoClass\Sso\Session\SuppressionCookie;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Carbon;

function store(): Store
{
    return new Store('exoclass-sso-test', new ArraySessionHandler(60));
}

it('fingerprints a cookie value one way and stably', function () {
    $fingerprint = SsoSession::fingerprint('RAW-EXOCLASS-COOKIE-VALUE-7f3a');

    expect($fingerprint)->toBe(hash('sha256', 'RAW-EXOCLASS-COOKIE-VALUE-7f3a'))
        ->and($fingerprint)->not->toContain('RAW-EXOCLASS-COOKIE-VALUE-7f3a')
        ->and(SsoSession::fingerprint('RAW-EXOCLASS-COOKIE-VALUE-7f3a'))->toBe($fingerprint)
        ->and(SsoSession::fingerprint('something else'))->not->toBe($fingerprint);
});

it('recognises the same cookie and notices a different one', function () {
    $session = store();
    SsoSession::rememberFingerprint($session, credential('FIRST'));

    expect(SsoSession::fingerprintMatches($session, credential('FIRST')))->toBeTrue()
        ->and(SsoSession::fingerprintMatches($session, credential('SECOND')))->toBeFalse();
});

it('treats a session that never saw a cookie as a mismatch, not a match', function () {
    expect(SsoSession::fingerprintMatches(store(), credential()))->toBeFalse()
        ->and(SsoSession::storedFingerprint(store()))->toBeNull();
});

it('answers false for a session no SSO ever touched', function () {
    $session = store();

    expect(SsoSession::isSso($session))->toBeFalse()
        ->and(SsoSession::exoClassUserId($session))->toBeNull()
        ->and(SsoSession::isFresh($session, 600))->toBeFalse()
        ->and(SsoSession::isThrottled($session, 120))->toBeFalse();
});

it('keeps a failed probe throttled for exactly the configured window', function () {
    Carbon::setTestNow('2026-09-19 12:00:00');
    $session = store();
    SsoSession::markProbed($session);

    Carbon::setTestNow('2026-09-19 12:01:59');
    expect(SsoSession::isThrottled($session, 120))->toBeTrue();

    Carbon::setTestNow('2026-09-19 12:02:00');
    expect(SsoSession::isThrottled($session, 120))->toBeFalse();

    Carbon::setTestNow();
});

it('lets a zero TTL mean "never throttle" rather than "throttle forever"', function () {
    $session = store();
    SsoSession::markProbed($session);
    SsoSession::markChecked($session);

    expect(SsoSession::isThrottled($session, 0))->toBeFalse()
        ->and(SsoSession::isFresh($session, 0))->toBeFalse();
});

it('stores the picker candidates flat, so any session driver can carry them', function () {
    $session = store();

    SsoSession::putChoice($session, new ChoiceRequired(
        new Candidate('1042', 'Robotikos akademija', ['city' => 'Vilnius']),
        new Candidate('2087', 'Atletikos akademija'),
    ), 'https://send.exoclass.test/admin/messages');

    expect($session->get(SsoSession::CANDIDATES))->toBe([
        ['key' => '1042', 'label' => 'Robotikos akademija', 'meta' => ['city' => 'Vilnius']],
        ['key' => '2087', 'label' => 'Atletikos akademija', 'meta' => []],
    ]);

    $candidates = SsoSession::candidates($session);

    expect($candidates)->toHaveCount(2)
        ->and($candidates[0])->toBeInstanceOf(Candidate::class)
        ->and($candidates[0]->label)->toBe('Robotikos akademija')
        ->and(SsoSession::intendedUrl($session))->toBe('https://send.exoclass.test/admin/messages');
});

it('drops a stashed candidate the session store mangled rather than rendering nonsense', function () {
    $session = store();
    $session->put(SsoSession::CANDIDATES, [
        ['key' => '1042', 'label' => 'Robotikos akademija', 'meta' => []],
        ['key' => '', 'label' => 'blank key'],
        ['label' => 'no key at all'],
        'not even an array',
    ]);

    expect(SsoSession::candidates($session))->toHaveCount(1);
});

it('hands the intended url over exactly once', function () {
    $session = store();
    SsoSession::putChoice($session, new ChoiceRequired(
        new Candidate('a', 'A'),
        new Candidate('b', 'B'),
    ), 'https://send.exoclass.test/admin');

    expect(SsoSession::pullIntendedUrl($session))->toBe('https://send.exoclass.test/admin')
        ->and(SsoSession::pullIntendedUrl($session))->toBeNull();
});

it('clears everything it ever wrote and nothing the app wrote', function () {
    $session = store();
    $session->put(SsoSession::AUTHENTICATED, true);
    $session->put(SsoSession::FINGERPRINT, 'abc');
    $session->put(SsoSession::EXOCLASS_USER_ID, 77);
    $session->put(SsoSession::CHECKED_AT, 1_700_000_000);
    $session->put(SsoSession::PROBED_AT, 1_700_000_000);
    $session->put(SsoSession::CANDIDATES, [['key' => 'a', 'label' => 'A', 'meta' => []]]);
    $session->put(SsoSession::INTENDED, 'https://send.exoclass.test/admin');
    $session->put('locale', 'lt');

    SsoSession::clear($session);

    expect($session->has(SsoSession::NAMESPACE))->toBeFalse()
        ->and(SsoSession::isSso($session))->toBeFalse()
        ->and(SsoSession::candidates($session))->toBe([])
        ->and($session->get('locale'))->toBe('lt');
});

it('reads the credential off a request using the configured cookie names', function () {
    $request = Request::create('/admin');
    $request->cookies->set('sta_exoclass_session', 'RAW-VALUE');
    $request->cookies->set('STA-XSRF-TOKEN', 'XSRF-VALUE');

    $credential = (new CredentialReader(config()))->from($request);

    expect($credential?->cookieName)->toBe('sta_exoclass_session')
        ->and($credential?->cookieValue)->toBe('RAW-VALUE')
        ->and($credential?->xsrfToken)->toBe('XSRF-VALUE');
});

it('reports no credential when the cookie is absent, blank, or nulled by the encrypter', function (mixed $value) {
    $request = Request::create('/admin');

    if ($value !== null) {
        $request->cookies->set('sta_exoclass_session', $value);
    }

    expect((new CredentialReader(config()))->from($request))->toBeNull();
})->with([
    'absent' => [null],
    'blank' => [''],
    'whitespace' => ['   '],
]);

it('carries no XSRF token when the app forgot to exempt that cookie too', function () {
    $request = Request::create('/admin');
    $request->cookies->set('sta_exoclass_session', 'RAW-VALUE');

    $credential = (new CredentialReader(config()))->from($request);

    expect($credential?->xsrfToken)->toBeNull();
});

it('makes a host-only suppression cookie that outlives the session it replaces', function () {
    $cookie = SuppressionCookie::make(5);

    expect($cookie->getName())->toBe(SuppressionCookie::NAME)
        ->and($cookie->getValue())->toBe('1')
        ->and($cookie->getPath())->toBe('/')
        ->and($cookie->getDomain())->toBeNull()
        ->and($cookie->isHttpOnly())->toBeTrue()
        ->and($cookie->getExpiresTime())->toBeGreaterThan(time());
});

it('never makes a suppression cookie that expires instantly', function () {
    // A zero here would mean "session cookie" to the browser on some paths and
    // "already expired" on others; either way the logout stops sticking.
    expect(SuppressionCookie::make(0)->getExpiresTime())->toBeGreaterThan(time());
});

it('sees the suppression marker on the next request', function () {
    $request = Request::create('/admin');
    expect(SuppressionCookie::presentOn($request))->toBeFalse();

    $request->cookies->set(SuppressionCookie::NAME, '1');
    expect(SuppressionCookie::presentOn($request))->toBeTrue();
});
