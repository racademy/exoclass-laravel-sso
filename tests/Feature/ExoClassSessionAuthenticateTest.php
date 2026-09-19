<?php

declare(strict_types=1);

use ExoClass\Sso\Http\Middleware\ExoClassSessionAuthenticate;
use ExoClass\Sso\Resolution\Authenticated;
use ExoClass\Sso\Resolution\Candidate;
use ExoClass\Sso\Resolution\ChoiceRequired;
use ExoClass\Sso\Resolution\Denied;
use ExoClass\Sso\Resolution\ResolutionTrigger;
use ExoClass\Sso\Session\SsoSession;
use ExoClass\Sso\Session\SuppressionCookie;
use ExoClass\Sso\Tests\TestCase;
use Illuminate\Cookie\Middleware\EncryptCookies;
use Illuminate\Session\Store;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Http;

const COOKIE = 'RAW-EXOCLASS-COOKIE-VALUE-7f3a';

beforeEach(function () {
    // The host app's job (see CookieExemptions): without it Laravel nulls the
    // foreign cookie and none of this fires.
    EncryptCookies::except(['sta_exoclass_session', 'STA-XSRF-TOKEN']);

    config()->set('exoclass-sso.choice_route', 'sso.choose');
});

/**
 * A visitor carrying the ExoClass session cookie.
 */
function withCookie(string $value = COOKIE, ?string $xsrf = null): TestCase
{
    $cookies = ['sta_exoclass_session' => $value];

    if ($xsrf !== null) {
        $cookies['STA-XSRF-TOKEN'] = $xsrf;
    }

    return harness()->withUnencryptedCookies($cookies);
}

/**
 * The session as it stands after a request.
 */
function sessionAfterRequest(): Store
{
    return app('session.store');
}

function upstreamAnswers(int $exoClassUserId = 48211): void
{
    Http::fake(['*users/current' => Http::response(identityPayload($exoClassUserId))]);
}

// ---------------------------------------------------------------------------
// The rows that must never cost an upstream call
// ---------------------------------------------------------------------------

it('does nothing at all while the flag is off', function () {
    config()->set('exoclass-sso.enabled', false);
    Http::fake();
    ssoResolver()->answerWith(fn () => new Authenticated(ssoUser()));

    withCookie()->get('/dashboard')->assertOk()->assertSee('dashboard for a guest');

    Http::assertNothingSent();
    expect(Auth::check())->toBeFalse();
});

it('never probes on a request that is not a navigation', function (string $method, string $uri) {
    Http::fake();
    ssoResolver()->answerWith(fn () => new Authenticated(ssoUser()));

    withCookie()->call($method, $uri);

    Http::assertNothingSent();
    expect(Auth::check())->toBeFalse();
})->with([
    'a form post' => ['POST', '/dashboard'],
    'a livewire round trip' => ['GET', '/livewire/update'],
    'the health check' => ['GET', '/up'],
]);

it('lets a visitor with no ExoClass cookie straight through', function () {
    Http::fake();

    harness()->get('/login')->assertOk()->assertSee('the login page');

    Http::assertNothingSent();
});

it('asks upstream at most once per probe window for a guest whose cookie was refused', function () {
    Http::fake(['*users/current' => Http::response(status: 401)]);

    withCookie()->get('/login')->assertOk();
    Http::assertSentCount(1);

    // Same session, second navigation, inside the TTL: no second call.
    withCookie()->get('/login')->assertOk();
    Http::assertSentCount(1);

    Carbon::setTestNow(Carbon::now()->addSeconds(121));
    withCookie()->get('/login')->assertOk();
    Http::assertSentCount(2);

    Carbon::setTestNow();
});

it('does not auto-login while the post-logout suppression cookie is alive', function () {
    // Laravel signs and encrypts this one itself; the test injects it raw.
    EncryptCookies::except([SuppressionCookie::NAME]);
    Http::fake();
    ssoResolver()->answerWith(fn () => new Authenticated(ssoUser()));

    withCookie()
        ->withUnencryptedCookies([SuppressionCookie::NAME => '1'])
        ->get('/dashboard')
        ->assertOk()
        ->assertSee('dashboard for a guest');

    Http::assertNothingSent();
});

// ---------------------------------------------------------------------------
// The guest who is signed into ExoClass
// ---------------------------------------------------------------------------

it('signs a guest in and lets them have the page they asked for', function () {
    upstreamAnswers();
    $user = ssoUser(7);
    ssoResolver()->answerWith(fn () => new Authenticated($user));

    withCookie()->get('/dashboard')
        ->assertOk()
        ->assertSee('dashboard for 7');

    expect(Auth::id())->toBe(7);
});

it('records what the session is, and never the cookie that proved it', function () {
    upstreamAnswers();
    ssoResolver()->answerWith(fn () => new Authenticated(ssoUser(7)));

    withCookie()->get('/dashboard')->assertOk();

    $session = sessionAfterRequest()->all();

    expect($session['exoclass_sso']['authenticated'])->toBeTrue()
        ->and($session['exoclass_sso']['fingerprint'])->toBe(hash('sha256', COOKIE))
        ->and($session['exoclass_sso']['exoclass_user_id'])->toBe(48211)
        ->and($session['exoclass_sso']['checked_at'])->toBeInt()
        ->and(json_encode($session))->not->toContain(COOKIE);
});

it('regenerates the session id, so a handed-out id cannot become a signed-in one', function () {
    upstreamAnswers();
    ssoResolver()->answerWith(fn () => new Authenticated(ssoUser(7)));

    $before = session()->getId();

    withCookie()->get('/dashboard')->assertOk();

    expect(sessionAfterRequest()->getId())->not->toBe($before);
});

it('sends a visitor on to where they were going before the login page caught them', function () {
    upstreamAnswers();
    ssoResolver()->answerWith(fn () => new Authenticated(ssoUser(7)));

    withCookie()
        ->withSession(['url.intended' => 'https://send.exoclass.test/dashboard'])
        ->get('/login')
        ->assertRedirect('https://send.exoclass.test/dashboard');
});

it('tells the resolver which door the visitor came through', function () {
    upstreamAnswers();
    $resolver = ssoResolver()->answerWith(fn () => new Authenticated(ssoUser(7)));

    withCookie()->get('/dashboard');

    expect($resolver->contexts[0]->trigger)->toBe(ResolutionTrigger::AutoLogin)
        ->and($resolver->contexts[0]->intendedUrl)->toBe('http://localhost/dashboard');
});

it('stashes the candidates and redirects to the picker when several apply', function () {
    upstreamAnswers();
    ssoResolver()->answerWith(fn () => new ChoiceRequired(
        new Candidate('1042', 'Robotikos akademija'),
        new Candidate('2087', 'Atletikos akademija'),
    ));

    withCookie()->get('/dashboard')->assertRedirect('http://localhost/choose');

    $session = sessionAfterRequest();

    expect(SsoSession::candidates($session))->toHaveCount(2)
        ->and(SsoSession::intendedUrl($session))->toBe('http://localhost/dashboard')
        ->and(Auth::check())->toBeFalse();
});

it('renders the picker even when the configured URL disagrees about scheme or host', function () {
    // A proxy the app does not trust, a forced https URL generator, an APP_URL
    // whose host differs from the Host header: the picker's absolute URL and
    // the request's stop matching, and an absolute-URL loop guard never fires.
    // The browser then follows the redirect back to the same page, forever.
    config()->set('exoclass-sso.choice_route', 'https://localhost/choose');
    upstreamAnswers();
    ssoResolver()->answerWith(fn () => new ChoiceRequired(
        new Candidate('1042', 'Robotikos akademija'),
        new Candidate('2087', 'Atletikos akademija'),
    ));

    withCookie()->get('/choose')->assertOk()->assertSee('pick one of 2');
});

it('renders the picker instead of redirecting to it forever', function () {
    upstreamAnswers();
    ssoResolver()->answerWith(fn () => new ChoiceRequired(
        new Candidate('1042', 'Robotikos akademija'),
        new Candidate('2087', 'Atletikos akademija'),
    ));

    withCookie()->get('/choose')->assertOk()->assertSee('pick one of 2');
});

it('falls through when the app has a choice to offer but no page to offer it on', function () {
    config()->set('exoclass-sso.choice_route', null);
    upstreamAnswers();
    ssoResolver()->answerWith(fn () => new ChoiceRequired(
        new Candidate('1042', 'Robotikos akademija'),
        new Candidate('2087', 'Atletikos akademija'),
    ));

    withCookie()->get('/dashboard')->assertOk()->assertSee('dashboard for a guest');
});

it('refuses a denied visitor with a 403 and leaves their ExoClass cookie alone', function () {
    upstreamAnswers();
    ssoResolver()->answerWith(fn () => new Denied('no eligible organization for this ExoClass account'));

    $response = withCookie()->get('/dashboard')->assertForbidden();

    // The visitor is legitimately signed into ExoClass; refusing them here must
    // not sign them out of it.
    foreach ($response->headers->getCookies() as $cookie) {
        expect($cookie->getName())->not->toBe('sta_exoclass_session');
    }

    expect(sessionAfterRequest()->get(SsoSession::PROBED_AT))->toBeInt();
});

it('renders the configured denial view when the app supplies one', function () {
    config()->set('exoclass-sso.denied_view', 'sso-denied');
    upstreamAnswers();
    ssoResolver()->answerWith(fn () => new Denied('no eligible organization'));

    withCookie()->get('/dashboard')
        ->assertForbidden()
        ->assertSee('no eligible organization');
});

it('lets the app take the denial over entirely', function () {
    ExoClassSessionAuthenticate::denyUsing(fn ($request, Denied $denied) => response('nope: '.$denied->reason, 403));
    upstreamAnswers();
    ssoResolver()->answerWith(fn () => new Denied('not a provider admin'));

    withCookie()->get('/dashboard')->assertForbidden()->assertSee('nope: not a provider admin');

    ExoClassSessionAuthenticate::denyUsing(null);
});

it('marks the probe and moves on when ExoClass says 401', function () {
    Http::fake(['*users/current' => Http::response(status: 401)]);
    $resolver = ssoResolver();

    withCookie()->get('/login')->assertOk()->assertSee('the login page');

    expect($resolver->calls())->toBe(0)
        ->and(sessionAfterRequest()->get(SsoSession::PROBED_AT))->toBeInt();
});

it('still renders the login page when ExoClass is unreachable, and says so in the log', function (int $status) {
    $log = captureLog();
    Http::fake(['*users/current' => Http::response('gateway is sad', $status)]);

    withCookie()->get('/login')->assertOk()->assertSee('the login page');

    expect(file_get_contents($log))->toContain('no verdict')
        ->and(file_get_contents($log))->not->toContain(COOKIE);
})->with(['a bad gateway' => [502], 'a teapot' => [418]]);

it('still renders the login page when ExoClass answers something unparseable', function () {
    $log = captureLog();
    Http::fake(['*users/current' => Http::response(['id' => null])]);

    withCookie()->get('/login')->assertOk()->assertSee('the login page');

    expect(file_get_contents($log))->toContain('no verdict');
});

it('never lets a broken resolver take the page down with it', function () {
    $log = captureLog();
    upstreamAnswers();
    ssoResolver()->answerWith(function () {
        throw new RuntimeException('the organization table is on fire');
    });

    withCookie()->get('/login')->assertOk()->assertSee('the login page');

    expect(file_get_contents($log))->toContain('resolver');
});

// ---------------------------------------------------------------------------
// The visitor who is already signed in here
// ---------------------------------------------------------------------------

it('never calls upstream for a session established with a password', function () {
    Http::fake();
    $user = ssoUser(7);

    harness()->actingAs($user)->get('/dashboard')->assertOk()->assertSee('dashboard for 7');

    Http::assertNothingSent();
    expect(Auth::check())->toBeTrue();
});

it('trusts an unchanged cookie until the liveness window closes', function () {
    Http::fake();
    $user = ssoUser(7);

    withCookie()->actingAs($user)->withSession(ssoSessionState())->get('/dashboard')->assertOk();

    Http::assertNothingSent();
});

it('re-validates the moment the cookie value changes', function () {
    upstreamAnswers();
    $user = ssoUser(7);

    withCookie('A-DIFFERENT-COOKIE-VALUE')
        ->actingAs($user)
        ->withSession(ssoSessionState())
        ->get('/dashboard')
        ->assertOk()
        ->assertSee('dashboard for 7');

    Http::assertSentCount(1);
    expect(Auth::id())->toBe(7);
});

it('re-validates once the liveness window has closed even with a frozen cookie', function () {
    upstreamAnswers();
    $user = ssoUser(7);

    withCookie()
        ->actingAs($user)
        ->withSession(ssoSessionState(checkedAt: Carbon::now()->getTimestamp() - 601))
        ->get('/dashboard')
        ->assertOk();

    Http::assertSentCount(1);
    expect(Auth::id())->toBe(7);
});

it('signs the visitor out locally when ExoClass says the session is gone', function () {
    Http::fake(['*users/current' => Http::response(status: 401)]);
    $user = ssoUser(7);

    withCookie('A-DIFFERENT-COOKIE-VALUE')
        ->actingAs($user)
        ->withSession(ssoSessionState())
        ->get('/dashboard')
        ->assertRedirect();

    expect(Auth::check())->toBeFalse();
});

it('sends them to the configured login route when their session is torn down', function () {
    config()->set('exoclass-sso.local_login_route', 'login');
    Http::fake(['*users/current' => Http::response(status: 401)]);

    withCookie('A-DIFFERENT-COOKIE-VALUE')
        ->actingAs(ssoUser(7))
        ->withSession(ssoSessionState())
        ->get('/dashboard')
        ->assertRedirect('http://localhost/login');
});

it('signs the visitor out when the shared cookie disappears, without asking anybody', function () {
    Http::fake();

    harness()->actingAs(ssoUser(7))->withSession(ssoSessionState())->get('/dashboard')->assertRedirect();

    Http::assertNothingSent();
    expect(Auth::check())->toBeFalse();
});

it('re-authenticates as the person who is signed into ExoClass now', function () {
    upstreamAnswers(exoClassUserId: 99001);
    ssoUser(7);
    $other = ssoUser(8, 'kita@robotikosakademija.lt');
    ssoResolver()->answerWith(fn () => new Authenticated($other));

    withCookie('SOMEBODY-ELSES-COOKIE')
        ->actingAs(ssoUser(7))
        ->withSession(ssoSessionState())
        ->get('/dashboard')
        ->assertOk()
        ->assertSee('dashboard for 8');

    expect(Auth::id())->toBe(8);
});

it('does not hand the new person the session the last one left behind', function () {
    // `regenerate()` MIGRATES session data: a new id, the same contents. On
    // every other path that is what we want — here a DIFFERENT HUMAN is taking
    // over the browser, and anything the app kept about the last one (a chosen
    // tenant, a passed password-confirmation gate) would follow them in.
    upstreamAnswers(exoClassUserId: 99001);
    ssoUser(7);
    $other = ssoUser(8, 'kita@robotikosakademija.lt');
    ssoResolver()->answerWith(fn () => new Authenticated($other));

    withCookie('SOMEBODY-ELSES-COOKIE')
        ->actingAs(ssoUser(7))
        ->withSession([
            ...ssoSessionState(),
            'filament.tenant' => 'org-of-user-7',
            'auth.password_confirmed_at' => Carbon::now()->getTimestamp(),
        ])
        ->get('/dashboard')
        ->assertOk()
        ->assertSee('dashboard for 8');

    expect(Auth::id())->toBe(8)
        ->and(sessionAfterRequest()->get('filament.tenant'))->toBeNull()
        ->and(sessionAfterRequest()->get('auth.password_confirmed_at'))->toBeNull()
        ->and(SsoSession::exoClassUserId(sessionAfterRequest()))->toBe(99001);
});

it('drops the session when the new ExoClass identity may not be here', function () {
    upstreamAnswers(exoClassUserId: 99001);
    ssoResolver()->answerWith(fn () => new Denied('not a provider admin'));

    withCookie('SOMEBODY-ELSES-COOKIE')
        ->actingAs(ssoUser(7))
        ->withSession(ssoSessionState())
        ->get('/dashboard')
        ->assertRedirect();

    expect(Auth::check())->toBeFalse();
});

it('keeps an established session alive through an ExoClass outage', function () {
    $log = captureLog();
    Http::fake(['*users/current' => Http::response(status: 503)]);
    $user = ssoUser(7);

    withCookie('A-DIFFERENT-COOKIE-VALUE')
        ->actingAs($user)
        ->withSession(ssoSessionState())
        ->get('/dashboard')
        ->assertOk()
        ->assertSee('dashboard for 7');

    expect(Auth::id())->toBe(7)
        ->and(file_get_contents($log))->toContain('liveness');
});

it('does not re-ask upstream on every navigation during an outage', function () {
    Http::fake(['*users/current' => Http::response(status: 503)]);
    $user = ssoUser(7);

    withCookie('A-DIFFERENT-COOKIE-VALUE')->actingAs($user)->withSession(ssoSessionState())->get('/dashboard')->assertOk();
    Http::assertSentCount(1);

    // The cookie still looks changed, but the check was just made: the backstop
    // has to hold or an outage becomes a request-rate multiplier.
    withCookie('A-DIFFERENT-COOKIE-VALUE')->actingAs($user)->get('/dashboard')->assertOk();
    Http::assertSentCount(1);
});
