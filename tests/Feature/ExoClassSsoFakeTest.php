<?php

declare(strict_types=1);

use ExoClass\Sso\Contracts\IdentityFetcher;
use ExoClass\Sso\Exceptions\MalformedResponseException;
use ExoClass\Sso\Exceptions\UnauthorizedException;
use ExoClass\Sso\Exceptions\UnavailableException;
use ExoClass\Sso\Resolution\Authenticated;
use ExoClass\Sso\Resolution\Denied;
use ExoClass\Sso\Testing\ExoClassSsoFake;
use PHPUnit\Framework\AssertionFailedError;

const PROVIDER_KEY = 'c0ffee00-1111-2222-3333-444455556666';

it('drives the real middleware end to end, which is the only thing it is for', function () {
    $sso = ExoClassSsoFake::fake();
    $user = ssoUser(7);
    ssoResolver()->answerWith(fn () => new Authenticated($user));

    $sso->withExoClassCookie(harness(), 'a-session-value')
        ->get('/dashboard')
        ->assertOk()
        ->assertSee('dashboard for 7');

    $sso->assertProbed();
});

it('answers a scoped question with the roles held at that provider', function () {
    $sso = ExoClassSsoFake::fake()->scoped(PROVIDER_KEY);

    $identity = app(IdentityFetcher::class)->fetch(credential());

    expect($identity->rolesFor(PROVIDER_KEY))->toBe(['provider'])
        ->and($identity->hasRoleAt(PROVIDER_KEY, 'administrator', 'provider'))->toBeTrue();

    $sso->assertProbed();
});

it('answers a provider key it does not know exactly as ExoClass does', function () {
    ExoClassSsoFake::fake()->scoped(PROVIDER_KEY);

    $identity = app(IdentityFetcher::class)->fetch(credential());

    // Real ExoClass discards an unresolvable key and answers 200 with the union
    // of every role. The package refuses that body, and a fake that quietly
    // answered 404 would hide the whole failure mode from every app.
    expect(fn () => $identity->rolesFor('a-key-exoclass-never-heard-of'))
        ->toThrow(MalformedResponseException::class);
});

it('tells the three failures apart, because the package treats them differently', function (string $shape, string $exception) {
    $sso = ExoClassSsoFake::fake();
    $sso->{$shape}();

    expect(fn () => app(IdentityFetcher::class)->fetch(credential()))->toThrow($exception);
})->with([
    'unauthorized' => ['unauthorized', UnauthorizedException::class],
    'unavailable' => ['unavailable', UnavailableException::class],
    'unreachable' => ['unreachable', UnavailableException::class],
    'malformed' => ['malformed', MalformedResponseException::class],
]);

it('counts what was asked and what was not', function () {
    $sso = ExoClassSsoFake::fake()->unauthorized();

    $sso->assertNotProbed();

    $sso->withExoClassCookie(harness(), 'a-session-value')->get('/login')->assertOk();

    $sso->assertProbed(1);

    expect(fn () => $sso->assertNotProbed())->toThrow(AssertionFailedError::class)
        ->and(fn () => $sso->assertProbed(2))->toThrow(AssertionFailedError::class);
});

it('proves a logout reached ExoClass with the token its CSRF gate demands', function () {
    $sso = ExoClassSsoFake::fake()->logoutOk();
    $user = ssoUser(7);
    ssoResolver()->answerWith(fn () => new Authenticated($user));

    $sso->withExoClassCookie(harness(), 'a-session-value', 'an-xsrf-token')
        ->actingAs($user)
        ->withSession(ssoSessionState('a-session-value'))
        ->get('/logout')
        ->assertOk();

    $sso->assertLogoutForwardedWithXsrf('an-xsrf-token');
});

it('fails the logout assertion when no logout was forwarded', function () {
    $sso = ExoClassSsoFake::fake();

    expect(fn () => $sso->assertLogoutForwardedWithXsrf())->toThrow(AssertionFailedError::class);
});

it('lets an app prove that a refused visitor gets a 403 and keeps their ExoClass session', function () {
    $sso = ExoClassSsoFake::fake();
    ssoResolver()->answerWith(fn () => new Denied('no eligible organization'));

    $response = $sso->withExoClassCookie(harness(), 'a-session-value')
        ->get('/dashboard')
        ->assertForbidden();

    foreach ($response->headers->getCookies() as $cookie) {
        expect($cookie->getName())->not->toBe('sta_exoclass_session');
    }
});

it('catches a credential that reached the log', function () {
    $log = captureLog();
    $sso = ExoClassSsoFake::fake()->unavailable();

    $sso->withExoClassCookie(harness(), 'a-very-secret-session-value')->get('/login')->assertOk();

    // The package logged the outage; none of it may carry the cookie.
    expect(file_get_contents($log))->toContain('no verdict');
    $sso->assertNothingLeaked($log);

    // And the assertion is not vacuous.
    file_put_contents($log, 'oops a-very-secret-session-value slipped out', FILE_APPEND);
    expect(fn () => $sso->assertNothingLeaked($log))->toThrow(AssertionFailedError::class);
});

it('hands out the committed fixtures for a test that wants to bend one', function () {
    $fixture = ExoClassSsoFake::fixture('users-current-unscoped');

    expect($fixture['email'])->toBe('mentorius@robotikosakademija.lt')
        ->and(fn () => ExoClassSsoFake::fixture('nothing-like-it'))->toThrow(RuntimeException::class);
});

it('lets a test supply its own body, for an identity the fixtures do not describe', function () {
    ExoClassSsoFake::fake()->unscoped([
        'id' => 99001,
        'external_key' => 'ffffffff-0000-0000-0000-000000000001',
        'email' => 'kita@atletikosakademija.lt',
        'employers' => [['id' => 2087, 'external_key' => 'aaaa', 'name' => 'Atletikos akademija']],
    ]);

    $identity = app(IdentityFetcher::class)->fetch(credential());

    expect($identity->user->id)->toBe(99001)
        ->and($identity->user->email)->toBe('kita@atletikosakademija.lt')
        ->and($identity->employers)->toHaveCount(1);
});
