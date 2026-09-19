<?php

declare(strict_types=1);

use ExoClass\Sso\Resolution\Authenticated;
use ExoClass\Sso\Resolution\Candidate;
use ExoClass\Sso\Resolution\ChoiceRequired;
use ExoClass\Sso\Resolution\Denied;
use ExoClass\Sso\Session\SsoSession;
use Illuminate\Cookie\Middleware\EncryptCookies;
use Illuminate\Support\Facades\Http;
use Illuminate\Testing\TestResponse;
use Symfony\Component\HttpFoundation\Response;

const CHOICE_COOKIE = 'RAW-EXOCLASS-COOKIE-VALUE-7f3a';

beforeEach(function () {
    EncryptCookies::except(['sta_exoclass_session', 'STA-XSRF-TOKEN']);
    config()->set('exoclass-sso.choice_route', 'sso.choose');

    // Every app binds its resolver; without one the action fails loudly at
    // resolution rather than quietly letting somebody in.
    ssoResolver();
});

/**
 * Post a pick, the way the picker page would.
 *
 * @param  array<string, mixed>  $session
 * @return TestResponse<Response>
 */
function pick(string $key, array $session = [], ?string $cookie = CHOICE_COOKIE): TestResponse
{
    $harness = harness();

    if ($cookie !== null) {
        $harness = $harness->withUnencryptedCookies(['sta_exoclass_session' => $cookie]);
    }

    return $harness
        ->withSession([...$session, '_token' => 'a-csrf-token'])
        ->post('/choose', ['key' => $key, '_token' => 'a-csrf-token']);
}

it('signs the visitor in as the candidate they picked and sends them where they were going', function () {
    Http::fake(['*users/current' => Http::response(identityPayload())]);
    $user = ssoUser(8, 'admin@atletikosakademija.lt');
    ssoResolver()->answerChoiceWith(fn () => new Authenticated($user));

    pick('2087', [SsoSession::INTENDED => 'http://localhost/dashboard'])
        ->assertOk()
        ->assertSee('entered as 8 heading for http://localhost/dashboard');

    $session = app('session.store');

    expect(SsoSession::isSso($session))->toBeTrue()
        ->and(SsoSession::exoClassUserId($session))->toBe(48211)
        ->and($session->get(SsoSession::FINGERPRINT))->toBe(hash('sha256', CHOICE_COOKIE))
        ->and(json_encode($session->all()))->not->toContain(CHOICE_COOKIE);
});

it('hands the key to the resolver, which is the only thing allowed to trust it', function () {
    Http::fake(['*users/current' => Http::response(identityPayload())]);
    $resolver = ssoResolver()->answerChoiceWith(fn () => new Authenticated(ssoUser(8)));

    pick('2087');

    expect($resolver->choiceKeys)->toBe(['2087']);
});

it('re-proves the ExoClass session rather than trusting the earlier probe', function () {
    Http::fake(['*users/current' => Http::response(identityPayload())]);
    ssoResolver()->answerChoiceWith(fn () => new Authenticated(ssoUser(8)));

    pick('2087');

    Http::assertSentCount(1);
});

it('refuses a key the resolver does not recognise', function () {
    Http::fake(['*users/current' => Http::response(identityPayload())]);
    ssoResolver()->answerChoiceWith(fn () => new Denied('the chosen organization is not one this account may enter'));

    pick('an-organization-they-invented')
        ->assertOk()
        ->assertSee('refused: the chosen organization is not one this account may enter');

    expect(SsoSession::isSso(app('session.store')))->toBeFalse();
});

it('hands a second choice back rather than guessing between the remaining candidates', function () {
    Http::fake(['*users/current' => Http::response(identityPayload())]);
    ssoResolver()->answerChoiceWith(fn () => new ChoiceRequired(
        new Candidate('1042', 'Robotikos akademija'),
        new Candidate('2087', 'Atletikos akademija'),
    ));

    pick('1042')->assertOk()->assertSee('refused: '.ChoiceRequired::class);
});

it('refuses a choice made without an ExoClass session cookie', function () {
    Http::fake();

    pick('2087', cookie: null)->assertOk()->assertSee('refused: no ExoClass session cookie');

    Http::assertNothingSent();
});

it('tells a signed-out visitor that ExoClass no longer knows them', function () {
    Http::fake(['*users/current' => Http::response(status: 401)]);

    pick('2087')->assertOk()->assertSee('refused: ExoClass no longer recognises this session');
});

it('says an outage is an outage, not a refusal of this person', function () {
    $log = captureLog();
    Http::fake(['*users/current' => Http::response(status: 503)]);

    pick('2087')->assertOk()->assertSee('refused: ExoClass could not be reached');

    expect(file_get_contents($log))->not->toContain(CHOICE_COOKIE);
});
