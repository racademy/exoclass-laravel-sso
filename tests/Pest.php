<?php

declare(strict_types=1);

use ExoClass\Sso\Contracts\IdentityResolver;
use ExoClass\Sso\Http\SessionCredential;
use ExoClass\Sso\Session\SsoSession;
use ExoClass\Sso\Tests\Support\ArrayUserProvider;
use ExoClass\Sso\Tests\Support\RecordingResolver;
use ExoClass\Sso\Tests\TestCase;
use Illuminate\Auth\GenericUser;
use Illuminate\Support\Carbon;
use Pest\TestSuite;

uses(TestCase::class)->in('Feature', 'Unit');

/**
 * Load a committed ExoClass fixture.
 *
 * @return array<array-key, mixed>
 */
function ssoFixture(string $name): array
{
    $path = __DIR__.'/../fixtures/'.$name.'.json';

    expect(file_exists($path))->toBeTrue("Missing fixture: {$path}");

    /** @var array<array-key, mixed> $decoded */
    $decoded = json_decode((string) file_get_contents($path), true, 512, JSON_THROW_ON_ERROR);

    return $decoded;
}

/**
 * The browser credential under test. The value is deliberately a distinctive
 * string so a redaction test can grep for it.
 */
function credential(string $value = 'RAW-EXOCLASS-COOKIE-VALUE-7f3a', ?string $xsrf = null): SessionCredential
{
    return new SessionCredential('sta_exoclass_session', $value, $xsrf);
}

/**
 * Point the default log channel at a fresh file and return its path, so a test
 * can grep what the package actually wrote.
 */
function captureLog(): string
{
    $path = sys_get_temp_dir().'/exoclass-sso-'.bin2hex(random_bytes(6)).'.log';

    config()->set('logging.default', 'sso-capture');
    config()->set('logging.channels.sso-capture', [
        'driver' => 'single',
        'path' => $path,
        'level' => 'debug',
    ]);

    return $path;
}

/**
 * The running test case, typed — `test()` alone is a union PHPStan cannot call
 * HTTP helpers on.
 */
function harness(): TestCase
{
    $harness = TestSuite::getInstance()->test;

    assert($harness instanceof TestCase);

    return $harness;
}

/**
 * The app-side resolver, bound into the container and returned so a test can
 * tell it what to answer.
 */
function ssoResolver(): RecordingResolver
{
    $resolver = app()->bound(RecordingResolver::class) ? app(RecordingResolver::class) : new RecordingResolver;

    app()->instance(RecordingResolver::class, $resolver);
    app()->instance(IdentityResolver::class, $resolver);

    return $resolver;
}

/**
 * A local account for the resolver to vouch for.
 */
function ssoUser(int $id = 7, string $email = 'mentorius@robotikosakademija.lt'): GenericUser
{
    return ArrayUserProvider::add($id, $email);
}

/**
 * The session state an SSO login leaves behind, for tests that start from an
 * already-authenticated visitor.
 *
 * @return array<string, mixed>
 */
function ssoSessionState(string $cookieValue = 'RAW-EXOCLASS-COOKIE-VALUE-7f3a', int $exoClassUserId = 48211, ?int $checkedAt = null): array
{
    return [
        SsoSession::AUTHENTICATED => true,
        SsoSession::FINGERPRINT => SsoSession::fingerprint($cookieValue),
        SsoSession::EXOCLASS_USER_ID => $exoClassUserId,
        SsoSession::CHECKED_AT => $checkedAt ?? Carbon::now()->getTimestamp(),
    ];
}

/**
 * The unscoped `users/current` body, with the ExoClass user id swapped so a
 * test can stage an account switch.
 *
 * @return array<array-key, mixed>
 */
function identityPayload(int $exoClassUserId = 48211, string $email = 'mentorius@robotikosakademija.lt'): array
{
    return [...ssoFixture('users-current-unscoped'), 'id' => $exoClassUserId, 'email' => $email];
}
