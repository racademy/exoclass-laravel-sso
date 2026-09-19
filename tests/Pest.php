<?php

declare(strict_types=1);

use ExoClass\Sso\Http\SessionCredential;
use ExoClass\Sso\Tests\TestCase;

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
