<?php

declare(strict_types=1);

use ExoClass\Sso\Http\SessionCredential;
use ExoClass\Sso\Support\LogSanitizer;

it('builds the Cookie header line from the name and the raw value', function () {
    expect(credential()->cookieHeader())->toBe('sta_exoclass_session=RAW-EXOCLASS-COOKIE-VALUE-7f3a');
});

it('rejects an empty cookie name', function () {
    new SessionCredential('', 'value');
})->throws(InvalidArgumentException::class, 'non-empty cookie name');

it('rejects an empty cookie value', function () {
    new SessionCredential('sta_exoclass_session', '   ');
})->throws(InvalidArgumentException::class, 'non-empty cookie value');

it('rejects an empty XSRF token when one is supplied', function () {
    new SessionCredential('sta_exoclass_session', 'value', '');
})->throws(InvalidArgumentException::class, 'non-empty XSRF token');

it('carries no XSRF token by default', function () {
    expect(credential()->xsrfToken)->toBeNull()
        ->and(credential()->withXsrfToken('abc')->xsrfToken)->toBe('abc')
        ->and(credential()->withXsrfToken('abc')->cookieValue)->toBe('RAW-EXOCLASS-COOKIE-VALUE-7f3a');
});

it('lists every secret it carries for the log sanitizer', function () {
    expect(credential()->redactable())->toBe(['RAW-EXOCLASS-COOKIE-VALUE-7f3a'])
        ->and(credential('cookie-v', 'xsrf-v')->redactable())->toBe(['cookie-v', 'xsrf-v']);
});

it('hides both secrets from debug output', function () {
    $dump = print_r(credential('cookie-v', 'xsrf-v'), true);

    expect($dump)->not->toContain('cookie-v')
        ->and($dump)->not->toContain('xsrf-v')
        ->and($dump)->toContain(LogSanitizer::REDACTED)
        ->and($dump)->toContain('sta_exoclass_session');
});
