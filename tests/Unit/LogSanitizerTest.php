<?php

declare(strict_types=1);

use ExoClass\Sso\Support\LogSanitizer;

it('redacts credential-bearing keys whatever their value', function () {
    $sanitized = LogSanitizer::context([
        'Cookie' => 'sta_exoclass_session=abc',
        'set-cookie' => 'sta_exoclass_session=def; Path=/',
        'X-XSRF-TOKEN' => 'token',
        'xsrf_token' => 'token',
        'Authorization' => 'Bearer secret',
        'url' => 'https://api.exoclass.test/api/v1/lt/users/current',
    ]);

    expect($sanitized['Cookie'])->toBe(LogSanitizer::REDACTED)
        ->and($sanitized['set-cookie'])->toBe(LogSanitizer::REDACTED)
        ->and($sanitized['X-XSRF-TOKEN'])->toBe(LogSanitizer::REDACTED)
        ->and($sanitized['xsrf_token'])->toBe(LogSanitizer::REDACTED)
        ->and($sanitized['Authorization'])->toBe(LogSanitizer::REDACTED)
        ->and($sanitized['url'])->toBe('https://api.exoclass.test/api/v1/lt/users/current');
});

it('scrubs a secret that leaked under an innocent key, at any depth', function () {
    $sanitized = LogSanitizer::context([
        'response' => [
            'body' => 'no session for s3cr3t-value',
            'headers' => ['cookie' => 'whatever'],
        ],
        'redirect' => 'https://api.exoclass.test/?debug=s3cr3t-value',
    ], ['s3cr3t-value']);

    expect($sanitized['response']['body'])->toBe('no session for '.LogSanitizer::REDACTED)
        ->and($sanitized['response']['headers']['cookie'])->toBe(LogSanitizer::REDACTED)
        ->and($sanitized['redirect'])->toBe('https://api.exoclass.test/?debug='.LogSanitizer::REDACTED);
});

it('leaves non-string leaves alone', function () {
    $sanitized = LogSanitizer::context(['status' => 503, 'ok' => false, 'nothing' => null], ['s3cr3t']);

    expect($sanitized)->toBe(['status' => 503, 'ok' => false, 'nothing' => null]);
});

it('clips a long upstream body after scrubbing it', function () {
    $body = str_repeat('a', 600).'s3cr3t';

    $clipped = LogSanitizer::body($body, ['s3cr3t']);

    expect($clipped)->not->toContain('s3cr3t')
        ->and(mb_strlen($clipped))->toBeLessThanOrEqual(504);
});

it('ignores an empty secret so it cannot redact the whole line', function () {
    expect(LogSanitizer::text('harmless', ['']))->toBe('harmless');
});
