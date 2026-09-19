<?php

declare(strict_types=1);

use ExoClass\Sso\Exceptions\MalformedResponseException;
use ExoClass\Sso\Exceptions\UnauthorizedException;
use ExoClass\Sso\Exceptions\UnavailableException;
use ExoClass\Sso\Http\ExoClassSessionClient;
use ExoClass\Sso\Support\LogSanitizer;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use ReflectionMethod;

function client(): ExoClassSessionClient
{
    return app(ExoClassSessionClient::class);
}

/**
 * The Guzzle options of the PendingRequest the client actually builds.
 *
 * @return array<string, mixed>
 */
function probeOptions(): array
{
    $request = (new ReflectionMethod(ExoClassSessionClient::class, 'request'))
        ->invoke(client(), 'GET', credential(), null);

    assert($request instanceof PendingRequest);

    return $request->getOptions();
}

it('calls users/current on the configured api url and locale', function () {
    Http::fake(['*' => Http::response(ssoFixture('users-current-unscoped'))]);

    $payload = client()->currentUser(credential());

    expect($payload['email'])->toBe('mentorius@robotikosakademija.lt');

    Http::assertSent(fn (Request $request): bool => $request->url() === 'https://api.exoclass.test/api/v1/lt/users/current'
        && $request->method() === 'GET');
});

it('forwards the cookie, the stateful Referer and Origin and asks for JSON', function () {
    Http::fake(['*' => Http::response(ssoFixture('users-current-unscoped'))]);

    client()->currentUser(credential());

    Http::assertSent(function (Request $request): bool {
        expect($request->header('Cookie'))->toBe(['sta_exoclass_session=RAW-EXOCLASS-COOKIE-VALUE-7f3a']);
        expect($request->header('Referer'))->toBe(['https://send.exoclass.test']);
        expect($request->header('Origin'))->toBe(['https://send.exoclass.test']);
        expect($request->header('Accept'))->toBe(['application/json']);
        expect($request->header('X-Provider-Key'))->toBe([]);
        expect($request->header('X-XSRF-TOKEN'))->toBe([]);

        return true;
    });
});

it('scopes the call with X-Provider-Key when a provider key is given', function () {
    Http::fake(['*' => Http::response(ssoFixture('users-current-scoped'))]);

    client()->currentUser(credential(), 'c0ffee00-1111-2222-3333-444455556666');

    Http::assertSent(fn (Request $request): bool => $request->header('X-Provider-Key') === ['c0ffee00-1111-2222-3333-444455556666']);
});

it('accepts a per-call locale override', function () {
    Http::fake(['*' => Http::response(ssoFixture('users-current-unscoped'))]);

    client()->currentUser(credential(), null, 'en');

    Http::assertSent(fn (Request $request): bool => $request->url() === 'https://api.exoclass.test/api/v1/en/users/current');
});

it('throws Unauthorized on 401 and never retries an authoritative verdict', function () {
    Http::fake(['*' => Http::response(['message' => 'Unauthenticated.'], 401)]);

    expect(fn () => client()->currentUser(credential()))
        ->toThrow(UnauthorizedException::class);

    Http::assertSentCount(1);
});

it('throws Unavailable on a 5xx', function () {
    Http::fake(['*' => Http::response('upstream exploded', 503)]);

    expect(fn () => client()->currentUser(credential()))
        ->toThrow(UnavailableException::class);
});

it('throws Unavailable on a connection failure or timeout', function () {
    Http::fake(fn (): never => throw new ConnectionException('cURL error 28: Operation timed out'));

    expect(fn () => client()->currentUser(credential()))
        ->toThrow(UnavailableException::class);
});

it('throws Unavailable on any other unexpected status, never a verdict', function () {
    Http::fake(['*' => Http::response(['message' => 'Forbidden'], 403)]);

    expect(fn () => client()->currentUser(credential()))
        ->toThrow(UnavailableException::class);
});

it('throws Malformed when a 200 carries no JSON object', function () {
    Http::fake(['*' => Http::response('<html>maintenance</html>', 200, ['Content-Type' => 'text/html'])]);

    expect(fn () => client()->currentUser(credential()))
        ->toThrow(MalformedResponseException::class);
});

it('spends the configured probe budget on transient failures only', function () {
    config()->set('exoclass-sso.probe_retry_times', 2);
    Http::fake(['*' => Http::response('nope', 500)]);

    expect(fn () => client()->currentUser(credential()))->toThrow(UnavailableException::class);

    Http::assertSentCount(2);
});

it('keeps the probe budget in milliseconds instead of rounding it up to a second', function (int $ms, float $seconds) {
    config()->set('exoclass-sso.probe_timeout_ms', $ms);

    expect(client()->probeTimeoutSeconds())->toBe($seconds);
})->with([
    'the shipped default is 1.5 s, not 2 s' => [1500, 1.5],
    'a tightened half-second stays half a second' => [500, 0.5],
    'a whole second is still a whole second' => [3000, 3.0],
    'an absurd 0 is floored, not turned into a second' => [0, 0.05],
]);

it('puts the configured timeout on the request that actually goes out', function (int $ms, float $seconds) {
    config()->set('exoclass-sso.probe_timeout_ms', $ms);

    // Reaching into the private builder is the point: asserting on the helper
    // alone let `->timeout(...)` be deleted with every test still green.
    expect(probeOptions()['timeout'])->toBe($seconds);
})->with([
    'default' => [1500, 1.5],
    'tightened' => [400, 0.4],
]);

it('logs out upstream with the paired XSRF token', function () {
    Http::fake(['*' => Http::response('', 204)]);

    client()->logout(credential(), 'XSRF-TOKEN-VALUE-abc');

    Http::assertSent(function (Request $request): bool {
        expect($request->url())->toBe('https://api.exoclass.test/api/v1/lt/auth/logout');
        expect($request->method())->toBe('POST');
        expect($request->header('Cookie'))->toBe(['sta_exoclass_session=RAW-EXOCLASS-COOKIE-VALUE-7f3a']);
        expect($request->header('X-XSRF-TOKEN'))->toBe(['XSRF-TOKEN-VALUE-abc']);
        expect($request->header('Referer'))->toBe(['https://send.exoclass.test']);

        return true;
    });
});

it('reports an upstream logout failure instead of throwing at the caller', function () {
    Http::fake(['*' => Http::response('nope', 500)]);

    expect(client()->logout(credential(), 'XSRF-TOKEN-VALUE-abc'))->toBeFalse();
});

it('never writes the cookie value or the XSRF token to the log', function () {
    $log = captureLog();

    // Worst case: the upstream error body reflects the credential back at us.
    Http::fake(['*' => Http::response('session RAW-EXOCLASS-COOKIE-VALUE-7f3a rejected by XSRF-TOKEN-VALUE-abc', 500)]);

    expect(fn () => client()->currentUser(credential('RAW-EXOCLASS-COOKIE-VALUE-7f3a', 'XSRF-TOKEN-VALUE-abc')))
        ->toThrow(UnavailableException::class);

    $written = file_exists($log) ? (string) file_get_contents($log) : '';

    expect($written)->not->toBe('')
        ->and($written)->not->toContain('RAW-EXOCLASS-COOKIE-VALUE-7f3a')
        ->and($written)->not->toContain('XSRF-TOKEN-VALUE-abc')
        ->and($written)->toContain(LogSanitizer::REDACTED);

    @unlink($log);
});

it('never puts the cookie value into an exception message', function () {
    Http::fake(['*' => Http::response('session RAW-EXOCLASS-COOKIE-VALUE-7f3a rejected', 500)]);

    try {
        client()->currentUser(credential());
        $message = '';
    } catch (UnavailableException $exception) {
        $message = $exception->getMessage().' '.$exception->getTraceAsString();
    }

    expect($message)->not->toContain('RAW-EXOCLASS-COOKIE-VALUE-7f3a');
});
