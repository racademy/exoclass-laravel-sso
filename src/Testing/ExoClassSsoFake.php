<?php

declare(strict_types=1);

namespace ExoClass\Sso\Testing;

use ExoClass\Sso\Support\CookieExemptions;
use Illuminate\Cookie\Middleware\EncryptCookies;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use JsonException;
use PHPUnit\Framework\Assert;
use RuntimeException;

/**
 * ExoClass, faked, so an app can test its own half of the integration.
 *
 * Every subsystem adopting this package has the same three tests to write —
 * a visitor is signed in, a visitor is refused, a logout is forwarded — and
 * without a kit each of them re-derives the shape of `users/current`, the
 * header ExoClass insists on, and the difference between 401 and 503. This is
 * that kit.
 *
 *     $sso = ExoClassSsoFake::fake()->scoped('c0ffee00-…');
 *
 *     $sso->withExoClassCookie($this, 'any-value')
 *         ->get('/admin')
 *         ->assertOk();
 *
 *     $sso->assertProbed();
 *
 * It is faithful about the two things that are easy to get wrong:
 *
 *  - An `X-Provider-Key` it does not know answers with the UNSCOPED body, which
 *    is what real ExoClass does — it discards a key it cannot resolve and
 *    returns 200 with every employer and the union of the user's roles. A test
 *    written against a stricter fake would pass while production granted access
 *    nobody granted.
 *  - `unavailable()` and `unreachable()` are not `unauthorized()`. Only 401 is
 *    a verdict; everything else must leave sessions and the login page alone,
 *    and an app should have a test saying so.
 */
final class ExoClassSsoFake
{
    private const MODE_OK = 'ok';

    private const MODE_UNAUTHORIZED = 'unauthorized';

    private const MODE_UNAVAILABLE = 'unavailable';

    private const MODE_UNREACHABLE = 'unreachable';

    private const MODE_MALFORMED = 'malformed';

    private string $mode = self::MODE_OK;

    private int $unavailableStatus = 503;

    /** @var array<array-key, mixed> */
    private array $unscoped;

    /** @var array<string, array<array-key, mixed>> */
    private array $scoped = [];

    private bool $logoutSucceeds = true;

    /** @var list<string> */
    private array $secrets = [];

    /** Unscoped `users/current` calls: the identity probe. */
    private int $probes = 0;

    /** Scoped calls, by provider key: the role lookups. */
    private int $scopedCalls = 0;

    /** @var list<array{xsrf: string|null, cookie: string|null}> */
    private array $logouts = [];

    private function __construct()
    {
        $this->unscoped = self::fixture('users-current-unscoped');
    }

    /**
     * Install the fake. Call once per test, then shape it with the methods
     * below — they mutate this instance rather than registering more stubs, so
     * the last word always wins.
     */
    public static function fake(): self
    {
        $fake = new self;

        Http::fake(static fn (Request $request) => $fake->answer($request));

        return $fake;
    }

    /**
     * The body the unscoped `users/current` returns — who the visitor is and
     * where they work.
     *
     * @param  array<array-key, mixed>|null  $fixture
     */
    public function unscoped(?array $fixture = null): self
    {
        $this->unscoped = $fixture ?? self::fixture('users-current-unscoped');
        $this->mode = self::MODE_OK;

        return $this;
    }

    /**
     * The body a call carrying this `X-Provider-Key` returns — the user's roles
     * AT that provider.
     *
     * The default fixture is re-stamped with the key asked for, because the
     * package refuses a scoped answer whose own `provider_info` names somebody
     * else, and a kit that tripped that check on every use would be useless.
     *
     * @param  array<array-key, mixed>|null  $fixture
     */
    public function scoped(string $providerKey, ?array $fixture = null): self
    {
        $payload = $fixture ?? self::fixture('users-current-scoped');

        if ($fixture === null) {
            $providerInfo = is_array($payload['provider_info'] ?? null) ? $payload['provider_info'] : [];
            $payload['provider_info'] = [...$providerInfo, 'external_key' => $providerKey];
        }

        $this->scoped[$providerKey] = $payload;
        $this->mode = self::MODE_OK;

        return $this;
    }

    /**
     * ExoClass says 401: this visitor has no valid session. The one
     * authoritative answer.
     */
    public function unauthorized(): self
    {
        $this->mode = self::MODE_UNAUTHORIZED;

        return $this;
    }

    /**
     * ExoClass answers, but with nothing usable — a 5xx, a gateway page, a
     * status nobody expected.
     */
    public function unavailable(int $status = 503): self
    {
        $this->mode = self::MODE_UNAVAILABLE;
        $this->unavailableStatus = $status;

        return $this;
    }

    /**
     * ExoClass does not answer at all: DNS, a dropped connection, a timeout.
     */
    public function unreachable(): self
    {
        $this->mode = self::MODE_UNREACHABLE;

        return $this;
    }

    /**
     * A 200 whose body this package cannot trust.
     */
    public function malformed(): self
    {
        $this->mode = self::MODE_MALFORMED;

        return $this;
    }

    public function logoutOk(): self
    {
        $this->logoutSucceeds = true;

        return $this;
    }

    /**
     * ExoClass refuses the logout — usually a CSRF rejection. Sign-out must
     * still complete locally, and an app should have a test saying so.
     */
    public function logoutFails(): self
    {
        $this->logoutSucceeds = false;

        return $this;
    }

    /**
     * Give the next request the ExoClass cookie, the way a browser under
     * `.exoclass.com` would.
     *
     * Also applies the encryption exemption the host app needs in
     * `bootstrap/app.php` — without it Laravel nulls the cookie and the test
     * fails for a reason that has nothing to do with what it is testing. An app
     * should still have one test WITHOUT this helper proving its own exemption
     * is wired up.
     *
     * Typed loosely on purpose: a host app's base test case may extend
     * Laravel's or Testbench's, and those two share no common ancestor.
     *
     * @template TTestCase of object
     *
     * @param  TTestCase  $testCase  a test case using Laravel's MakesHttpRequests
     * @return TTestCase the same test case, so `->get(…)` chains
     */
    public function withExoClassCookie(object $testCase, string $value, ?string $xsrf = null): object
    {
        if (! method_exists($testCase, 'withUnencryptedCookies')) {
            throw new RuntimeException(sprintf(
                '%s cannot carry an ExoClass cookie: it does not use Laravel\'s MakesHttpRequests.',
                $testCase::class,
            ));
        }

        $this->secrets[] = $value;

        $names = CookieExemptions::names();
        EncryptCookies::except($names);

        $cookies = [$names[0] ?? 'exoclass_session' => $value];

        if ($xsrf !== null) {
            $this->secrets[] = $xsrf;
            $cookies[$names[1] ?? 'EXO-XSRF-TOKEN'] = $xsrf;
        }

        $testCase->withUnencryptedCookies($cookies);

        return $testCase;
    }

    /**
     * How many times the identity was asked for upstream.
     */
    public function assertProbed(int $times = 1): self
    {
        Assert::assertSame($times, $this->probes, sprintf(
            'Expected ExoClass to be asked for the identity %d time(s), but it was asked %d time(s).',
            $times,
            $this->probes,
        ));

        return $this;
    }

    /**
     * Nothing was asked of ExoClass at all — the assertion behind every
     * throttle, every exempt path and every password session.
     */
    public function assertNotProbed(): self
    {
        Assert::assertSame(0, $this->probes + $this->scopedCalls, sprintf(
            'Expected ExoClass not to be asked anything, but it answered %d identity call(s) and %d role call(s).',
            $this->probes,
            $this->scopedCalls,
        ));

        return $this;
    }

    /**
     * The logout reached ExoClass carrying the browser's XSRF token — the thing
     * ExoClass's CSRF gate refuses the call without.
     */
    public function assertLogoutForwardedWithXsrf(?string $xsrf = null): self
    {
        Assert::assertNotEmpty($this->logouts, 'Expected a logout to be forwarded to ExoClass, but none was.');

        $tokens = array_map(static fn (array $logout): ?string => $logout['xsrf'], $this->logouts);

        if ($xsrf !== null) {
            Assert::assertContains($xsrf, $tokens, 'The logout did not carry the expected XSRF token.');

            return $this;
        }

        Assert::assertNotEmpty(
            array_filter($tokens, static fn (?string $token): bool => $token !== null && $token !== ''),
            'A logout was forwarded, but with no X-XSRF-TOKEN header — ExoClass will refuse it as a CSRF failure.',
        );

        return $this;
    }

    /**
     * Nothing secret reached the log.
     *
     * Point it at a log file (or any captured text) and it fails if the cookie
     * value or the XSRF token this fake handed out appears anywhere in it —
     * including reflected inside an upstream error body or an exception message.
     */
    public function assertNothingLeaked(string $logPathOrContents, string ...$alsoSecret): self
    {
        $contents = is_file($logPathOrContents)
            ? (string) file_get_contents($logPathOrContents)
            : $logPathOrContents;

        foreach ([...$this->secrets, ...$alsoSecret] as $secret) {
            if ($secret === '') {
                continue;
            }

            Assert::assertStringNotContainsString(
                $secret,
                $contents,
                'A credential this fake handed out was written to the log.',
            );
        }

        return $this;
    }

    /**
     * A committed ExoClass response shape, for a test that wants to bend one.
     *
     * @return array<array-key, mixed>
     */
    public static function fixture(string $name): array
    {
        $path = __DIR__.'/../../fixtures/'.$name.'.json';

        if (! is_file($path)) {
            throw new RuntimeException("ExoClassSsoFake has no fixture named {$name}.");
        }

        try {
            $decoded = json_decode((string) file_get_contents($path), true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new RuntimeException("ExoClassSsoFake could not read the fixture {$name}.", 0, $exception);
        }

        return is_array($decoded) ? $decoded : [];
    }

    private function answer(Request $request): mixed
    {
        $url = $request->url();

        if (str_contains($url, 'auth/logout')) {
            $this->logouts[] = [
                'xsrf' => $request->header('X-XSRF-TOKEN')[0] ?? null,
                'cookie' => $request->header('Cookie')[0] ?? null,
            ];

            return $this->logoutSucceeds
                ? Http::response(status: 204)
                : Http::response(['message' => 'CSRF token mismatch.'], 419);
        }

        if (! str_contains($url, 'users/current')) {
            return Http::response([
                'message' => "ExoClassSsoFake was asked for {$url}, which is not part of the SSO surface.",
            ], 404);
        }

        $providerKey = $request->header('X-Provider-Key')[0] ?? null;

        if (is_string($providerKey) && $providerKey !== '') {
            $this->scopedCalls++;
        } else {
            $this->probes++;
        }

        return match ($this->mode) {
            self::MODE_UNAUTHORIZED => Http::response(['message' => 'Unauthenticated.'], 401),
            self::MODE_UNAVAILABLE => Http::response('<html><body>Bad gateway</body></html>', $this->unavailableStatus),
            self::MODE_UNREACHABLE => throw new ConnectionException('cURL error 28: Operation timed out.'),
            self::MODE_MALFORMED => Http::response(['status' => 'ok']),
            default => Http::response($this->payloadFor(is_string($providerKey) ? $providerKey : null)),
        };
    }

    /**
     * @return array<array-key, mixed>
     */
    private function payloadFor(?string $providerKey): array
    {
        if ($providerKey === null) {
            return $this->unscoped;
        }

        // The fidelity that matters: ExoClass does NOT reject a provider key it
        // cannot resolve. It falls through to the unfiltered branch and answers
        // 200 with everything — which is why the package checks `provider_info`
        // and why this fake must be able to reproduce it.
        return $this->scoped[$providerKey] ?? $this->unscoped;
    }
}
