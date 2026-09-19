<?php

declare(strict_types=1);

namespace ExoClass\Sso\Http;

use ExoClass\Sso\Exceptions\ExoClassSsoException;
use ExoClass\Sso\Exceptions\MalformedResponseException;
use ExoClass\Sso\Exceptions\UnauthorizedException;
use ExoClass\Sso\Exceptions\UnavailableException;
use ExoClass\Sso\Support\LogSanitizer;
use ExoClass\Sso\Support\SsoLogger;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Http\Client\RequestException;
use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Http;
use LogicException;
use Throwable;

/**
 * The only thing in this package that talks to ExoClass.
 *
 * It forwards the browser's ExoClass session cookie to
 * `GET {api_url}/{locale}/users/current` and reports back ExoClass's verdict.
 * Three rules shape everything here:
 *
 *  1. REFERER AND ORIGIN ARE NOT OPTIONAL. Laravel's HTTP client sends no
 *     `Referer` of its own, and without one ExoClass's Sanctum
 *     `EnsureFrontendRequestsAreStateful` classifies the forwarded call as
 *     stateless, skips the session guard and answers 401 — the single failure
 *     that cost RA Portal the most time (finding H-3). Both headers carry the
 *     configured bare origin, which ExoClass must list in
 *     `SANCTUM_STATEFUL_DOMAINS`.
 *
 *  2. THIS IS AN INTERACTIVE PROBE, NOT A BACKGROUND JOB. A visitor is waiting
 *     behind it, so the budget is one attempt and ~1.5 s by default, and a 401
 *     — the ordinary answer for a visitor who simply is not signed into
 *     ExoClass — is never retried.
 *
 *  3. ONLY A 401 IS A VERDICT. Timeouts, 5xx and every other unexpected status
 *     mean "we could not ask", never "the session is dead": they surface as
 *     {@see UnavailableException} so callers fail soft and leave both the login
 *     page and any existing session alone.
 */
final class ExoClassSessionClient
{
    public function __construct(
        private readonly Repository $config,
        private readonly SsoLogger $logger = new SsoLogger,
    ) {}

    /**
     * Validate the credential upstream and return the raw `users/current`
     * payload. With `$providerKey` the answer is scoped to that ExoClass
     * provider (roles and employers filtered, `provider_info` populated);
     * without it ExoClass returns every employer and an unattributed role list.
     *
     * @return array<array-key, mixed>
     *
     * @throws UnauthorizedException 401 — authoritative "no valid session"
     * @throws UnavailableException transport failure, timeout, 5xx, or any other status
     * @throws MalformedResponseException 2xx whose body is not a JSON object
     */
    public function currentUser(SessionCredential $credential, ?string $providerKey = null, ?string $locale = null): array
    {
        $path = $this->localePath($locale).'users/current';

        $response = $this->dispatch('GET', $path, $credential, $providerKey);

        $payload = $response->json();

        if (! is_array($payload) || $payload === []) {
            $this->logger->warning('ExoClass SSO probe returned an unusable body.', [
                'url' => $this->absoluteUrl($path),
                'status' => $response->status(),
                'body' => LogSanitizer::body($response->body(), $credential->redactable()),
            ], $credential->redactable());

            throw MalformedResponseException::notJson($this->absoluteUrl($path));
        }

        return $payload;
    }

    /**
     * End the ExoClass session itself, so a logout here is a logout everywhere
     * (decision D-5). Soft-fails: a failed upstream logout must never block the
     * local sign-out, so this reports `false` instead of throwing.
     */
    public function logout(SessionCredential $credential, string $xsrfToken, ?string $locale = null): bool
    {
        $path = $this->localePath($locale).'auth/logout';

        try {
            $this->dispatch('POST', $path, $credential->withXsrfToken($xsrfToken), null);

            return true;
        } catch (ExoClassSsoException $exception) {
            $this->logger->warning('ExoClass SSO upstream logout failed; signing out locally anyway.', [
                'url' => $this->absoluteUrl($path),
                'exception' => $exception::class,
                'reason' => $exception->getMessage(),
            ], $credential->redactable());

            return false;
        }
    }

    /**
     * The wall-clock ceiling of one probe, in seconds — the configured
     * millisecond budget exactly, NOT rounded up to the next second.
     *
     * `PendingRequest::timeout()` is declared `int|float` on both supported
     * majors and hands the value straight to Guzzle, so the operator who caps a
     * cold guest page at 1.5 s gets 1.5 s. The old whole-second rounding handed
     * them 2 s, and turned a tightened 500 ms into 1 s — always the ceiling
     * they did not configure.
     */
    public function probeTimeoutSeconds(): float
    {
        $ms = (int) $this->config->get('exoclass-sso.probe_timeout_ms', 1500);

        return max(0.05, $ms / 1000);
    }

    /**
     * Attempts (not re-tries) one probe may spend.
     */
    public function probeAttempts(): int
    {
        return max(1, (int) $this->config->get('exoclass-sso.probe_retry_times', 1));
    }

    /**
     * @throws ExoClassSsoException
     */
    private function dispatch(string $method, string $path, SessionCredential $credential, ?string $providerKey): Response
    {
        $url = $this->absoluteUrl($path);

        try {
            $request = $this->request($method, $credential, $providerKey);

            $response = match ($method) {
                'GET' => $request->get($path),
                'POST' => $request->post($path),
                default => throw new LogicException("Unsupported ExoClass SSO verb: {$method}."),
            };
        } catch (ConnectionException $exception) {
            $this->logger->warning('ExoClass SSO probe could not reach ExoClass.', [
                'url' => $url,
                'method' => $method,
                'reason' => LogSanitizer::text($exception->getMessage(), $credential->redactable()),
            ], $credential->redactable());

            throw UnavailableException::fromTransport($url, $exception);
        } catch (RequestException $exception) {
            // A retry budget of one leaves the failed response un-thrown, but a
            // caller-supplied middleware could still turn one into an exception.
            $response = $exception->response;
        }

        if ($response->successful()) {
            return $response;
        }

        if ($response->status() === 401) {
            // The ordinary answer for a visitor who is not signed into
            // ExoClass. Deliberately not logged: it is not an incident, and on
            // a public page it would be the most frequent line in the log.
            throw UnauthorizedException::forUrl($url);
        }

        $this->logger->warning('ExoClass SSO probe got no usable verdict.', [
            'url' => $url,
            'method' => $method,
            'status' => $response->status(),
            'body' => LogSanitizer::body($response->body(), $credential->redactable()),
        ], $credential->redactable());

        throw UnavailableException::fromStatus($url, $response->status());
    }

    private function request(string $method, SessionCredential $credential, ?string $providerKey): PendingRequest
    {
        return Http::baseUrl($this->apiUrl())
            ->withHeaders($this->headers($method, $credential, $providerKey))
            ->acceptJson()
            ->timeout($this->probeTimeoutSeconds())
            ->retry(
                $this->probeAttempts(),
                100,
                when: self::shouldRetry(...),
                throw: false,
            );
    }

    /**
     * @return array<string, string>
     */
    private function headers(string $method, SessionCredential $credential, ?string $providerKey): array
    {
        $referer = $this->statefulReferer();

        $headers = [
            'Cookie' => $credential->cookieHeader(),
            'Referer' => $referer,
            'Origin' => $referer,
        ];

        if ($providerKey !== null && trim($providerKey) !== '') {
            $headers['X-Provider-Key'] = $providerKey;
        }

        // GET/HEAD/OPTIONS are CSRF-exempt upstream, so the XSRF token is sent
        // only where it is actually needed — one fewer secret on the wire.
        if (! in_array($method, ['GET', 'HEAD', 'OPTIONS'], true) && $credential->xsrfToken !== null) {
            $headers['X-XSRF-TOKEN'] = $credential->xsrfToken;
        }

        return $headers;
    }

    /**
     * Retry transport failures and 5xx; never retry a verdict. Re-sending a
     * 401 only makes a signed-out visitor wait longer for the same answer.
     */
    private static function shouldRetry(Throwable $exception): bool
    {
        if ($exception instanceof ConnectionException) {
            return true;
        }

        if ($exception instanceof RequestException) {
            return $exception->response->serverError();
        }

        return false;
    }

    private function apiUrl(): string
    {
        $url = trim((string) $this->config->get('exoclass-sso.api_url', ''));

        if ($url === '') {
            throw new LogicException('exoclass-sso.api_url is not configured (set EXOCLASS_SSO_API_URL).');
        }

        return rtrim($url, '/');
    }

    private function statefulReferer(): string
    {
        $referer = trim((string) $this->config->get('exoclass-sso.stateful_referer', ''));

        if ($referer === '') {
            throw new LogicException(
                'exoclass-sso.stateful_referer is not configured. ExoClass answers 401 without a Referer '
                .'matching its SANCTUM_STATEFUL_DOMAINS.'
            );
        }

        return rtrim($referer, '/');
    }

    private function localePath(?string $locale): string
    {
        $resolved = trim($locale ?? (string) $this->config->get('exoclass-sso.locale', 'lt'), '/');

        return $resolved === '' ? '' : $resolved.'/';
    }

    private function absoluteUrl(string $path): string
    {
        return $this->apiUrl().'/'.ltrim($path, '/');
    }
}
