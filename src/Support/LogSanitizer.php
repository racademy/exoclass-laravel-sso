<?php

declare(strict_types=1);

namespace ExoClass\Sso\Support;

use Illuminate\Support\Str;

/**
 * Single choke point for everything this package writes to a log.
 *
 * Two independent defences, because either one alone leaks:
 *   1. NAME-based: any array key that names a credential-bearing header or
 *      field (`cookie`, `set-cookie`, `x-xsrf-token`, ...) is replaced wholesale,
 *      at any depth, whatever its value.
 *   2. VALUE-based: the caller passes the live secrets (the raw session cookie
 *      value, the XSRF token) and every occurrence of those strings is scrubbed
 *      from every message and every remaining string — including places where a
 *      secret was interpolated into a URL, an upstream body or an exception
 *      message under an innocent key.
 *
 * Ported from RA Portal's `BaseExoClassClient::sanitizeHeaders()` /
 * `sanitizePayload()` and narrowed to the SSO surface.
 */
final class LogSanitizer
{
    public const REDACTED = '[redacted]';

    /** Max characters of an upstream body kept in a log line. */
    private const BODY_LIMIT = 500;

    /**
     * Header and field names whose VALUE is a credential.
     *
     * @var list<string>
     */
    private const REDACTED_NAMES = [
        'cookie',
        'cookies',
        'set-cookie',
        'x-xsrf-token',
        'xsrf-token',
        'xsrf_token',
        'xsrftoken',
        'authorization',
        'proxy-authorization',
        'x-api-key',
        'x-auth-token',
        'x-provider-key',
        'password',
        'access_token',
        'token',
    ];

    /**
     * Sanitize a log context: redact by key name, then scrub known secrets out
     * of every surviving string.
     *
     * @param  array<array-key, mixed>  $context
     * @param  list<string>  $secrets
     * @return array<array-key, mixed>
     */
    public static function context(array $context, array $secrets = []): array
    {
        $sanitized = [];

        foreach ($context as $key => $value) {
            if (is_string($key) && self::isRedactedName($key)) {
                $sanitized[$key] = self::REDACTED;

                continue;
            }

            $sanitized[$key] = self::value($value, $secrets);
        }

        return $sanitized;
    }

    /**
     * Scrub every known secret out of a free-text string (log message, upstream
     * body, exception message).
     *
     * @param  list<string>  $secrets
     */
    public static function text(string $text, array $secrets = []): string
    {
        foreach ($secrets as $secret) {
            if ($secret === '') {
                continue;
            }

            $text = str_replace($secret, self::REDACTED, $text);
        }

        return $text;
    }

    /**
     * Clip an upstream response body to something a log line can carry, after
     * scrubbing it.
     *
     * @param  list<string>  $secrets
     */
    public static function body(string $body, array $secrets = []): string
    {
        return Str::limit(self::text($body, $secrets), self::BODY_LIMIT);
    }

    /**
     * @param  list<string>  $secrets
     */
    private static function value(mixed $value, array $secrets): mixed
    {
        if (is_string($value)) {
            return self::text($value, $secrets);
        }

        if (is_array($value)) {
            return self::context($value, $secrets);
        }

        return $value;
    }

    private static function isRedactedName(string $key): bool
    {
        return in_array(strtolower(str_replace('_', '-', $key)), array_map(
            static fn (string $name): string => str_replace('_', '-', $name),
            self::REDACTED_NAMES,
        ), true);
    }
}
