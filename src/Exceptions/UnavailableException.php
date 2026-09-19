<?php

declare(strict_types=1);

namespace ExoClass\Sso\Exceptions;

use Throwable;

/**
 * ExoClass produced no usable verdict: a connection error, a timeout, a 5xx,
 * or any other unexpected status. Callers MUST fail soft — never block the
 * login page and never tear down an existing session on this exception, since
 * "we could not ask" is not "the session is dead".
 */
final class UnavailableException extends ExoClassSsoException
{
    public static function fromTransport(string $url, Throwable $previous): self
    {
        return new self("ExoClass is unreachable at {$url}: ".$previous->getMessage(), 0, $previous);
    }

    public static function fromStatus(string $url, int $status): self
    {
        return new self("ExoClass returned HTTP {$status} at {$url}.", $status);
    }
}
