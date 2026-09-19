<?php

declare(strict_types=1);

namespace ExoClass\Sso\Exceptions;

/**
 * ExoClass answered 401: the forwarded session cookie is absent, expired or
 * belongs to a logged-out session. This is an AUTHORITATIVE verdict — the
 * middleware treats it as "this visitor is a guest" and falls through to the
 * login page without retrying.
 */
final class UnauthorizedException extends ExoClassSsoException
{
    public static function forUrl(string $url): self
    {
        return new self("ExoClass rejected the forwarded session cookie (401) at {$url}.");
    }
}
