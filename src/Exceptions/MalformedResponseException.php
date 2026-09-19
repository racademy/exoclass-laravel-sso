<?php

declare(strict_types=1);

namespace ExoClass\Sso\Exceptions;

/**
 * ExoClass answered 2xx with a body this package cannot trust: not JSON, not an
 * object, or missing the identifying user fields. A malformed answer is never
 * treated as an identity.
 */
final class MalformedResponseException extends ExoClassSsoException
{
    public static function notJson(string $url): self
    {
        return new self("ExoClass returned a non-JSON or empty body at {$url}.");
    }

    public static function missingUser(string $url): self
    {
        return new self("ExoClass returned a JSON body without an identifiable user at {$url}.");
    }
}
