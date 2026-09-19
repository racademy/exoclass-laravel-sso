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

    /**
     * ExoClass answered a scoped question with a body scoped to someone else —
     * or to nobody, which is what it does for an `X-Provider-Key` it cannot
     * resolve. Refusing is the only safe reading: the roles in such a body are
     * the union across every provider, and treating them as roles held at the
     * requested one would grant access nobody granted.
     */
    public static function notScopedToProvider(string $requested, ?string $answered): self
    {
        $answered ??= 'no provider at all';

        return new self(
            "ExoClass was asked about provider {$requested} and answered about {$answered}; "
            .'its roles are not attributable to the requested provider.'
        );
    }
}
