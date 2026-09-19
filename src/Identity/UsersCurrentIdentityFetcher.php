<?php

declare(strict_types=1);

namespace ExoClass\Sso\Identity;

use ExoClass\Sso\Contracts\IdentityFetcher;
use ExoClass\Sso\Exceptions\UnauthorizedException;
use ExoClass\Sso\Exceptions\UnavailableException;
use ExoClass\Sso\Http\ExoClassSessionClient;
use ExoClass\Sso\Http\SessionCredential;

/**
 * The default fetcher: one unscoped `users/current` call for the identity, plus
 * one scoped call per provider the resolver actually asks about.
 *
 * The two-step dance exists because ExoClass's unscoped answer lists every
 * employer but gives a flat, unattributed `roles[]` — "is this person a
 * provider admin AT employer #42" is simply not in it. The scoped call
 * (`X-Provider-Key`) is the only way to ask. A resolver that checks one
 * candidate therefore pays two round trips; one that checks five pays six, and
 * a future dedicated `auth/identity` endpoint would collapse all of it to one
 * without changing a single caller.
 */
final readonly class UsersCurrentIdentityFetcher implements IdentityFetcher
{
    public function __construct(private ExoClassSessionClient $client) {}

    /**
     * @throws UnauthorizedException
     * @throws UnavailableException
     */
    public function fetch(SessionCredential $credential): ExoClassIdentity
    {
        $payload = $this->client->currentUser($credential);

        return ExoClassIdentity::fromArray(
            $payload,
            /**
             * @return list<string>
             */
            function (string $providerKey) use ($credential): array {
                $scoped = $this->client->currentUser($credential, $providerKey);
                $body = is_array($scoped['data'] ?? null) ? $scoped['data'] : $scoped;
                $user = is_array($body['user'] ?? null) ? $body['user'] : $body;

                return ExoClassIdentity::parseRoleNames($user['roles'] ?? $body['roles'] ?? null);
            },
        );
    }
}
