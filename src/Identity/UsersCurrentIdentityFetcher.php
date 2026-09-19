<?php

declare(strict_types=1);

namespace ExoClass\Sso\Identity;

use ExoClass\Sso\Contracts\IdentityFetcher;
use ExoClass\Sso\Exceptions\MalformedResponseException;
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
 *
 * AND THE SCOPED ANSWER IS CHECKED, not assumed. ExoClass does not reject an
 * `X-Provider-Key` it cannot resolve — `UserController::currentUser` discards
 * the result of `resolveIdFromExternalKey()` and falls through to the
 * unfiltered branch, answering 200 with every employer and the union of the
 * user's roles across all of them. A stale key, a re-keyed provider, a staging
 * key sent at a prod `api_url` or a numeric id passed where the uuid belongs
 * would therefore each turn `hasRoleAt()` into a yes for a provider the user
 * has no relationship with. So the roles are believed only when the answer's
 * own `provider_info` names the provider that was asked about; anything else
 * is a {@see MalformedResponseException}. This primitive fails CLOSED.
 */
final readonly class UsersCurrentIdentityFetcher implements IdentityFetcher
{
    public function __construct(private ExoClassSessionClient $client) {}

    /**
     * @throws UnauthorizedException
     * @throws UnavailableException
     * @throws MalformedResponseException
     */
    public function fetch(SessionCredential $credential): ExoClassIdentity
    {
        $payload = $this->client->currentUser($credential);

        return ExoClassIdentity::fromArray(
            $payload,
            /**
             * @return list<string>
             *
             * @throws MalformedResponseException when ExoClass did not scope its answer to $providerKey
             */
            function (string $providerKey) use ($credential): array {
                $scoped = ExoClassIdentity::fromArray($this->client->currentUser($credential, $providerKey));

                if ($scoped->providerInfo?->matches($providerKey) !== true) {
                    throw MalformedResponseException::notScopedToProvider(
                        $providerKey,
                        $scoped->providerInfo?->externalKey,
                    );
                }

                return $scoped->roles;
            },
        );
    }
}
