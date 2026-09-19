<?php

declare(strict_types=1);

namespace ExoClass\Sso\Identity;

use Closure;
use ExoClass\Sso\Exceptions\MalformedResponseException;
use InvalidArgumentException;
use LogicException;

/**
 * The identity ExoClass reports for a forwarded session cookie.
 *
 * Parsing is deliberately forgiving about ENVELOPES and SPELLINGS, because the
 * same logical payload reaches us in several shapes (RA Portal's
 * `AuthLoginResponse::fromArray` learned each of them the hard way):
 *
 *   - `users/current` returns the user resource BARE, with `provider_info`
 *     glued on at the top level;
 *   - other ExoClass controllers wrap the same body in `{"data": {...}}`;
 *   - `/auth/login` emits `provider_info` while `/auth/login-v2` emits
 *     `provider` for the very same object;
 *   - `roles` / `employers` sit inside the user object on some routes and
 *     beside it on others.
 *
 * It is NOT forgiving about substance: a payload without an identifiable user
 * is a {@see MalformedResponseException}, never an anonymous identity.
 *
 * ROLES. Unscoped `users/current` returns a flat `roles[]` with no provider
 * attribution, so "which role does this user hold AT provider X" can only be
 * answered by a second, scoped call ({@see rolesFor()}). That call runs at most
 * once per provider key per identity instance.
 */
final class ExoClassIdentity
{
    /**
     * Memoized scoped role lookups, keyed by provider external key.
     *
     * @var array<string, list<string>>
     */
    private array $rolesCache = [];

    /**
     * @param  list<Employer>  $employers
     * @param  list<string>  $roles  role names carried by THIS payload: provider-scoped
     *                               when the payload came from a scoped call, otherwise
     *                               the union across every provider (not attributable).
     * @param  ProviderInfo|null  $providerInfo  the provider ExoClass says it scoped this
     *                                           payload to, or null when it scoped it to nobody
     * @param  (Closure(string): list<string>)|null  $rolesLoader  performs the scoped call
     */
    public function __construct(
        public readonly ExoClassUser $user,
        public readonly array $employers = [],
        public readonly array $roles = [],
        public readonly ?ProviderInfo $providerInfo = null,
        private readonly ?Closure $rolesLoader = null,
    ) {}

    /**
     * @param  array<array-key, mixed>  $payload
     * @param  (Closure(string): list<string>)|null  $rolesLoader
     *
     * @throws MalformedResponseException when the payload carries no user
     */
    public static function fromArray(array $payload, ?Closure $rolesLoader = null, string $url = ''): self
    {
        $body = self::asMap($payload['data'] ?? null) ?? self::asMap($payload) ?? [];
        $user = self::asMap($body['user'] ?? null) ?? $body;

        $id = $user['id'] ?? null;
        $email = $user['email'] ?? null;

        if (! is_int($id) && ! (is_string($id) && $id !== '' && ctype_digit($id))) {
            throw MalformedResponseException::missingUser($url);
        }

        if (! is_string($email) || trim($email) === '') {
            throw MalformedResponseException::missingUser($url);
        }

        return new self(
            user: new ExoClassUser(
                id: (int) $id,
                externalKey: self::asString($user['external_key'] ?? null) ?? '',
                email: $email,
                firstName: self::asString($user['first_name'] ?? null),
                lastName: self::asString($user['last_name'] ?? null),
                language: self::asString($user['language'] ?? null),
            ),
            employers: self::parseEmployers($user['employers'] ?? $body['employers'] ?? null),
            roles: self::parseRoleNames($user['roles'] ?? $body['roles'] ?? null),
            providerInfo: self::parseProviderInfo(
                $user['provider_info'] ?? $user['provider'] ?? $body['provider_info'] ?? $body['provider'] ?? null
            ),
            rolesLoader: $rolesLoader,
        );
    }

    /**
     * Role names this user holds AT the given provider, via the scoped
     * `users/current` call. Memoized per provider key for the lifetime of this
     * instance, so a resolver may ask once per candidate without fear.
     *
     * @return list<string>
     */
    public function rolesFor(string $providerKey): array
    {
        if (trim($providerKey) === '') {
            // A blank key is not "ask about nobody", it is a caller bug — and
            // upstream would answer it with the unattributed union.
            throw new InvalidArgumentException(
                'A provider external key is required to ask which roles a user holds AT a provider.'
            );
        }

        if (array_key_exists($providerKey, $this->rolesCache)) {
            return $this->rolesCache[$providerKey];
        }

        if ($this->rolesLoader === null) {
            throw new LogicException(
                'This ExoClassIdentity has no roles loader bound, so it cannot answer rolesFor(). '
                .'Build it through an IdentityFetcher, or pass a loader closure to the constructor.'
            );
        }

        return $this->rolesCache[$providerKey] = ($this->rolesLoader)($providerKey);
    }

    public function hasRoleAt(string $providerKey, string ...$roles): bool
    {
        $held = array_map(strtolower(...), $this->rolesFor($providerKey));

        foreach ($roles as $role) {
            if (in_array(strtolower($role), $held, true)) {
                return true;
            }
        }

        return false;
    }

    public function employerByExternalKey(string $externalKey): ?Employer
    {
        foreach ($this->employers as $employer) {
            if ($employer->externalKey === $externalKey) {
                return $employer;
            }
        }

        return null;
    }

    /**
     * Role names out of an ExoClass `roles[]` block, which carries objects
     * (`{id, name, permissions}`) on every current route but is accepted as a
     * list of plain strings too.
     *
     * @return list<string>
     */
    public static function parseRoleNames(mixed $roles): array
    {
        if (! is_array($roles)) {
            return [];
        }

        $names = [];

        foreach ($roles as $role) {
            if (is_string($role) && $role !== '') {
                $names[] = $role;

                continue;
            }

            if (is_array($role)) {
                $name = self::asString($role['name'] ?? null);

                if ($name !== null) {
                    $names[] = $name;
                }
            }
        }

        return array_values(array_unique($names));
    }

    /**
     * An unresolved `provider_info` — every field null, which is what ExoClass
     * emits when it scoped the answer to nobody — is NOT a provider. Returning
     * null for it is the whole point: it is what lets a scoped lookup tell an
     * answer about provider X from an answer about everybody.
     */
    private static function parseProviderInfo(mixed $provider): ?ProviderInfo
    {
        if (! is_array($provider)) {
            return null;
        }

        $id = $provider['id'] ?? null;
        $id = is_int($id) || (is_string($id) && $id !== '' && ctype_digit($id)) ? (int) $id : null;
        $externalKey = self::asString($provider['external_key'] ?? null);

        if ($id === null && $externalKey === null) {
            return null;
        }

        return new ProviderInfo(
            id: $id,
            externalKey: $externalKey,
            name: self::asString($provider['name'] ?? null),
        );
    }

    /**
     * @return list<Employer>
     */
    private static function parseEmployers(mixed $employers): array
    {
        if (! is_array($employers)) {
            return [];
        }

        $parsed = [];

        foreach ($employers as $employer) {
            if (! is_array($employer)) {
                continue;
            }

            $id = $employer['id'] ?? null;

            if (! is_int($id) && ! (is_string($id) && $id !== '' && ctype_digit($id))) {
                continue;
            }

            $parsed[] = new Employer(
                id: (int) $id,
                externalKey: self::asString($employer['external_key'] ?? null) ?? '',
                name: self::asString($employer['name'] ?? null) ?? '',
            );
        }

        return $parsed;
    }

    /**
     * @return array<array-key, mixed>|null
     */
    private static function asMap(mixed $value): ?array
    {
        return is_array($value) && $value !== [] ? $value : null;
    }

    private static function asString(mixed $value): ?string
    {
        if (is_string($value)) {
            return trim($value) === '' ? null : $value;
        }

        if (is_int($value) || is_float($value)) {
            return (string) $value;
        }

        return null;
    }
}
