<?php

declare(strict_types=1);

namespace ExoClass\Sso\Identity;

/**
 * The provider ExoClass says it scoped an answer to — the `provider_info` block
 * (`provider` on `/auth/login-v2`) that `UserController::currentUser` glues on
 * top of every `users/current` response.
 *
 * This is the ONLY field in the payload that reports which provider the answer
 * is about, which makes it load-bearing rather than decorative. ExoClass does
 * not reject an `X-Provider-Key` it cannot resolve: it discards the resolution
 * result, falls through to the unfiltered branch and answers 200 with every
 * employer and the union of the user's roles across all of them — a body
 * distinguishable from a genuinely scoped one only by this block, which then
 * arrives filled with nulls.
 *
 * So an identity built from an unscoped answer carries NO ProviderInfo at all
 * ({@see ExoClassIdentity::$providerInfo} is null), and a scoped lookup checks
 * {@see matches()} before it believes a role list.
 */
final readonly class ProviderInfo
{
    public function __construct(
        public ?int $id,
        public ?string $externalKey,
        public ?string $name,
    ) {}

    /**
     * Is this the provider the caller asked about? A null external key never
     * matches: an unattributed answer is not an answer about anybody.
     */
    public function matches(string $providerKey): bool
    {
        return $this->externalKey !== null && $this->externalKey === $providerKey;
    }
}
