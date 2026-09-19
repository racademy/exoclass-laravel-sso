<?php

declare(strict_types=1);

namespace ExoClass\Sso\Identity;

/**
 * One ExoClass provider the user is employed by (`employers[]` on
 * `users/current`, shaped by `ProviderApiMap::responseFromProviderDto`).
 *
 * `id` is the numeric provider id a subsystem maps onto its own organization
 * (ExoSend stores it as `organizations.exoclass_provider_id`); `externalKey` is
 * the uuid ExoClass expects back in the `X-Provider-Key` header when asking for
 * this user's roles AT this provider.
 */
final readonly class Employer
{
    public function __construct(
        public int $id,
        public string $externalKey,
        public string $name,
    ) {}
}
