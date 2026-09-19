<?php

declare(strict_types=1);

namespace ExoClass\Sso\Identity;

/**
 * The person behind the forwarded ExoClass session, as ExoClass describes them
 * on `users/current` (`UserApiMap::responseFromUserDto`).
 *
 * Only the fields a subsystem needs to identify and create a local user are
 * surfaced; everything else in the upstream payload is deliberately dropped so
 * the package never becomes an accidental user-profile mirror.
 */
final readonly class ExoClassUser
{
    public function __construct(
        public int $id,
        public string $externalKey,
        public string $email,
        public ?string $firstName = null,
        public ?string $lastName = null,
        public ?string $language = null,
    ) {}

    public function fullName(): string
    {
        return trim(implode(' ', array_filter([$this->firstName, $this->lastName])));
    }
}
