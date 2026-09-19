<?php

declare(strict_types=1);

namespace ExoClass\Sso\Resolution;

/**
 * Everything a resolver may know about the ATTEMPT, as opposed to the identity.
 *
 * Deliberately tiny and deliberately free of the credential: a resolver must
 * never see, store or forward the session cookie.
 */
final readonly class ResolutionContext
{
    /**
     * @param  array<string, scalar|null>  $meta
     */
    public function __construct(
        public ResolutionTrigger $trigger = ResolutionTrigger::AutoLogin,
        public ?string $intendedUrl = null,
        public ?string $ipAddress = null,
        public array $meta = [],
    ) {}

    public static function autoLogin(?string $intendedUrl = null, ?string $ipAddress = null): self
    {
        return new self(ResolutionTrigger::AutoLogin, $intendedUrl, $ipAddress);
    }

    public static function buttonReturn(?string $intendedUrl = null, ?string $ipAddress = null): self
    {
        return new self(ResolutionTrigger::ButtonReturn, $intendedUrl, $ipAddress);
    }

    public static function choice(?string $intendedUrl = null, ?string $ipAddress = null): self
    {
        return new self(ResolutionTrigger::Choice, $intendedUrl, $ipAddress);
    }

    public static function liveness(?string $intendedUrl = null, ?string $ipAddress = null): self
    {
        return new self(ResolutionTrigger::Liveness, $intendedUrl, $ipAddress);
    }
}
