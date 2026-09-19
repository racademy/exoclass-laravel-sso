<?php

declare(strict_types=1);

namespace ExoClass\Sso\Contracts;

use ExoClass\Sso\Identity\ExoClassIdentity;
use ExoClass\Sso\Resolution\ChoiceRequired;
use ExoClass\Sso\Resolution\Denied;
use ExoClass\Sso\Resolution\Resolution;
use ExoClass\Sso\Resolution\ResolutionContext;

/**
 * The one contract a subsystem implements to adopt ExoClass SSO.
 *
 * The package proves WHO the visitor is upstream; the resolver decides what
 * that means locally — which organizations they may enter, whether a local user
 * is created, and whether access is refused. The package never touches the
 * app's user table, its roles or its tenancy.
 *
 * Both methods must be side-effect-compatible with being called more than once
 * for the same visitor (auto-login, button return and picker all land here),
 * and both must fail CLOSED: anything the resolver cannot positively justify is
 * a {@see Denied}, never an Authenticated.
 */
interface IdentityResolver
{
    /**
     * First pass: decide from the identity alone.
     */
    public function resolve(ExoClassIdentity $identity, ResolutionContext $context): Resolution;

    /**
     * Second pass: the visitor picked one of the candidates a previous
     * {@see ChoiceRequired} offered.
     *
     * The candidate key arrives from the browser, so the implementation MUST
     * re-derive the candidate list from the identity and reject a key that is
     * not in it — never trust the submitted key on its own.
     */
    public function resolveChoice(ExoClassIdentity $identity, string $candidateKey): Resolution;
}
