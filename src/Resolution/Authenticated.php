<?php

declare(strict_types=1);

namespace ExoClass\Sso\Resolution;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * The resolver identified exactly one local account for this ExoClass identity
 * and vouches for it. The middleware logs this user in and regenerates the
 * session.
 */
final readonly class Authenticated implements Resolution
{
    public function __construct(public Authenticatable $user) {}
}
