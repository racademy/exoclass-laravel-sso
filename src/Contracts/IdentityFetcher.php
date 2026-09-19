<?php

declare(strict_types=1);

namespace ExoClass\Sso\Contracts;

use ExoClass\Sso\Exceptions\MalformedResponseException;
use ExoClass\Sso\Exceptions\UnauthorizedException;
use ExoClass\Sso\Exceptions\UnavailableException;
use ExoClass\Sso\Http\SessionCredential;
use ExoClass\Sso\Identity\ExoClassIdentity;

/**
 * Turns a browser credential into a verified ExoClass identity.
 *
 * This is the seam that keeps the rest of the package honest about HOW the
 * identity was obtained. Today the only implementation forwards the session
 * cookie to `users/current`; a dedicated `auth/identity` endpoint, or a token
 * exchange for subsystems outside `*.exoclass.com`, plugs in here without the
 * middleware or any app's resolver changing.
 */
interface IdentityFetcher
{
    /**
     * @throws UnauthorizedException authoritative "no valid ExoClass session"
     * @throws UnavailableException upstream gave no usable verdict — fail soft
     * @throws MalformedResponseException 2xx body this package cannot trust
     */
    public function fetch(SessionCredential $credential): ExoClassIdentity;
}
