<?php

declare(strict_types=1);

namespace ExoClass\Sso\Resolution;

/**
 * Which door the visitor came through. The resolver's VERDICT must not depend
 * on it (parity: auto-login, button return and picker share one code path and
 * the tests assert identical outcomes) — it exists so log lines and analytics
 * can tell the three apart.
 */
enum ResolutionTrigger: string
{
    /** A navigable GET arrived already carrying a valid ExoClass cookie. */
    case AutoLogin = 'auto_login';

    /** The visitor came back from the ExoClass login screen. */
    case ButtonReturn = 'button_return';

    /** The visitor picked one candidate on the app's picker. */
    case Choice = 'choice';

    /** An authenticated SSO session is being re-validated upstream. */
    case Liveness = 'liveness';
}
