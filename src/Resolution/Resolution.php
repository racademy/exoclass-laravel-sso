<?php

declare(strict_types=1);

namespace ExoClass\Sso\Resolution;

/**
 * The three — and only three — answers a resolver may give.
 *
 *   {@see Authenticated}   log this Authenticatable in
 *   {@see ChoiceRequired}  ask the visitor which of these to enter
 *   {@see Denied}          refuse, with a reason fit for a log line
 *
 * PHP has no sealed types, so the set is kept closed by convention and by the
 * middleware, which matches on exactly these three and treats anything else as
 * a programming error rather than inventing a fallback. Adding a fourth
 * outcome is a package change, not an app change.
 */
interface Resolution {}
