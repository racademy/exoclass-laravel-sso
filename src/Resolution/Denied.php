<?php

declare(strict_types=1);

namespace ExoClass\Sso\Resolution;

use InvalidArgumentException;

/**
 * Access refused. The visitor stays signed into ExoClass — their cookie is left
 * untouched — and the app renders its 403 page.
 *
 * `reason` is an operator-facing string that goes into the structured log line
 * verbatim, so it must be short, stable and free of anything secret.
 */
final readonly class Denied implements Resolution
{
    public function __construct(public string $reason)
    {
        if (trim($reason) === '') {
            throw new InvalidArgumentException('Denied requires a reason — it is the log line.');
        }
    }
}
