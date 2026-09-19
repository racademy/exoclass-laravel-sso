<?php

declare(strict_types=1);

namespace ExoClass\Sso\Resolution;

use InvalidArgumentException;

/**
 * One option on the picker: `key` is what comes back from the browser and is
 * re-validated against the identity, `label` is what the visitor reads, `meta`
 * is whatever the app wants to render alongside (never secrets — it is stashed
 * in the session and rendered in HTML).
 */
final readonly class Candidate
{
    /**
     * @param  array<string, scalar|null>  $meta
     */
    public function __construct(
        public string $key,
        public string $label,
        public array $meta = [],
    ) {
        if (trim($key) === '') {
            throw new InvalidArgumentException('Candidate requires a non-empty key.');
        }

        if (trim($label) === '') {
            throw new InvalidArgumentException('Candidate requires a non-empty label.');
        }
    }

    /**
     * @return array{key: string, label: string, meta: array<string, scalar|null>}
     */
    public function toArray(): array
    {
        return ['key' => $this->key, 'label' => $this->label, 'meta' => $this->meta];
    }
}
