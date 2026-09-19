<?php

declare(strict_types=1);

namespace ExoClass\Sso\Resolution;

use InvalidArgumentException;

/**
 * The identity maps onto more than one thing the visitor could enter. The
 * middleware stashes the candidates and redirects to the app's picker; the
 * chosen key comes back through `IdentityResolver::resolveChoice()`.
 */
final readonly class ChoiceRequired implements Resolution
{
    /** @var list<Candidate> */
    public array $candidates;

    public function __construct(Candidate ...$candidates)
    {
        if (count($candidates) < 2) {
            throw new InvalidArgumentException(
                'ChoiceRequired needs at least two candidates — with one, answer Authenticated; with none, Denied.'
            );
        }

        $keys = array_map(static fn (Candidate $candidate): string => $candidate->key, $candidates);

        if (count(array_unique($keys)) !== count($keys)) {
            throw new InvalidArgumentException('ChoiceRequired candidates must have unique keys.');
        }

        $this->candidates = array_values($candidates);
    }

    /**
     * @param  list<Candidate>  $candidates
     */
    public static function fromList(array $candidates): self
    {
        return new self(...$candidates);
    }

    /**
     * @return list<string>
     */
    public function keys(): array
    {
        return array_map(static fn (Candidate $candidate): string => $candidate->key, $this->candidates);
    }
}
