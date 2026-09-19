<?php

declare(strict_types=1);

namespace ExoClass\Sso\Tests\Support;

use Closure;
use ExoClass\Sso\Contracts\IdentityResolver;
use ExoClass\Sso\Identity\ExoClassIdentity;
use ExoClass\Sso\Resolution\Denied;
use ExoClass\Sso\Resolution\Resolution;
use ExoClass\Sso\Resolution\ResolutionContext;

/**
 * The app's half of the deal, stubbed: answers whatever a test told it to and
 * records what it was asked, so a test can assert on the trigger and the
 * intended URL the middleware handed over.
 */
final class RecordingResolver implements IdentityResolver
{
    /** @var Closure(ExoClassIdentity, ResolutionContext): Resolution */
    private Closure $answer;

    /** @var (Closure(ExoClassIdentity, string): Resolution)|null */
    private ?Closure $choiceAnswer = null;

    /** @var list<ResolutionContext> */
    public array $contexts = [];

    /** @var list<string> */
    public array $choiceKeys = [];

    public function __construct()
    {
        $this->answer = static fn (): Resolution => new Denied('no answer configured for this test');
    }

    /**
     * @param  Closure(ExoClassIdentity, ResolutionContext): Resolution  $answer
     */
    public function answerWith(Closure $answer): self
    {
        $this->answer = $answer;

        return $this;
    }

    /**
     * @param  Closure(ExoClassIdentity, string): Resolution  $answer
     */
    public function answerChoiceWith(Closure $answer): self
    {
        $this->choiceAnswer = $answer;

        return $this;
    }

    public function calls(): int
    {
        return count($this->contexts);
    }

    public function resolve(ExoClassIdentity $identity, ResolutionContext $context): Resolution
    {
        $this->contexts[] = $context;

        return ($this->answer)($identity, $context);
    }

    public function resolveChoice(ExoClassIdentity $identity, string $candidateKey): Resolution
    {
        $this->choiceKeys[] = $candidateKey;

        return $this->choiceAnswer !== null
            ? ($this->choiceAnswer)($identity, $candidateKey)
            : ($this->answer)($identity, ResolutionContext::choice());
    }
}
