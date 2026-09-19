<?php

declare(strict_types=1);

namespace ExoClass\Sso\Http;

use ExoClass\Sso\Support\LogSanitizer;
use InvalidArgumentException;
use SensitiveParameter;

/**
 * The browser-supplied ExoClass credential this package forwards upstream: the
 * per-environment session cookie (name + RAW opaque value) and, for
 * state-changing verbs, the paired XSRF token.
 *
 * The value is NEVER decrypted, parsed or trusted locally — only ExoClass's
 * verdict on it counts. Both members are secrets: {@see redactable()} lists the
 * strings every log line must scrub.
 */
final readonly class SessionCredential
{
    public function __construct(
        public string $cookieName,
        #[SensitiveParameter]
        public string $cookieValue,
        #[SensitiveParameter]
        public ?string $xsrfToken = null,
    ) {
        if (trim($cookieName) === '') {
            throw new InvalidArgumentException('SessionCredential requires a non-empty cookie name.');
        }

        if (trim($cookieValue) === '') {
            throw new InvalidArgumentException('SessionCredential requires a non-empty cookie value.');
        }

        if ($xsrfToken !== null && trim($xsrfToken) === '') {
            throw new InvalidArgumentException('SessionCredential requires a non-empty XSRF token when one is given.');
        }
    }

    /**
     * The `Cookie:` header line carrying this credential.
     */
    public function cookieHeader(): string
    {
        return $this->cookieName.'='.$this->cookieValue;
    }

    public function withXsrfToken(#[SensitiveParameter] string $xsrfToken): self
    {
        return new self($this->cookieName, $this->cookieValue, $xsrfToken);
    }

    /**
     * Every secret string carried by this credential, for the log sanitizer.
     *
     * @return list<string>
     */
    public function redactable(): array
    {
        $secrets = [$this->cookieValue];

        if ($this->xsrfToken !== null) {
            $secrets[] = $this->xsrfToken;
        }

        return $secrets;
    }

    /**
     * Never let a var_dump, a stack trace or a queued job payload carry the
     * secret: debug output shows the cookie NAME only.
     *
     * @return array<string, string>
     */
    public function __debugInfo(): array
    {
        return [
            'cookieName' => $this->cookieName,
            'cookieValue' => LogSanitizer::REDACTED,
            'xsrfToken' => LogSanitizer::REDACTED,
        ];
    }
}
