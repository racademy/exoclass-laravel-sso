<?php

declare(strict_types=1);

namespace ExoClass\Sso\Support;

use Illuminate\Support\Facades\Log;
use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;

/**
 * The ONLY way this package writes a log line. Every message, context array and
 * upstream body passes through {@see LogSanitizer} first, with the live secrets
 * of the request in hand, so a leak needs a deliberate bypass rather than a
 * forgotten `Log::info()` argument.
 *
 * Lines are tagged `exoclass-sso` so an operator can grep one subsystem's SSO
 * traffic out of a shared daily log.
 */
final class SsoLogger
{
    public function __construct(private readonly ?LoggerInterface $logger = null) {}

    /**
     * @param  array<array-key, mixed>  $context
     * @param  list<string>  $secrets
     */
    public function info(string $message, array $context = [], array $secrets = []): void
    {
        $this->log(LogLevel::INFO, $message, $context, $secrets);
    }

    /**
     * @param  array<array-key, mixed>  $context
     * @param  list<string>  $secrets
     */
    public function warning(string $message, array $context = [], array $secrets = []): void
    {
        $this->log(LogLevel::WARNING, $message, $context, $secrets);
    }

    /**
     * @param  array<array-key, mixed>  $context
     * @param  list<string>  $secrets
     */
    public function error(string $message, array $context = [], array $secrets = []): void
    {
        $this->log(LogLevel::ERROR, $message, $context, $secrets);
    }

    /**
     * @param  array<array-key, mixed>  $context
     * @param  list<string>  $secrets
     */
    public function log(string $level, string $message, array $context = [], array $secrets = []): void
    {
        $sanitizedContext = LogSanitizer::context($context, $secrets);
        $sanitizedContext['channel'] = 'exoclass-sso';

        $sanitizedMessage = LogSanitizer::text($message, $secrets);

        if ($this->logger instanceof LoggerInterface) {
            $this->logger->log($level, $sanitizedMessage, $sanitizedContext);

            return;
        }

        Log::log($level, $sanitizedMessage, $sanitizedContext);
    }
}
