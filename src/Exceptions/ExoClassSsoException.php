<?php

declare(strict_types=1);

namespace ExoClass\Sso\Exceptions;

use RuntimeException;

/**
 * Base for every failure the ExoClass SSO transport can produce.
 *
 * Exception messages are part of the redaction surface: they end up in logs,
 * error trackers and (for a misconfigured app) on screen, so they may carry a
 * URL, an HTTP status and a short reason — never the forwarded session cookie
 * value nor the XSRF token.
 */
abstract class ExoClassSsoException extends RuntimeException {}
