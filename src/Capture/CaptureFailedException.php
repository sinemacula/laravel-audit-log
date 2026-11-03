<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Capture;

/**
 * Reported when an event could not be captured for any reason but a failed
 * write, which is reported as the write's own failure, in place of the
 * exception the capture failed with, whose message can hold the event's values.
 *
 * It holds the class of the event, the class of what translated it and the
 * class of the exception, and nothing else. Its message is built from those
 * alone, and it has no previous exception, so neither a handler nor a log
 * reaches the original.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class CaptureFailedException extends \RuntimeException
{
    /** @var string The message, by the event's class, the mapper's and the exception's. */
    private const string MESSAGE = 'Capturing `%s` with `%s` failed with `%s`.';

    /** @var string What the message names in place of a mapper when more than one mapping matched the event. */
    private const string NO_MAPPER = 'no mapper';

    /**
     * Constructor.
     *
     * @param  string  $eventClass
     * @param  ?string  $mapperClass
     * @param  string  $exceptionClass
     */
    private function __construct(

        /** The class of the event, or of the watched model, that was not captured. */
        public readonly string $eventClass,

        /** The class of the mapper or the package listener that translated the event, or `null` when more than one mapping matched it. */
        public readonly ?string $mapperClass,

        /** The class of the exception the capture failed with, an anonymous one named without its file. */
        public readonly string $exceptionClass,
    ) {
        parent::__construct(sprintf(self::MESSAGE, $eventClass, $mapperClass ?? self::NO_MAPPER, $exceptionClass));
    }

    /**
     * The exception for a capture of the event's class, translated by the
     * mapper's, that failed so: the failure is named by its class alone, as
     * `get_debug_type()` names it, and is never kept.
     *
     * @param  string  $eventClass
     * @param  ?string  $mapperClass
     * @param  \Throwable  $failure
     * @return self
     */
    public static function of(string $eventClass, ?string $mapperClass, #[\SensitiveParameter] \Throwable $failure): self
    {
        return new self($eventClass, $mapperClass, get_debug_type($failure));
    }
}
