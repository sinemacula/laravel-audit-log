<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Capture;

/**
 * Reported in place of a failed capture. It holds class names alone and no
 * previous exception, since the original's message can hold the event's values.
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

    /** @var string Named in place of a mapper when more than one mapping matched. */
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

        /** The mapper or package listener's class, or `null` when more than one mapping matched. */
        public readonly ?string $mapperClass,

        /** The failure's class, an anonymous one named without its file. */
        public readonly string $exceptionClass,
    ) {
        parent::__construct(sprintf(self::MESSAGE, $eventClass, $mapperClass ?? self::NO_MAPPER, $exceptionClass));
    }

    /**
     * The exception for a failed capture, naming the failure by
     * `get_debug_type()` and never keeping it.
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
