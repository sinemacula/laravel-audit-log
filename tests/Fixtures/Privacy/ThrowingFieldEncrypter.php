<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Privacy;

use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;
use SineMacula\Laravel\AuditLog\Privacy\FieldContext;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * A field encrypter that always throws, with the plaintext in its message, the
 * worst a real one could do: a `\RuntimeException`, or an `\Error` when told.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ThrowingFieldEncrypter implements FieldEncrypter
{
    /** @var int How many times it was called. */
    private int $calls = 0;

    /**
     * Constructor.
     *
     * @param  bool  $throwsAnError
     */
    public function __construct(

        /** Whether it throws an `\Error` rather than a `\RuntimeException`. */
        private readonly bool $throwsAnError = false,
    ) {}

    /**
     * Throw, with the plaintext in the message.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @param  string  $plaintext
     * @param  \SineMacula\Laravel\AuditLog\Privacy\FieldContext  $context
     * @return never
     *
     * @throws \Error
     * @throws \RuntimeException
     */
    #[\Override]
    public function encrypt(Reference $owner, #[\SensitiveParameter] string $plaintext, FieldContext $context): never
    {
        $this->calls++;

        if ($this->throwsAnError) {
            throw new \Error('could not encrypt ' . $plaintext);
        }

        throw new \RuntimeException('could not encrypt ' . $plaintext);
    }

    /**
     * How many times it was called.
     *
     * @return int
     */
    public function calls(): int
    {
        return $this->calls;
    }
}
