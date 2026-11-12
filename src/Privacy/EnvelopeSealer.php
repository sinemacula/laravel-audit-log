<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Privacy;

use Illuminate\Contracts\Debug\ExceptionHandler;
use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * The one way a value reaches the field encrypter in a capture; a failure costs
 * the field, never the record, and stops the encrypter for the rest of the
 * capture.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class EnvelopeSealer
{
    /** @var bool Whether the encrypter has failed during this capture. */
    private bool $failed = false;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter  $encrypter
     * @param  \Illuminate\Contracts\Debug\ExceptionHandler  $handler
     */
    public function __construct(

        /** What seals a value under its owner's key. */
        private readonly FieldEncrypter $encrypter,

        /** Where a failure is reported. */
        private readonly ExceptionHandler $handler,
    ) {}

    /**
     * The plaintext sealed as `v`, `k` and `c`, or `null` when the owner has no
     * key or the encrypter fails or has already failed.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @param  string  $plaintext
     * @param  \SineMacula\Laravel\AuditLog\Privacy\FieldContext  $context
     * @return ?array{v: int, k: string, c: string}
     */
    public function seal(#[\SensitiveParameter] Reference $owner, #[\SensitiveParameter] string $plaintext, #[\SensitiveParameter] FieldContext $context): ?array
    {
        if ($this->failed) {
            return null;
        }

        try {
            $envelope = $this->encrypter->encrypt($owner, $plaintext, $context);
        } catch (\Throwable) {
            // Its message could hold the plaintext, so it is never kept
            $envelope = [];
        }

        if ($envelope === null) {
            return null;
        }

        $sealed = EncryptedField::parts($envelope);

        if ($sealed === null) {
            $this->fail();
        }

        return $sealed;
    }

    /**
     * Stop calling the encrypter for this capture and report the failure once.
     *
     * @return void
     */
    private function fail(): void
    {
        $this->failed = true;

        try {
            $this->handler->report(FieldEncryptionFailedException::for($this->encrypter));
        } catch (\Throwable) {
            // A broken reporter must not fail the record
        }
    }
}
