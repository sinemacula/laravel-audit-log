<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Privacy;

use Illuminate\Contracts\Debug\ExceptionHandler;
use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Support\TextSanitizer;
use SineMacula\Laravel\AuditLog\Support\ValueNormaliser;

/**
 * The one way a value reaches the field encrypter during a capture, with the
 * context it is sealed for. It accepts only an envelope of exactly `v`, `k` and
 * `c`, returned in that order, and contains every failure, so a broken
 * encrypter costs a field and never the record.
 *
 * A failure is an encrypter that throws or returns anything else. It is
 * reported once, as a `FieldEncryptionFailedException` that names only the
 * encrypter's class, and what was thrown is discarded, because its message
 * could hold the plaintext. The sealer then calls the encrypter no more, so a
 * wildcard over thousands of elements cannot flood a reporter or keep sending
 * plaintext to a broken encrypter.
 *
 * It holds that state for one capture, so it is built per capture and is never
 * a singleton.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class EnvelopeSealer
{
    /** @var int How many parts an envelope has: `v`, `k` and `c`. */
    private const int ENVELOPE_PARTS = 3;

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
     * The plaintext sealed under the owner's key for the context, as `v`, `k`
     * and `c` in that order, or `null` when the owner has no key, when the
     * encrypter fails, or when it has already failed during this capture. Only
     * a failure is reported; an owner with no key is not one, and later calls
     * go on.
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
            // What was thrown could hold the plaintext in its message, so it is
            // never kept, logged or chained: all it leaves is an empty envelope
            $envelope = [];
        }

        if ($envelope === null) {
            return null;
        }

        $sealed = self::validated($envelope);

        if ($sealed === null) {
            $this->fail();
        }

        return $sealed;
    }

    /**
     * Stop calling the encrypter for this capture and report the failure. A
     * reporter that fails too is ignored: the field is already dropped, and
     * there is nowhere left to say so.
     *
     * @return void
     */
    private function fail(): void
    {
        $this->failed = true;

        try {
            $this->handler->report(FieldEncryptionFailedException::for($this->encrypter));
        } catch (\Throwable) {
            // The record is still being written; a broken reporter must not
            // undo the containment of the failure it was told about
        }
    }

    /**
     * The envelope in its fixed order, or `null` when it is anything but
     * exactly a valid `v`, `k` and `c`, in any order. The contract promises
     * this shape, but nothing enforces a promise made in a docblock.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $envelope
     * @return ?array{v: int, k: string, c: string}
     */
    private static function validated(#[\SensitiveParameter] array $envelope): ?array
    {
        $version    = $envelope['v'] ?? null;
        $key        = $envelope['k'] ?? null;
        $ciphertext = $envelope['c'] ?? null;

        if (count($envelope) !== self::ENVELOPE_PARTS || !self::isVersion($version) || !self::isText($key) || !self::isText($ciphertext)) {
            return null;
        }

        return ['v' => $version, 'k' => $key, 'c' => $ciphertext];
    }

    /**
     * Whether the value is an integer from 1 to the largest integer every
     * reader of the stored JSON keeps exactly.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @phpstan-assert-if-true int $value
     *
     * @param  mixed  $value
     * @return bool
     */
    private static function isVersion(#[\SensitiveParameter] mixed $value): bool
    {
        return is_int($value) && $value >= 1 && $value <= ValueNormaliser::MAX_SAFE_INTEGER;
    }

    /**
     * Whether the value is a non-empty string that cleaning would not change,
     * since an envelope is stored and signed exactly as given.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @phpstan-assert-if-true string $value
     *
     * @param  mixed  $value
     * @return bool
     */
    private static function isText(#[\SensitiveParameter] mixed $value): bool
    {
        return is_string($value) && $value !== '' && TextSanitizer::isClean($value);
    }
}
