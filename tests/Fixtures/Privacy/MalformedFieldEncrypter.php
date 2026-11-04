<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Privacy;

use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;
use SineMacula\Laravel\AuditLog\Privacy\FieldContext;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * A field encrypter that returns whatever array its constructor was given,
 * whatever the contract asks for, so a test can hand the package any envelope.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class MalformedFieldEncrypter implements FieldEncrypter
{
    /** @var int How many times it was called. */
    private int $calls = 0;

    /**
     * Constructor.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $envelope
     */
    public function __construct(

        /** What it returns from every call. */
        private readonly array $envelope,
    ) {}

    /**
     * The array it was given, which need not be what the contract asks for.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @param  string  $plaintext
     * @param  \SineMacula\Laravel\AuditLog\Privacy\FieldContext  $context
     * @return array{v: int, k: string, c: string}
     */
    #[\Override]
    public function encrypt(Reference $owner, #[\SensitiveParameter] string $plaintext, FieldContext $context): array
    {
        $this->calls++;

        return $this->envelope; // @phpstan-ignore return.type
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
