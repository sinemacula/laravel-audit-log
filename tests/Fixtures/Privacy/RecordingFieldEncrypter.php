<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Privacy;

use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;
use SineMacula\Laravel\AuditLog\Privacy\FieldContext;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * A field encrypter that keeps each call and its context, sealing as `{v: 1, k:
 * 'key_' . id, c: base64 of the plaintext}` so a test can read back what was
 * sealed and under whose key.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordingFieldEncrypter implements FieldEncrypter
{
    /** @var list<array{0: \SineMacula\Laravel\AuditLog\Records\Reference, 1: string}> Each owner and plaintext it was given, in order. */
    private array $calls = [];

    /** @var list<\SineMacula\Laravel\AuditLog\Privacy\FieldContext> The context of each call, in order. */
    private array $contexts = [];

    /**
     * The plaintext sealed under a key named for the owner's id.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @param  string  $plaintext
     * @param  \SineMacula\Laravel\AuditLog\Privacy\FieldContext  $context
     * @return array{v: int, k: string, c: string}
     */
    #[\Override]
    public function encrypt(Reference $owner, #[\SensitiveParameter] string $plaintext, FieldContext $context): array
    {
        $this->calls[]    = [$owner, $plaintext];
        $this->contexts[] = $context;

        return ['v' => 1, 'k' => 'key_' . $owner->id, 'c' => base64_encode($plaintext)];
    }

    /**
     * Each owner and plaintext it was given, in order.
     *
     * @return list<array{0: \SineMacula\Laravel\AuditLog\Records\Reference, 1: string}>
     */
    public function calls(): array
    {
        return $this->calls;
    }

    /**
     * The context of each call, in order.
     *
     * @return list<\SineMacula\Laravel\AuditLog\Privacy\FieldContext>
     */
    public function contexts(): array
    {
        return $this->contexts;
    }

    /**
     * The path of each call's context, in order.
     *
     * @return list<non-empty-list<int|string>>
     */
    public function paths(): array
    {
        return array_map(static fn (FieldContext $context): array => $context->path, $this->contexts);
    }
}
