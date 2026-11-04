<?php

declare(strict_types = 1);

namespace Tests\Unit\Privacy;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Privacy\EncryptedField;
use SineMacula\Laravel\AuditLog\Privacy\Enums\FieldState;
use SineMacula\Laravel\AuditLog\Privacy\SealedFieldReader;

/**
 * Unit tests for the field reader the package binds: it answers `encrypted` for
 * every field, and its answer holds nothing of the field it was given.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SealedFieldReader::class)]
final class SealedFieldReaderTest extends TestCase
{
    /** @var string An entry id. */
    private const string ENTRY_ID = '01932b4e-8a40-7000-8000-000000000001';

    /**
     * An IP address, an owned note and a nested property are each answered
     * `encrypted`, with no value, and shown as its marker.
     *
     * @return void
     */
    public function testItAlwaysAnswersEncrypted(): void
    {
        $reader = new SealedFieldReader;

        foreach (['ip', 'properties._audit.note', 'properties.cards.0.number'] as $path) {
            $reading = $reader->read(new EncryptedField(self::ENTRY_ID, $path, 1, 'key_42', 'Y2lwaGVy'));

            self::assertSame(FieldState::ENCRYPTED, $reading->state, $path);
            self::assertNull($reading->value, $path);
            self::assertSame('[ENCRYPTED]', $reading->display(), $path);
        }
    }

    /**
     * Fields that differ in every part are answered alike, and the answer holds
     * none of the entry id, the path, the key reference or the ciphertext.
     *
     * @return void
     */
    public function testItReadsNothingOfTheField(): void
    {
        $reader = new SealedFieldReader;

        $first  = $reader->read(new EncryptedField(self::ENTRY_ID, 'ip', 1, 'key_42', 'Zmlyc3QgY2lwaGVydGV4dA'));
        $second = $reader->read(new EncryptedField('01932b4e-8a40-7000-8000-000000000002', 'properties.card', 7, 'key_43', 'c2Vjb25kIGNpcGhlcnRleHQ'));

        self::assertEquals($first, $second);

        $answered = serialize($second);

        foreach (['01932b4e-8a40-7000-8000-000000000002', 'properties.card', 'key_43', 'c2Vjb25kIGNpcGhlcnRleHQ'] as $part) {
            self::assertStringNotContainsString($part, $answered);
        }
    }
}
