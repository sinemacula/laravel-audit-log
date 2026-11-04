<?php

declare(strict_types = 1);

namespace Tests\Unit\Privacy;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Privacy\EncryptedField;
use SineMacula\Laravel\AuditLog\Privacy\Enums\FieldState;
use SineMacula\Laravel\AuditLog\Privacy\FieldReading;
use SineMacula\Laravel\AuditLog\Privacy\SealedFieldReader;

/**
 * Unit tests for the field reader the package binds: it answers `encrypted` for
 * every field of a page, one reading for each, in order, and its answer holds
 * nothing of the fields it was given.
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
     * An IP address, an owned note and a nested property of a page are each
     * answered `encrypted`, with no value, shown as its marker, one reading for
     * each field.
     *
     * @return void
     */
    public function testItAlwaysAnswersEncrypted(): void
    {
        $fields   = [self::field(['ip']), self::field(['properties', '_audit', 'note']), self::field(['properties', 'cards', 0, 'number'])];
        $readings = (new SealedFieldReader)->readAll($fields);

        self::assertSame([0, 1, 2], array_keys($readings));

        foreach ($readings as $index => $reading) {
            self::assertInstanceOf(FieldReading::class, $reading);
            self::assertSame(FieldState::ENCRYPTED, $reading->state, (string) $index);
            self::assertNull($reading->value, (string) $index);
            self::assertSame('[ENCRYPTED]', $reading->display(), (string) $index);
        }
    }

    /**
     * A page with no field is answered with no reading.
     *
     * @return void
     */
    public function testAnEmptyPageHasNoReading(): void
    {
        self::assertSame([], (new SealedFieldReader)->readAll([]));
    }

    /**
     * Fields that differ in every part are answered alike, and the answer holds
     * none of the entry id, the path, the key reference or the ciphertext.
     *
     * @return void
     */
    public function testItReadsNothingOfTheField(): void
    {
        $first  = self::field(['ip'], self::ENTRY_ID, 1, 'key_42', 'Zmlyc3QgY2lwaGVydGV4dA');
        $second = self::field(['properties', 'card'], '01932b4e-8a40-7000-8000-000000000002', 7, 'key_43', 'c2Vjb25kIGNpcGhlcnRleHQ');

        [$firstReading, $secondReading] = (new SealedFieldReader)->readAll([$first, $second]);

        self::assertEquals($firstReading, $secondReading);

        $answered = serialize($secondReading);

        foreach (['01932b4e-8a40-7000-8000-000000000002', 'properties', 'card', 'key_43', 'c2Vjb25kIGNpcGhlcnRleHQ'] as $part) {
            self::assertStringNotContainsString($part, $answered);
        }
    }

    /**
     * The field at the segments, of the envelope given.
     *
     * @param  non-empty-list<int|string>  $segments
     * @param  string  $entryId
     * @param  int  $version
     * @param  string  $key
     * @param  string  $ciphertext
     * @return \SineMacula\Laravel\AuditLog\Privacy\EncryptedField
     */
    private static function field(array $segments, string $entryId = self::ENTRY_ID, int $version = 1, string $key = 'key_42', string $ciphertext = 'Y2lwaGVy'): EncryptedField
    {
        $field = EncryptedField::fromEnvelope($entryId, $segments, ['v' => $version, 'k' => $key, 'c' => $ciphertext]);

        self::assertInstanceOf(EncryptedField::class, $field);

        return $field;
    }
}
