<?php

declare(strict_types = 1);

namespace Tests\Unit\Integrity;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Integrity\PruneRecord;

/**
 * Unit tests for the prune record of version 2.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PruneRecord::class)]
final class PruneRecordTest extends TestCase
{
    /** @var string The golden prune vectors. */
    private const string GOLDEN = __DIR__ . '/../../Fixtures/Integrity/prune-v2.json';

    /** @var string The golden seal's id. */
    private const string SEAL_ID = '01932b4e-9000-7000-8000-000000000003';

    /** @var string The golden seal's digest. */
    private const string SEAL_DIGEST = '8e996a967b105c7f6c9e723def229fa1434797ac4cb60f6ffbc914861f0e0065';

    /** @var string The golden first prune operation's id. */
    private const string OPERATION_ID = '01932b4e-a000-7000-8000-000000000001';

    /** @var string When the golden first prune ran. */
    private const string PRUNED_AT = '2027-11-01T00:00:00.000000Z';

    /** @var string The golden first prune's signature. */
    private const string SIGNATURE = '60353b699e1e0e46b892c18515f5e62bb26f723627f1a5f9e0fa51d1f60d1edc';

    /** @var string What a refused bitmap must be. */
    private const string PRUNED = 'A prune record\'s `pruned` must be the canonical base64url bitmap of its `member_count` members.';

    /** @var string What a refused count must be. */
    private const string PRUNED_COUNT = 'A prune record\'s `pruned_count` must be the number of members its bitmap sets, at least 1.';

    /**
     * The record keeps every field as given, and is of version 2.
     *
     * @return void
     */
    public function testKeepsItsFields(): void
    {
        $record = self::record();

        self::assertSame('app-eu-1', $record->logId);
        self::assertSame(self::SEAL_ID, $record->sealId);
        self::assertSame(self::SEAL_DIGEST, $record->sealDigest);
        self::assertSame(3, $record->memberCount);
        self::assertSame('BQ', $record->pruned);
        self::assertSame(2, $record->prunedCount);
        self::assertSame(self::OPERATION_ID, $record->operationId);
        self::assertSame(self::PRUNED_AT, $record->prunedAt);
        self::assertSame('k2026', $record->keyId);
        self::assertSame(self::SIGNATURE, $record->signature);
        self::assertSame(2, PruneRecord::VERSION);
    }

    /**
     * The golden records reproduce, and the canonical form leaves out the
     * signature.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheGoldenRecordsReproduce(): void
    {
        foreach (['first', 'second'] as $name) {
            $record = PruneRecord::fromArray([...self::fields($name), 'signature' => self::text('prune_' . $name . '_signature')]);

            self::assertSame(self::fields($name), $record->toArray(), $name);
            self::assertSame(self::text('prune_' . $name . '_canonical'), CanonicalEncoder::encode($record->toArray()), $name);
            self::assertSame(self::text('prune_' . $name . '_digest'), $record->digest(), $name);
            self::assertSame(hash('sha256', self::text('prune_' . $name . '_canonical')), $record->digest(), $name);
            self::assertArrayNotHasKey('signature', $record->toArray(), $name);
        }

        self::assertSame(self::record()->digest(), self::record(['signature' => str_repeat('0', 64)])->digest());
    }

    /**
     * Every field the signature covers changes the digest, the bitmap and its
     * count among them.
     *
     * @return void
     */
    public function testEveryBoundFieldChangesTheDigest(): void
    {
        $digest  = self::record()->digest();
        $changed = [
            'log id'       => ['log_id' => 'app-eu-2'],
            'seal id'      => ['seal_id' => '01932b4e-9000-7000-8000-000000000004'],
            'seal digest'  => ['seal_digest' => str_repeat('a', 64)],
            'member count' => ['member_count' => 4],
            'bitmap'       => ['pruned' => 'Ag', 'pruned_count' => 1],
            'operation id' => ['operation_id' => '01932b4e-a000-7000-8000-000000000002'],
            'pruned at'    => ['pruned_at' => '2027-11-01T00:00:00.000001Z'],
            'key id'       => ['key_id' => 'k2025'],
        ];

        foreach ($changed as $what => $fields) {
            self::assertNotSame($digest, self::record($fields)->digest(), $what);
        }
    }

    /**
     * The count must be how many members the bitmap sets: one fewer, one more
     * or the bitmap's under another bitmap is refused.
     *
     * @return void
     */
    public function testThePrunedCountMustBeThePopcount(): void
    {
        foreach ([1, 3] as $count) {
            try {
                self::record(['pruned_count' => $count]);
                self::fail(sprintf('Expected a count of %d to be refused.', $count));
            } catch (\InvalidArgumentException $exception) {
                self::assertSame(self::PRUNED_COUNT, $exception->getMessage());
            }
        }

        self::assertSame(3, self::record(['pruned' => 'Bw', 'pruned_count' => 3])->prunedCount);
    }

    /**
     * A count of none, or below none, is refused even over a bitmap that sets
     * none, so a record always prunes at least one member.
     *
     * @return void
     */
    public function testRefusesAZeroCount(): void
    {
        foreach ([0, -1] as $count) {
            try {
                self::record(['pruned' => 'AA', 'pruned_count' => $count]);
                self::fail(sprintf('Expected a count of %d to be refused.', $count));
            } catch (\InvalidArgumentException $exception) {
                self::assertSame(self::PRUNED_COUNT, $exception->getMessage());
            }
        }
    }

    /**
     * Rows of `[field, malformed value, message]`: one or more for each field.
     *
     * @return iterable<string, array{0: string, 1: int|string, 2: string}>
     */
    public static function provideMalformedFields(): iterable
    {
        $logId  = 'A prune record\'s `log_id` must be 1 to 64 letters, digits, dots, underscores or hyphens, starting with a letter or a digit.';
        $count  = 'A prune record\'s `member_count` must be from 1 to 50000.';
        $keyId  = 'A prune record\'s `key_id` must be 1 to 32 letters, digits, dots, underscores or hyphens, starting with a letter or a digit.';
        $digest = ' must be 64 lower-case hexadecimal characters.';

        yield from [
            'a log id starting with a dot'    => ['log_id', '.app', $logId],
            'a log id of 65 characters'       => ['log_id', str_repeat('a', 65), $logId],
            'an upper-case seal id'           => ['seal_id', strtoupper(self::SEAL_ID), 'A prune record\'s `seal_id` must be a lower-case UUID.'],
            'a short seal digest'             => ['seal_digest', substr(self::SEAL_DIGEST, 1), 'A prune record\'s `seal_digest`' . $digest],
            'no members'                      => ['member_count', 0, $count],
            'one member too many'             => ['member_count', 50001, $count],
            'a bitmap of other members'       => ['member_count', 9, self::PRUNED],
            'a padded bitmap'                 => ['pruned', 'BQ==', self::PRUNED],
            'a bitmap of base64'              => ['pruned', '+w', self::PRUNED],
            'a bitmap past the members'       => ['pruned', 'DQ', self::PRUNED],
            'a non-canonical bitmap'          => ['pruned', 'BR', self::PRUNED],
            'an empty bitmap'                 => ['pruned', '', self::PRUNED],
            'a count past the bitmap'         => ['pruned_count', 4, self::PRUNED_COUNT],
            'an operation id that is no UUID' => ['operation_id', 'prune-1', 'A prune record\'s `operation_id` must be a lower-case UUID.'],
            'a prune time in stored form'     => ['pruned_at', '2027-11-01 00:00:00.000000', 'A prune record\'s `pruned_at` must be ISO-8601 UTC with microseconds.'],
            'an empty key id'                 => ['key_id', '', $keyId],
            'a key id with a space'           => ['key_id', 'k 2026', $keyId],
            'an upper-case signature'         => ['signature', strtoupper(self::SIGNATURE), 'A prune record\'s `signature`' . $digest],
            'an empty signature'              => ['signature', '', 'A prune record\'s `signature`' . $digest],
        ];
    }

    /**
     * Each malformed field is refused with its message, built by hand and read
     * from its stored form alike.
     *
     * @param  string  $field
     * @param  int|string  $value
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMalformedFields')]
    public function testRefusesEachMalformedField(string $field, int|string $value, string $message): void
    {
        try {
            self::record([$field => $value]);
            self::fail('Expected the field to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame($message, $exception->getMessage());
        }

        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage($message);

        PruneRecord::fromArray([...self::record()->toArray(), 'signature' => self::SIGNATURE, $field => $value]);
    }

    /**
     * A record of one member and one of the most members a seal holds are both
     * kept.
     *
     * @return void
     */
    public function testAcceptsEachMemberCountBoundary(): void
    {
        self::assertSame(1, self::record(['member_count' => 1, 'pruned' => 'AQ', 'pruned_count' => 1])->memberCount);
        $first = rtrim(strtr(base64_encode("\x01" . str_repeat("\0", 6249)), '+/', '-_'), '=');

        self::assertSame(50000, self::record(['member_count' => 50000, 'pruned' => $first, 'pruned_count' => 1])->memberCount);
    }

    /**
     * Rows of `[version]`: every version but 2, and a 2 that is not an integer.
     *
     * @return iterable<string, array{0: int|string|null}>
     */
    public static function provideOtherVersions(): iterable
    {
        yield from [
            'version 1'   => [1],
            'version 3'   => [3],
            'two as text' => ['2'],
            'none'        => [null],
        ];
    }

    /**
     * A stored record of any other version is refused as one that cannot be
     * read, and one of version 2 reads back as it was signed.
     *
     * @param  int|string|null  $version
     * @return void
     */
    #[DataProvider('provideOtherVersions')]
    public function testFromArrayRefusesAnotherVersion(int|string|null $version): void
    {
        $stored = [...self::record()->toArray(), 'signature' => self::SIGNATURE];

        self::assertEquals(self::record(), PruneRecord::fromArray($stored));

        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('A stored prune record must be of version 2.');

        PruneRecord::fromArray([...$stored, 'v' => $version]);
    }

    /**
     * Rows of `[field, what it must be]`: every field of a stored record, each
     * left out.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideFields(): iterable
    {
        foreach (['log_id', 'seal_id', 'seal_digest', 'member_count', 'pruned', 'pruned_count', 'operation_id', 'pruned_at', 'key_id', 'signature'] as $field) {
            yield $field => [$field, in_array($field, ['member_count', 'pruned_count'], true) ? 'an integer' : 'text'];
        }
    }

    /**
     * A stored record missing any field, or holding it as another type, is
     * refused, naming the field.
     *
     * @param  string  $field
     * @param  string  $type
     * @return void
     */
    #[DataProvider('provideFields')]
    public function testFromArrayRefusesAMissingField(string $field, string $type): void
    {
        $stored  = [...self::record()->toArray(), 'signature' => self::SIGNATURE];
        $message = sprintf('A stored prune record\'s `%s` must be %s.', $field, $type);
        $other   = $type === 'text' ? 7 : '7';

        foreach (['missing' => array_diff_key($stored, [$field => true]), 'of another type' => [...$stored, $field => $other]] as $what => $fields) {
            try {
                PruneRecord::fromArray($fields);
                self::fail(sprintf('Expected a stored record with `%s` %s to be refused.', $field, $what));
            } catch (\UnexpectedValueException $exception) {
                self::assertSame($message, $exception->getMessage(), $what);
            }
        }
    }

    /**
     * A stored record holding a field no record of its version has is refused,
     * since its signature could not cover it.
     *
     * @return void
     */
    public function testFromArrayRefusesAnUnknownField(): void
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('A stored prune record must hold no field but those of its version.');

        PruneRecord::fromArray([...self::record()->toArray(), 'signature' => self::SIGNATURE, 'note' => 'kept']);
    }

    /**
     * A record covers exactly the members its bitmap sets, in member order.
     *
     * @return void
     */
    public function testPositionsAndCovers(): void
    {
        $first  = self::record();
        $second = self::record(['pruned' => 'Ag', 'pruned_count' => 1]);
        $wide   = self::record(['member_count' => 10, 'pruned' => 'AQI', 'pruned_count' => 2]);

        self::assertSame([0, 2], $first->positions());
        self::assertSame([1], $second->positions());
        self::assertSame([0, 9], $wide->positions());
        self::assertSame([true, false, true, false, false], array_map($first->covers(...), [0, 1, 2, 3, -1]));
        self::assertSame([false, true, false], array_map($second->covers(...), [0, 1, 2]));
        self::assertSame([true, false, true, false, false], array_map($wide->covers(...), [0, 8, 9, 10, 16]));
    }

    /**
     * The golden first record, with the fields given changed.
     *
     * @param  array<string, int|string>  $changes
     * @return \SineMacula\Laravel\AuditLog\Integrity\PruneRecord
     *
     * @throws \InvalidArgumentException
     */
    private static function record(array $changes = []): PruneRecord
    {
        $fields = [
            'log_id'       => 'app-eu-1',
            'seal_id'      => self::SEAL_ID,
            'seal_digest'  => self::SEAL_DIGEST,
            'member_count' => 3,
            'pruned'       => 'BQ',
            'pruned_count' => 2,
            'operation_id' => self::OPERATION_ID,
            'pruned_at'    => self::PRUNED_AT,
            'key_id'       => 'k2026',
            'signature'    => self::SIGNATURE,
            ...$changes,
        ];

        return new PruneRecord(
            (string) $fields['log_id'],
            (string) $fields['seal_id'],
            (string) $fields['seal_digest'],
            (int) $fields['member_count'],
            (string) $fields['pruned'],
            (int) $fields['pruned_count'],
            (string) $fields['operation_id'],
            (string) $fields['pruned_at'],
            (string) $fields['key_id'],
            (string) $fields['signature'],
        );
    }

    /**
     * The golden fields of the record named.
     *
     * @param  'first'|'second'  $name
     * @return array<string, int|string>
     *
     * @throws \JsonException
     */
    private static function fields(string $name): array
    {
        $fields = self::vectors()['prune_' . $name] ?? null;

        /** @var array<string, int|string> */
        return is_array($fields) ? $fields : self::fail(sprintf('The golden prune vectors have no `prune_%s`.', $name));
    }

    /**
     * The golden string under the key given.
     *
     * @param  string  $field
     * @return string
     *
     * @throws \JsonException
     */
    private static function text(string $field): string
    {
        $value = self::vectors()[$field] ?? null;

        return is_string($value) ? $value : self::fail(sprintf('The golden prune vectors have no `%s`.', $field));
    }

    /**
     * The golden prune vectors, decoded.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return array<array-key, mixed>
     *
     * @throws \JsonException
     */
    private static function vectors(): array
    {
        $vectors = json_decode((string) file_get_contents(self::GOLDEN), true, 512, JSON_THROW_ON_ERROR);

        return is_array($vectors) ? $vectors : self::fail('The golden prune vectors are not a map.');
    }
}
