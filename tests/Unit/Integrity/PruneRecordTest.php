<?php

declare(strict_types = 1);

namespace Tests\Unit\Integrity;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Integrity\PruneRecord;

/**
 * Unit tests for the prune record: the fields it keeps, the canonical form that
 * leaves out its signature, the golden digest reproduced, and each malformed
 * field refused with its message.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PruneRecord::class)]
final class PruneRecordTest extends TestCase
{
    /** @var string The golden seal vectors. */
    private const string GOLDEN = __DIR__ . '/../../Fixtures/Integrity/seal-v1.json';

    /** @var string The golden first seal's id. */
    private const string SEAL_ID = '01932b4e-9000-7000-8000-000000000001';

    /** @var string The golden second seal's id. */
    private const string OTHER_SEAL_ID = '01932b4e-9000-7000-8000-000000000002';

    /** @var string The golden first seal's digest. */
    private const string SEAL_DIGEST = '329162defc18f3f10f3a8a351a7faa0c0e5e1004d65ea3b432feb0b54d3282c6';

    /** @var string The golden prune operation's id. */
    private const string OPERATION_ID = '01932b4e-a000-7000-8000-000000000001';

    /** @var string When the golden prune ran. */
    private const string PRUNED_AT = '2027-11-01T00:00:00.000000Z';

    /** @var string The golden prune signature. */
    private const string SIGNATURE = '4d29b82a8f85a8d8225104279ddd477f350dac4a41f667d359665900081291c5';

    /**
     * The record keeps every field as given.
     *
     * @return void
     */
    public function testKeepsEveryField(): void
    {
        $record = self::record();

        self::assertSame('app-eu-1', $record->logId);
        self::assertSame(self::SEAL_ID, $record->sealId);
        self::assertSame(self::SEAL_DIGEST, $record->sealDigest);
        self::assertSame(2, $record->memberCount);
        self::assertSame(self::OPERATION_ID, $record->operationId);
        self::assertSame(self::PRUNED_AT, $record->prunedAt);
        self::assertSame('k2026', $record->keyId);
        self::assertSame(self::SIGNATURE, $record->signature);
        self::assertSame(1, PruneRecord::VERSION);
    }

    /**
     * The canonical form holds the version and every field but the signature,
     * so the digest does not change with it.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheCanonicalFormLeavesOutTheSignature(): void
    {
        $record = self::record();

        self::assertSame(self::golden('prune'), $record->toArray());
        self::assertArrayNotHasKey('signature', $record->toArray());
        self::assertSame($record->digest(), self::record(str_repeat('0', 64))->digest());
    }

    /**
     * The golden record encodes to the golden canonical string and has the
     * golden digest.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheGoldenDigestIsReproduced(): void
    {
        $record = self::record();

        self::assertSame(self::golden('prune_canonical'), CanonicalEncoder::encode($record->toArray()));
        self::assertSame(self::golden('prune_digest'), $record->digest());
        self::assertSame(hash('sha256', self::golden('prune_canonical')), $record->digest());
    }

    /**
     * Every bound field changes the digest.
     *
     * @return void
     */
    public function testEveryBoundFieldChangesTheDigest(): void
    {
        $digest = self::record()->digest();

        $changed = [
            'log id'       => new PruneRecord('app-eu-2', self::SEAL_ID, self::SEAL_DIGEST, 2, self::OPERATION_ID, self::PRUNED_AT, 'k2026', self::SIGNATURE),
            'seal id'      => new PruneRecord('app-eu-1', self::OTHER_SEAL_ID, self::SEAL_DIGEST, 2, self::OPERATION_ID, self::PRUNED_AT, 'k2026', self::SIGNATURE),
            'seal digest'  => new PruneRecord('app-eu-1', self::SEAL_ID, str_repeat('a', 64), 2, self::OPERATION_ID, self::PRUNED_AT, 'k2026', self::SIGNATURE),
            'member count' => new PruneRecord('app-eu-1', self::SEAL_ID, self::SEAL_DIGEST, 3, self::OPERATION_ID, self::PRUNED_AT, 'k2026', self::SIGNATURE),
            'operation id' => new PruneRecord('app-eu-1', self::SEAL_ID, self::SEAL_DIGEST, 2, '01932b4e-a000-7000-8000-000000000002', self::PRUNED_AT, 'k2026', self::SIGNATURE),
            'pruned at'    => new PruneRecord('app-eu-1', self::SEAL_ID, self::SEAL_DIGEST, 2, self::OPERATION_ID, '2027-11-01T00:00:00.000001Z', 'k2026', self::SIGNATURE),
            'key id'       => new PruneRecord('app-eu-1', self::SEAL_ID, self::SEAL_DIGEST, 2, self::OPERATION_ID, self::PRUNED_AT, 'k2025', self::SIGNATURE),
        ];

        foreach ($changed as $what => $record) {
            self::assertNotSame($digest, $record->digest(), $what);
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
            'an operation id that is no UUID' => ['operation_id', 'prune-1', 'A prune record\'s `operation_id` must be a lower-case UUID.'],
            'a prune time in stored form'     => ['pruned_at', '2027-11-01 00:00:00.000000', 'A prune record\'s `pruned_at` must be ISO-8601 UTC with microseconds.'],
            'an empty key id'                 => ['key_id', '', $keyId],
            'a key id with a space'           => ['key_id', 'k 2026', $keyId],
            'an upper-case signature'         => ['signature', strtoupper(self::SIGNATURE), 'A prune record\'s `signature`' . $digest],
            'an empty signature'              => ['signature', '', 'A prune record\'s `signature`' . $digest],
        ];
    }

    /**
     * Each malformed field is refused with its message.
     *
     * @param  string  $field
     * @param  int|string  $value
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMalformedFields')]
    public function testRefusesEachMalformedField(string $field, int|string $value, string $message): void
    {
        $fields = [
            'log_id'       => 'app-eu-1',
            'seal_id'      => self::SEAL_ID,
            'seal_digest'  => self::SEAL_DIGEST,
            'member_count' => 2,
            'operation_id' => self::OPERATION_ID,
            'pruned_at'    => self::PRUNED_AT,
            'key_id'       => 'k2026',
            'signature'    => self::SIGNATURE,
            $field         => $value,
        ];

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        new PruneRecord(
            (string) $fields['log_id'],
            (string) $fields['seal_id'],
            (string) $fields['seal_digest'],
            (int) $fields['member_count'],
            (string) $fields['operation_id'],
            (string) $fields['pruned_at'],
            (string) $fields['key_id'],
            (string) $fields['signature'],
        );
    }

    /**
     * A record of one member and one of the most members a seal holds are both
     * kept.
     *
     * @return void
     */
    public function testAcceptsEachMemberCountBoundary(): void
    {
        foreach ([1, 50000] as $count) {
            $record = new PruneRecord('app-eu-1', self::SEAL_ID, self::SEAL_DIGEST, $count, self::OPERATION_ID, self::PRUNED_AT, 'k2026', self::SIGNATURE);

            self::assertSame($count, $record->memberCount);
        }
    }

    /**
     * The golden prune record, under the signature given.
     *
     * @param  string  $signature
     * @return \SineMacula\Laravel\AuditLog\Integrity\PruneRecord
     */
    private static function record(string $signature = self::SIGNATURE): PruneRecord
    {
        return new PruneRecord('app-eu-1', self::SEAL_ID, self::SEAL_DIGEST, 2, self::OPERATION_ID, self::PRUNED_AT, 'k2026', $signature);
    }

    /**
     * The golden value under the key given.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $field
     * @return mixed
     *
     * @throws \JsonException
     */
    private static function golden(string $field): mixed
    {
        $golden = json_decode((string) file_get_contents(self::GOLDEN), true, 512, JSON_THROW_ON_ERROR);

        return is_array($golden) && array_key_exists($field, $golden) ? $golden[$field] : self::fail(sprintf('The golden seal has no `%s`.', $field));
    }
}
