<?php

declare(strict_types = 1);

namespace Tests\Unit\Integrity;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Integrity\SealEnvelope;

/**
 * Unit tests for the seal envelope: the golden members digest, canonical seal
 * and digest reproduced byte for byte, the second golden seal chained onto the
 * first, members sorted bytewise whatever their order, a digest that every
 * field changes, each malformed field and member refused with its message, the
 * genesis rule left to verification, and a stored seal read in every form an
 * engine returns, refused naming the column and never quoting its value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SealEnvelope::class)]
final class SealEnvelopeTest extends TestCase
{
    /** @var string The golden seal vectors. */
    private const string GOLDEN = __DIR__ . '/../../Fixtures/Integrity/seal-v1.json';

    /** @var string A digest that is not the golden seal's. */
    private const string OTHER_DIGEST = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

    /** @var string A signature, for a stored row. */
    private const string SIGNATURE = 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';

    /** @var string Why a stored column is refused, by the column it names. */
    private const string STORED_MALFORMED = 'A stored seal\'s `%s` is malformed.';

    /** @var list<string> The thirteen envelope columns a stored seal must have. */
    private const array COLUMNS = [
        'id', 'sequence', 'log_id', 'previous_id', 'previous_digest', 'member_count', 'members_digest',
        'first_recorded_at', 'last_recorded_at', 'sealed_at', 'signer', 'key_id', 'algorithm_version',
    ];

    /**
     * The envelope's versions, signer and limits are pinned: a change to any is
     * a new version of the seal, never an edit of this one.
     *
     * @return void
     */
    public function testTheConstantsArePinned(): void
    {
        self::assertSame(1, SealEnvelope::VERSION);
        self::assertSame(1, SealEnvelope::ALGORITHM_VERSION);
        self::assertSame([1], SealEnvelope::SUPPORTED_ALGORITHM_VERSIONS);
        self::assertSame('hmac', SealEnvelope::SIGNER);
        self::assertSame(50000, SealEnvelope::MAX_MEMBERS);
        self::assertSame('/\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\z/', SealEnvelope::LOG_ID_PATTERN);
    }

    /**
     * The golden members, given out of order, give the golden canonical list
     * and its digest.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheGoldenMembersDigestIsReproduced(): void
    {
        $members = self::goldenMembers('members');

        self::assertSame('01932b4e-8a40-7000-8000-000000000002', $members[0][0]);
        self::assertSame(self::goldenString('members_digest'), SealEnvelope::membersDigest($members));
        self::assertSame(self::goldenString('members_digest'), hash('sha256', self::goldenString('members_canonical')));
        self::assertSame(self::goldenString('seal_2_members_digest'), SealEnvelope::membersDigest(self::goldenMembers('seal_2_members')));
    }

    /**
     * The golden first seal has the golden fourteen fields, encodes to the
     * golden canonical string, and has the golden digest.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheGoldenSealCanonicalAndDigestAreReproduced(): void
    {
        $seal = self::goldenSeal('seal_1');

        self::assertSame(self::goldenFields('seal_1'), $seal->toArray());
        self::assertCount(14, $seal->toArray());
        self::assertSame(self::goldenString('seal_1_canonical'), CanonicalEncoder::encode($seal->toArray()));
        self::assertSame(self::goldenString('seal_1_digest'), $seal->digest());
        self::assertSame(self::goldenString('members_digest'), $seal->membersDigest);
    }

    /**
     * The golden second seal links to the first by its id and its digest, and
     * reproduces its own digest.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheSecondGoldenSealChainsOntoTheFirst(): void
    {
        $first  = self::goldenSeal('seal_1');
        $second = self::goldenSeal('seal_2');

        self::assertSame($first->sequence + 1, $second->sequence);
        self::assertSame($first->id, $second->previousId);
        self::assertSame($first->digest(), $second->previousDigest);
        self::assertSame(self::goldenString('seal_2_members_digest'), $second->membersDigest);
        self::assertSame(self::goldenString('seal_2_digest'), $second->digest());
        self::assertNotSame($first->digest(), $second->digest());
    }

    /**
     * Every order of the members gives one digest, the digest of the members
     * sorted bytewise by entry id: a digit sorts before a letter, and the HMACs
     * play no part in the order.
     *
     * @return void
     */
    public function testMembersAreSortedBytewiseWhateverTheirOrder(): void
    {
        $nine   = ['01932b4e-8a40-7000-8000-000000000009', str_repeat('f', 64)];
        $letter = ['01932b4e-8a40-7000-8000-00000000000a', str_repeat('0', 64)];
        $one    = ['01932b4e-8a40-7000-8000-000000000001', str_repeat('e', 64)];

        $expected = hash('sha256', CanonicalEncoder::encode([$one, $nine, $letter]));

        foreach ([[$one, $nine, $letter], [$letter, $nine, $one], [$nine, $one, $letter], [$letter, $one, $nine]] as $order) {
            self::assertSame($expected, SealEnvelope::membersDigest($order));
        }

        self::assertNotSame($expected, hash('sha256', CanonicalEncoder::encode([$one, $letter, $nine])));
    }

    /**
     * Rows of `[field, changed value, whether an envelope can hold it]`: each
     * of the fourteen fields. The version, the signer and the algorithm version
     * have one value this release builds, so a change to them is shown on the
     * encoded fields.
     *
     * @return iterable<string, array{0: string, 1: int|string, 2: bool}>
     */
    public static function provideChangedFields(): iterable
    {
        yield from [
            'v'                 => ['v', 2, false],
            'log_id'            => ['log_id', 'app-eu-2', true],
            'id'                => ['id', '01932b4e-9000-7000-8000-000000000009', true],
            'sequence'          => ['sequence', 2, true],
            'previous_id'       => ['previous_id', '01932b4e-9000-7000-8000-000000000000', true],
            'previous_digest'   => ['previous_digest', self::OTHER_DIGEST, true],
            'member_count'      => ['member_count', 3, true],
            'members_digest'    => ['members_digest', self::OTHER_DIGEST, true],
            'first_recorded_at' => ['first_recorded_at', '2026-10-31T23:34:56.890124Z', true],
            'last_recorded_at'  => ['last_recorded_at', '2026-10-31T23:35:00.000002Z', true],
            'sealed_at'         => ['sealed_at', '2026-10-31T23:40:00.000001Z', true],
            'signer'            => ['signer', 'ed25519', false],
            'key_id'            => ['key_id', 'k2025', true],
            'algorithm_version' => ['algorithm_version', 2, false],
        ];
    }

    /**
     * Changing any one of the fourteen fields changes the seal digest, so none
     * can be altered unnoticed.
     *
     * @param  string  $field
     * @param  int|string  $value
     * @param  bool  $buildable
     * @return void
     *
     * @throws \JsonException
     */
    #[DataProvider('provideChangedFields')]
    public function testChangingAnyFieldChangesTheDigest(string $field, int|string $value, bool $buildable): void
    {
        $golden  = self::goldenSeal('seal_1');
        $changed = [...$golden->toArray(), $field => $value];
        $digest  = hash('sha256', CanonicalEncoder::encode($changed));

        self::assertArrayHasKey($field, $golden->toArray());
        self::assertNotSame($golden->digest(), $digest, $field);

        if (!$buildable) {
            return;
        }

        self::assertSame($digest, self::envelope([$field => $value])->digest(), $field);
    }

    /**
     * An empty member list is refused: a seal holds at least one entry.
     *
     * @return void
     */
    public function testRefusesAnEmptyMemberList(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A seal must have at least one member.');

        SealEnvelope::membersDigest([]);
    }

    /**
     * An entry given twice is refused, even with another HMAC: an entry belongs
     * to a seal at most once.
     *
     * @return void
     */
    public function testRefusesADuplicateMember(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A seal\'s members must each be a different entry.');

        SealEnvelope::membersDigest([
            ['01932b4e-8a40-7000-8000-000000000001', str_repeat('a', 64)],
            ['01932b4e-8a40-7000-8000-000000000002', str_repeat('b', 64)],
            ['01932b4e-8a40-7000-8000-000000000001', str_repeat('c', 64)],
        ]);
    }

    /**
     * Rows of `[entry id, HMAC, message]`: members whose id is not a lower-case
     * UUID or whose HMAC is not 64 lower-case hex.
     *
     * @return iterable<string, array{0: string, 1: string, 2: string}>
     */
    public static function provideMalformedMembers(): iterable
    {
        $id     = 'A seal member\'s entry id must be a lower-case UUID, the form every engine stores and returns.';
        $hmac   = 'A seal member\'s HMAC must be 64 lower-case hexadecimal characters.';
        $valid  = '01932b4e-8a40-7000-8000-000000000001';
        $digest = str_repeat('a', 64);

        yield from [
            'an upper-case id'    => ['01932B4E-8A40-7000-8000-000000000001', $digest, $id],
            'an id with no dash'  => ['01932b4e8a40700080000000000000001', $digest, $id],
            'an empty id'         => ['', $digest, $id],
            'a short HMAC'        => [$valid, str_repeat('a', 63), $hmac],
            'a long HMAC'         => [$valid, str_repeat('a', 65), $hmac],
            'a non-hex HMAC'      => [$valid, str_repeat('g', 64), $hmac],
            'an upper-case HMAC'  => [$valid, str_repeat('A', 64), $hmac],
            'an HMAC with a line' => [$valid, $digest . "\n", $hmac],
        ];
    }

    /**
     * Each malformed member is refused with its message, wherever it sits in
     * the list.
     *
     * @param  string  $entryId
     * @param  string  $hmac
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMalformedMembers')]
    public function testRefusesAMalformedMember(string $entryId, string $hmac, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        SealEnvelope::membersDigest([['01932b4e-8a40-7000-8000-000000000002', str_repeat('b', 64)], [$entryId, $hmac]]);
    }

    /**
     * Rows of `[field, malformed value, message]`: one or more for each rule of
     * the constructor.
     *
     * @return iterable<string, array{0: string, 1: int|string|null, 2: string}>
     */
    public static function provideMalformedFields(): iterable
    {
        $logId   = 'A seal\'s `log_id` must be 1 to 64 letters, digits, dots, underscores or hyphens, starting with a letter or a digit.';
        $id      = 'A seal\'s `id` must be a lower-case UUID, the form every engine stores and returns.';
        $count   = 'A seal\'s `member_count` must be from 1 to 50000.';
        $last    = 'A seal\'s `last_recorded_at` must be ISO-8601 UTC with microseconds, and not before its `first_recorded_at`.';
        $keyId   = 'A seal\'s `key_id` must be 1 to 32 letters, digits, dots, underscores or hyphens, starting with a letter or a digit.';
        $version = 'A seal\'s `algorithm_version` is not supported by this release.';

        yield from [
            'a log id starting with a hyphen' => ['log_id', '-a', $logId],
            'a log id with a slash'           => ['log_id', 'a/b', $logId],
            'a log id of 65 characters'       => ['log_id', str_repeat('a', 65), $logId],
            'an empty log id'                 => ['log_id', '', $logId],
            'an upper-case id'                => ['id', '01932B4E-9000-7000-8000-000000000001', $id],
            'an id that is no UUID'           => ['id', 'seal-1', $id],
            'a sequence of 0'                 => ['sequence', 0, 'A seal\'s `sequence` must be at least 1.'],
            'a negative sequence'             => ['sequence', -1, 'A seal\'s `sequence` must be at least 1.'],
            'an upper-case previous id'       => ['previous_id', '01932B4E-9000-7000-8000-000000000000', 'A seal\'s `previous_id` must be null or a lower-case UUID.'],
            'a short previous digest'         => ['previous_digest', str_repeat('a', 63), 'A seal\'s `previous_digest` must be null or 64 lower-case hexadecimal characters.'],
            'no members'                      => ['member_count', 0, $count],
            'one member too many'             => ['member_count', 50001, $count],
            'an upper-case members digest'    => ['members_digest', str_repeat('A', 64), 'A seal\'s `members_digest` must be 64 lower-case hexadecimal characters.'],
            'a first time in the stored form' => ['first_recorded_at', '2026-10-31 23:34:56.890123', 'A seal\'s `first_recorded_at` must be ISO-8601 UTC with microseconds.'],
            'a first time on no date'         => ['first_recorded_at', '2026-02-30T00:00:00.000000Z', 'A seal\'s `first_recorded_at` must be ISO-8601 UTC with microseconds.'],
            'a last time with no fraction'    => ['last_recorded_at', '2026-10-31T23:35:00Z', $last],
            'a last time before the first'    => ['last_recorded_at', '2026-10-31T23:34:56.890122Z', $last],
            'a seal time with an offset'      => ['sealed_at', '2026-10-31T23:40:00.000000+00:00', 'A seal\'s `sealed_at` must be ISO-8601 UTC with microseconds.'],
            'an empty key id'                 => ['key_id', '', $keyId],
            'a key id of 33 characters'       => ['key_id', str_repeat('k', 33), $keyId],
            'an algorithm version of 2'       => ['algorithm_version', 2, $version],
            'an algorithm version of 0'       => ['algorithm_version', 0, $version],
            'another signer'                  => ['signer', 'ed25519', 'A seal\'s `signer` must be `hmac`.'],
            'an upper-case signer'            => ['signer', 'HMAC', 'A seal\'s `signer` must be `hmac`.'],
        ];
    }

    /**
     * Each malformed field is refused with one sentence naming the field.
     *
     * @param  string  $field
     * @param  int|string|null  $value
     * @param  string  $message
     * @return void
     *
     * @throws \JsonException
     */
    #[DataProvider('provideMalformedFields')]
    public function testRefusesEachMalformedField(string $field, int|string|null $value, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        self::envelope([$field => $value]);
    }

    /**
     * The first and the latest member's times may be the same instant, and a
     * seal may hold the most members there are.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAcceptsEachBoundary(): void
    {
        $seal = self::envelope(['last_recorded_at' => '2026-10-31T23:34:56.890123Z', 'member_count' => 50000, 'sequence' => PHP_INT_MAX]);

        self::assertSame($seal->firstRecordedAt, $seal->lastRecordedAt);
        self::assertSame(50000, $seal->memberCount);
        self::assertSame(PHP_INT_MAX, $seal->sequence);
        self::assertSame(1, self::envelope(['member_count' => 1])->memberCount);
    }

    /**
     * Neither the genesis rule nor the pairing of the previous fields is
     * enforced when a seal is built or loaded: a later seal with no link, a
     * genesis seal with one, or one previous field without the other is
     * evidence for verification to report, not a row to refuse.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testDoesNotEnforceGenesisWhenLoading(): void
    {
        $orphan = self::envelope(['sequence' => 3, 'previous_id' => null, 'previous_digest' => null]);

        self::assertSame(3, $orphan->sequence);
        self::assertNull($orphan->previousId);
        self::assertNull($orphan->previousDigest);

        $linkedGenesis = self::envelope(['previous_id' => '01932b4e-9000-7000-8000-000000000000', 'previous_digest' => self::OTHER_DIGEST]);

        self::assertSame(1, $linkedGenesis->sequence);
        self::assertSame(self::OTHER_DIGEST, $linkedGenesis->previousDigest);

        $half = self::envelope(['sequence' => 2, 'previous_digest' => self::OTHER_DIGEST]);

        self::assertNull($half->previousId);
        self::assertSame($orphan->toArray(), SealEnvelope::fromRow($orphan->toRow(self::OTHER_DIGEST, self::SIGNATURE))->toArray());
        self::assertSame($half->toArray(), SealEnvelope::fromRow($half->toRow(self::OTHER_DIGEST, self::SIGNATURE))->toArray());
    }

    /**
     * A stored seal reads back as the envelope it was written from, whatever
     * other columns the row holds.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testFromRowReadsTheStoredEnvelope(): void
    {
        $seal   = self::goldenSeal('seal_2');
        $stored = [...$seal->toRow($seal->digest(), self::SIGNATURE), 'anchor' => null, 'anchor_receipt' => '{}', 'anchored_at' => null];

        $read = SealEnvelope::fromRow($stored);

        self::assertSame($seal->toArray(), $read->toArray());
        self::assertSame(self::goldenString('seal_2_digest'), $read->digest());
    }

    /**
     * Rows of `[stored time, the instant it reads as]`: the forms the engines
     * return, PostgreSQL dropping trailing fractional zeros.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideStoredTimes(): iterable
    {
        yield from [
            'one fractional digit'  => ['2026-10-31 23:40:00.2', '2026-10-31T23:40:00.200000Z'],
            'six fractional digits' => ['2026-10-31 23:40:00.200000', '2026-10-31T23:40:00.200000Z'],
            'no fraction'           => ['2026-10-31 23:40:00', '2026-10-31T23:40:00.000000Z'],
            'microseconds'          => ['2026-10-31 23:40:00.000001', '2026-10-31T23:40:00.000001Z'],
        ];
    }

    /**
     * Each time a stored seal holds is read in every form an engine returns,
     * and converted to the package's form, so the digest is the one signed.
     *
     * @param  string  $stored
     * @param  string  $instant
     * @return void
     *
     * @throws \JsonException
     */
    #[DataProvider('provideStoredTimes')]
    public function testFromRowReadsEachEngineTimeForm(string $stored, string $instant): void
    {
        $row = self::storedRow(['sealed_at' => $stored, 'first_recorded_at' => '2026-10-31 23:34:56.890123', 'last_recorded_at' => $stored]);

        $seal = SealEnvelope::fromRow($row);

        self::assertSame($instant, $seal->sealedAt);
        self::assertSame($instant, $seal->lastRecordedAt);
        self::assertSame('2026-10-31T23:34:56.890123Z', $seal->firstRecordedAt);
    }

    /**
     * An integer column is read from an integer or from the decimal string an
     * engine may return for one.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testFromRowReadsIntegersAsTheirDecimalStrings(): void
    {
        $seal = SealEnvelope::fromRow(self::storedRow(['sequence' => '1', 'member_count' => '2', 'algorithm_version' => '1']));

        self::assertSame(1, $seal->sequence);
        self::assertSame(2, $seal->memberCount);
        self::assertSame(1, $seal->algorithmVersion);
        self::assertSame(self::goldenString('seal_1_digest'), $seal->digest());
    }

    /**
     * Rows of `[column]`: each of the thirteen envelope columns.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideEnvelopeColumns(): iterable
    {
        foreach (self::COLUMNS as $column) {
            yield $column => [$column];
        }
    }

    /**
     * A stored seal missing any envelope column is refused naming it; a column
     * holding `null` is present, and one missing is never read as `null`.
     *
     * @param  string  $column
     * @return void
     *
     * @throws \JsonException
     */
    #[DataProvider('provideEnvelopeColumns')]
    public function testFromRowRefusesAMissingColumnNamingIt(string $column): void
    {
        $row = self::storedRow();

        unset($row[$column]);

        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage(sprintf('A stored seal has no `%s` column; every envelope column is required to read it.', $column));

        SealEnvelope::fromRow($row);
    }

    /**
     * The digest and the signature are not envelope columns: a row without them
     * still reads.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testFromRowNeedsNoDigestOrSignature(): void
    {
        $row = self::storedRow();

        unset($row['seal_digest'], $row['signature']);

        self::assertSame(self::goldenString('seal_1_digest'), SealEnvelope::fromRow($row)->digest());
    }

    /**
     * Rows of `[column, malformed stored value]`: a wrong type, a malformed
     * form, and a value the envelope refuses, each holding the planted text
     * where it can.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: string, 1: mixed}>
     */
    public static function provideMalformedStoredValues(): iterable
    {
        yield from [
            'a log id that is no string'       => ['log_id', 42],
            'a log id outside the grammar'     => ['log_id', 's3cr3t/log'],
            'an id that is no UUID'            => ['id', 's3cr3t'],
            'an id that is null'               => ['id', null],
            'a sequence that is no integer'    => ['sequence', 's3cr3t'],
            'a sequence padded with a zero'    => ['sequence', '01'],
            'a sequence of 0'                  => ['sequence', 0],
            'a float sequence'                 => ['sequence', 1.0],
            'a previous id that is no string'  => ['previous_id', ['s3cr3t']],
            'a previous digest that is upper'  => ['previous_digest', 'S3CR3T' . str_repeat('A', 58)],
            'a member count over the most'     => ['member_count', '50001'],
            'a members digest that is null'    => ['members_digest', null],
            'a first time that is no time'     => ['first_recorded_at', 's3cr3t'],
            'a last time in the package form'  => ['last_recorded_at', '2026-10-31T23:35:00.000001Z'],
            'a last time before the first'     => ['last_recorded_at', '2026-10-31 23:34:56.890122'],
            'a seal time that is an integer'   => ['sealed_at', 1793490000],
            'a seal time on no date'           => ['sealed_at', '2026-02-30 00:00:00'],
            'another signer'                   => ['signer', 's3cr3t'],
            'a key id outside the grammar'     => ['key_id', 's3cr3t key'],
            'an algorithm version unsupported' => ['algorithm_version', 2],
            'an algorithm version as text'     => ['algorithm_version', 'one'],
        ];
    }

    /**
     * Each malformed stored column is refused with an unexpected-value
     * exception naming the column and never quoting the value, nor chaining the
     * refusal that found it.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $column
     * @param  mixed  $value
     * @return void
     *
     * @throws \JsonException
     */
    #[DataProvider('provideMalformedStoredValues')]
    public function testFromRowNeverQuotesAValue(string $column, mixed $value): void
    {
        try {
            SealEnvelope::fromRow(self::storedRow([$column => $value]));
            self::fail('Expected the stored seal to be refused.');
        } catch (\UnexpectedValueException $exception) {
            self::assertSame(sprintf(self::STORED_MALFORMED, $column), $exception->getMessage());
            self::assertStringNotContainsStringIgnoringCase('s3cr3t', $exception->getMessage());
            self::assertNull($exception->getPrevious());
        }
    }

    /**
     * The insert row holds the thirteen envelope columns, the digest and the
     * signature in table order, every time in the form the database stores, and
     * no anchor column.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testToRowStoresTimesInTheStorageForm(): void
    {
        $seal = self::goldenSeal('seal_1');

        self::assertSame([
            'id'                => '01932b4e-9000-7000-8000-000000000001',
            'sequence'          => 1,
            'log_id'            => 'app-eu-1',
            'previous_id'       => null,
            'previous_digest'   => null,
            'member_count'      => 2,
            'members_digest'    => self::goldenString('members_digest'),
            'seal_digest'       => self::goldenString('seal_1_digest'),
            'first_recorded_at' => '2026-10-31 23:34:56.890123',
            'last_recorded_at'  => '2026-10-31 23:35:00.000001',
            'sealed_at'         => '2026-10-31 23:40:00.000000',
            'signer'            => 'hmac',
            'key_id'            => 'k2026',
            'algorithm_version' => 1,
            'signature'         => self::goldenString('seal_1_signature'),
        ], $seal->toRow(self::goldenString('seal_1_digest'), self::goldenString('seal_1_signature')));
    }

    /**
     * Rows of `[digest, signature, message]`: a digest or a signature that is
     * not 64 lower-case hex.
     *
     * @return iterable<string, array{0: string, 1: string, 2: string}>
     */
    public static function provideMalformedDigestsAndSignatures(): iterable
    {
        $digest    = 'A seal\'s `seal_digest` must be 64 lower-case hexadecimal characters.';
        $signature = 'A seal\'s `signature` must be 64 lower-case hexadecimal characters.';

        yield from [
            'a short digest'       => [str_repeat('a', 63), self::SIGNATURE, $digest],
            'an upper-case digest' => [str_repeat('A', 64), self::SIGNATURE, $digest],
            'an empty signature'   => [self::OTHER_DIGEST, '', $signature],
            'a non-hex signature'  => [self::OTHER_DIGEST, str_repeat('z', 64), $signature],
        ];
    }

    /**
     * A digest or a signature no seal could have is refused before the row is
     * built.
     *
     * @param  string  $digest
     * @param  string  $signature
     * @param  string  $message
     * @return void
     *
     * @throws \JsonException
     */
    #[DataProvider('provideMalformedDigestsAndSignatures')]
    public function testToRowRefusesAMalformedDigestOrSignature(string $digest, string $signature, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        self::goldenSeal('seal_1')->toRow($digest, $signature);
    }

    /**
     * Neither the order of the envelope's fields nor the order of a stored
     * row's columns changes the digest: the canonical encoding sorts the keys.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheEnvelopeAndTheSignedRowOrderAreIrrelevant(): void
    {
        $seal     = self::goldenSeal('seal_1');
        $reversed = array_reverse($seal->toArray(), true);

        self::assertNotSame(array_keys($seal->toArray()), array_keys($reversed));
        self::assertSame($seal->digest(), hash('sha256', CanonicalEncoder::encode($reversed)));
        self::assertSame($seal->digest(), SealEnvelope::fromRow(array_reverse(self::storedRow(), true))->digest());
    }

    /**
     * The golden first seal's stored row, with the overrides given, as an
     * engine returns it.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $overrides
     * @return array<string, mixed>
     *
     * @throws \JsonException
     */
    private static function storedRow(array $overrides = []): array
    {
        return [...self::goldenSeal('seal_1')->toRow(self::goldenString('seal_1_digest'), self::goldenString('seal_1_signature')), ...$overrides];
    }

    /**
     * The golden first seal with the fields given changed, built through the
     * constructor.
     *
     * @param  array<string, int|string|null>  $overrides
     * @return \SineMacula\Laravel\AuditLog\Integrity\SealEnvelope
     *
     * @throws \JsonException
     */
    private static function envelope(array $overrides): SealEnvelope
    {
        return self::build([...self::goldenFields('seal_1'), ...$overrides]);
    }

    /**
     * The golden seal under the key given.
     *
     * @param  'seal_1'|'seal_2'  $seal
     * @return \SineMacula\Laravel\AuditLog\Integrity\SealEnvelope
     *
     * @throws \JsonException
     */
    private static function goldenSeal(string $seal): SealEnvelope
    {
        return self::build(self::goldenFields($seal));
    }

    /**
     * An envelope of the fields given, under their canonical keys; a field of
     * the wrong type fails the test rather than the envelope.
     *
     * @param  array<string, int|string|null>  $fields
     * @return \SineMacula\Laravel\AuditLog\Integrity\SealEnvelope
     */
    private static function build(array $fields): SealEnvelope
    {
        return new SealEnvelope(
            self::text($fields['log_id']),
            self::text($fields['id']),
            self::integer($fields['sequence']),
            $fields['previous_id']     === null ? null : self::text($fields['previous_id']),
            $fields['previous_digest'] === null ? null : self::text($fields['previous_digest']),
            self::integer($fields['member_count']),
            self::text($fields['members_digest']),
            self::text($fields['first_recorded_at']),
            self::text($fields['last_recorded_at']),
            self::text($fields['sealed_at']),
            self::text($fields['key_id']),
            self::integer($fields['algorithm_version']),
            self::text($fields['signer']),
        );
    }

    /**
     * The value as a string, failing the test otherwise.
     *
     * @param  int|string|null  $value
     * @return string
     */
    private static function text(int|string|null $value): string
    {
        return is_string($value) ? $value : self::fail('A golden field is not a string.');
    }

    /**
     * The value as an integer, failing the test otherwise.
     *
     * @param  int|string|null  $value
     * @return int
     */
    private static function integer(int|string|null $value): int
    {
        return is_int($value) ? $value : self::fail('A golden field is not an integer.');
    }

    /**
     * The golden seal's fourteen fields, in the envelope's order.
     *
     * @param  'seal_1'|'seal_2'  $seal
     * @return array<string, int|string|null>
     *
     * @throws \JsonException
     */
    private static function goldenFields(string $seal): array
    {
        $fields = self::golden()[$seal] ?? null;

        if (!is_array($fields)) {
            self::fail(sprintf('The golden seal has no `%s`.', $seal));
        }

        $typed = [];

        foreach ($fields as $key => $value) {
            $typed[(string) $key] = is_int($value) || is_string($value) || $value === null ? $value : self::fail('A golden field is not a scalar.');
        }

        return $typed;
    }

    /**
     * The golden members under the key given, as pairs of an entry id and an
     * HMAC.
     *
     * @param  'members'|'seal_2_members'  $field
     * @return list<array{0: string, 1: string}>
     *
     * @throws \JsonException
     */
    private static function goldenMembers(string $field): array
    {
        $members = self::golden()[$field] ?? null;
        $pairs   = [];

        foreach (is_array($members) ? $members : [] as $member) {
            if (!is_array($member) || !is_string($member[0] ?? null) || !is_string($member[1] ?? null)) {
                self::fail(sprintf('The golden `%s` holds a member that is not a pair of strings.', $field));
            }

            $pairs[] = [$member[0], $member[1]];
        }

        return $pairs !== [] ? $pairs : self::fail(sprintf('The golden seal has no `%s`.', $field));
    }

    /**
     * The golden string under the key given.
     *
     * @param  string  $field
     * @return string
     *
     * @throws \JsonException
     */
    private static function goldenString(string $field): string
    {
        $value = self::golden()[$field] ?? null;

        return is_string($value) ? $value : self::fail(sprintf('The golden seal has no `%s`.', $field));
    }

    /**
     * The golden seal vectors, decoded.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return array<array-key, mixed>
     *
     * @throws \JsonException
     */
    private static function golden(): array
    {
        $golden = json_decode((string) file_get_contents(self::GOLDEN), true, 512, JSON_THROW_ON_ERROR);

        return is_array($golden) ? $golden : self::fail('The golden seal vectors are not a map.');
    }
}
