<?php

declare(strict_types = 1);

namespace Tests\Unit\Integrity;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\JournalRow;

/**
 * Unit tests for a lifecycle journal row: a draft's canonical payload and its
 * digest, the signed fields that hold the digest and never the payload, each
 * malformed field refused naming it, the first row alone without a previous
 * HMAC, a stored row read in every form an engine returns and refused naming
 * the column, never its value, a payload that is not the canonical text of a
 * map refused, the insert row, and the golden rows reproduced.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JournalRow::class)]
final class JournalRowTest extends TestCase
{
    /** @var string The golden journal vectors. */
    private const string GOLDEN = __DIR__ . '/../../Fixtures/Integrity/journal-v1.json';

    /** @var string An HMAC, for a row after the first or a signed one. */
    private const string HMAC = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

    /** @var string Why a stored column is refused, by the column it names. */
    private const string STORED_MALFORMED = 'A stored journal row\'s `%s` is malformed.';

    /** @var list<string> Every column a stored row must have but its payload. */
    private const array COLUMNS = [
        'id', 'sequence', 'log_id', 'kind', 'operation_id', 'occurred_at', 'authority_type', 'authority_id', 'reason', 'external_reference',
        'seal_id', 'hold_id', 'payload_digest', 'previous_hmac', 'key_id', 'hmac',
    ];

    /**
     * A draft's payload is the canonical JSON text of its map, keys sorted, its
     * digest the SHA-256 of that text, and it holds no key id and no HMAC until
     * it is signed.
     *
     * @return void
     */
    public function testADraftCarriesItsCanonicalPayloadAndItsDigest(): void
    {
        $draft = self::draft(['payload' => ['z' => 1, 'a' => ['b' => true, 'a' => null]]]);

        self::assertSame('{"a":{"a":null,"b":true},"z":1}', $draft->payload);
        self::assertSame(hash('sha256', '{"a":{"a":null,"b":true},"z":1}'), $draft->payloadDigest);
        self::assertSame(['a' => ['a' => null, 'b' => true], 'z' => 1], $draft->payloadMap());
        self::assertSame('', $draft->keyId);
        self::assertSame('', $draft->hmac);
        self::assertTrue($draft->hasPayloadOfItsDigest());
    }

    /**
     * An empty payload is the empty map, `{}`, never the empty list.
     *
     * @return void
     */
    public function testAnEmptyPayloadIsTheEmptyMap(): void
    {
        $draft = self::draft(['payload' => []]);

        self::assertSame('{}', $draft->payload);
        self::assertSame(hash('sha256', '{}'), $draft->payloadDigest);
        self::assertSame([], $draft->payloadMap());
    }

    /**
     * A payload that is a list, or holds a value with no canonical form, is
     * refused as the draft is built.
     *
     * @return void
     */
    public function testAListPayloadIsMalformed(): void
    {
        foreach (['a list' => ['a', 'b'], 'a float' => ['ratio' => 1.5], 'an object' => ['at' => new \DateTimeImmutable]] as $what => $payload) {
            try {
                self::draft(['payload' => $payload]);
                self::fail(sprintf('Expected %s to be refused.', $what));
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('A journal row\'s `payload` must be a map with a canonical encoding.', $exception->getMessage(), $what);
                self::assertNull($exception->getPrevious(), $what);
            }
        }
    }

    /**
     * The signed fields are every column but the HMAC and the payload, whose
     * digest stands for it, so the chain verifies from the small columns.
     *
     * @return void
     */
    public function testTheSignedFieldsHoldThePayloadDigestNotThePayload(): void
    {
        $row    = self::draft()->withSignature('k2026', self::HMAC);
        $fields = $row->signedFields();

        self::assertSame([
            'v', 'id', 'sequence', 'log_id', 'kind', 'operation_id', 'occurred_at', 'authority_type', 'authority_id', 'reason',
            'external_reference', 'seal_id', 'hold_id', 'payload_digest', 'previous_hmac', 'key_id',
        ], array_keys($fields));
        self::assertSame(1, $fields['v']);
        self::assertSame($row->payloadDigest, $fields['payload_digest']);
        self::assertSame('k2026', $fields['key_id']);
        self::assertNotContains($row->payload, $fields);
        self::assertSame(hash('sha256', CanonicalEncoder::encode($fields)), $row->digest());
    }

    /**
     * The digest moves with every signed field, the key id included, and not
     * with the HMAC.
     *
     * @return void
     */
    public function testTheDigestCoversTheKeyIdButNotTheHmac(): void
    {
        $signed = self::draft()->withSignature('k2026', self::HMAC);

        self::assertSame($signed->digest(), self::draft()->withSignature('k2026', str_repeat('c', 64))->digest());
        self::assertNotSame($signed->digest(), self::draft()->withSignature('k2025', self::HMAC)->digest());
        self::assertNotSame($signed->digest(), self::draft(['reason' => 'case.other'])->withSignature('k2026', self::HMAC)->digest());
    }

    /**
     * Rows of `[field, malformed value, message]`: every field the draft
     * checks.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: string, 1: mixed, 2: string}>
     */
    public static function provideMalformedFields(): iterable
    {
        $row      = 'A journal row\'s ';
        $uuid     = ' must be a lower-case UUID.';
        $text     = ' must be null or 1 to 191 characters, with no control characters.';
        $logId    = $row . '`log_id` must be 1 to 64 letters, digits, dots, underscores or hyphens, starting with a letter or a digit.';
        $reason   = $row . '`reason` must be null or 1 to 64 lower-case letters, digits, dots, underscores, colons or hyphens.';
        $previous = $row . '`previous_hmac` must be null on the first row and 64 lower-case hexadecimal characters on every other.';
        $time     = $row . '`occurred_at` must be ISO-8601 UTC with microseconds.';
        $holder   = $row . '`authority_id`' . $text . ' It is set exactly when the authority type is.';

        yield from [
            'an upper-case id'              => ['id', '01932B4E-B000-7000-8000-000000000001', $row . '`id`' . $uuid],
            'a sequence of 0'               => ['sequence', 0, $row . '`sequence` must be at least 1.'],
            'a log id with a slash'         => ['log_id', 'app/eu', $logId],
            'an operation id that is no id' => ['operation_id', 'op-1', $row . '`operation_id`' . $uuid],
            'a time with an offset'         => ['occurred_at', '2026-10-31T23:42:00.000000+00:00', $time],
            'an empty authority type'       => ['authority', ['', '7'], $row . '`authority_type`' . $text],
            'an authority type too long'    => ['authority', [str_repeat('a', 192), '7'], $row . '`authority_type`' . $text],
            'an authority id with a NUL'    => ['authority', ['App\Models\User', "7\0"], $holder],
            'an upper-case reason'          => ['reason', 'Case.Review', $reason],
            'a reason of 65 characters'     => ['reason', str_repeat('a', 65), $reason],
            'an empty external reference'   => ['external_reference', '', $row . '`external_reference`' . $text],
            'a reference with a new line'   => ['external_reference', "CASE\n1", $row . '`external_reference`' . $text],
            'a seal id that is no id'       => ['seal_id', 'seal-1', $row . '`seal_id` must be null or a lower-case UUID.'],
            'a hold id that is upper case'  => ['hold_id', '01932B4E-D000-7000-8000-000000000001', $row . '`hold_id` must be null or a lower-case UUID.'],
            'a short previous HMAC'         => ['previous_hmac', str_repeat('a', 63), $previous],
        ];
    }

    /**
     * Each malformed field is refused with one sentence naming the field.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $field
     * @param  mixed  $value
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMalformedFields')]
    public function testRefusesEachMalformedField(string $field, mixed $value, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        self::draft([$field => $value, 'sequence' => $field === 'previous_hmac' ? 2 : ($field === 'sequence' ? $value : 1)]);
    }

    /**
     * A signature is refused unless it names a key id and an HMAC of 64
     * lower-case hex.
     *
     * @return void
     */
    public function testRefusesAMalformedSignature(): void
    {
        $keyId    = 'A journal row\'s `key_id` must be 1 to 32 letters, digits, dots, underscores or hyphens, starting with a letter or a digit.';
        $hmac     = 'A journal row\'s `hmac` must be 64 lower-case hexadecimal characters.';
        $refusals = [
            'an empty key id'    => ['', self::HMAC, $keyId],
            'a key id too long'  => [str_repeat('k', 33), self::HMAC, $keyId],
            'an empty HMAC'      => ['k2026', '', $hmac],
            'an upper-case HMAC' => ['k2026', strtoupper(self::HMAC), $hmac],
        ];

        foreach ($refusals as $what => [$keyId, $hmac, $message]) {
            try {
                self::draft()->withSignature($keyId, $hmac);
                self::fail(sprintf('Expected %s to be refused.', $what));
            } catch (\InvalidArgumentException $exception) {
                self::assertSame($message, $exception->getMessage(), $what);
            }
        }
    }

    /**
     * Only the first row has no previous HMAC: a first row with one, and a
     * later row without one, are refused; an authority and a hold are each
     * optional.
     *
     * @return void
     */
    public function testTheFirstRowHasNoPreviousAndEveryOtherHasOne(): void
    {
        $message = 'A journal row\'s `previous_hmac` must be null on the first row and 64 lower-case hexadecimal characters on every other.';

        self::assertNull(self::draft()->previousHmac);
        self::assertSame(self::HMAC, self::draft(['sequence' => 2, 'previous_hmac' => self::HMAC])->previousHmac);
        self::assertSame(PHP_INT_MAX, self::draft(['sequence' => PHP_INT_MAX, 'previous_hmac' => self::HMAC])->sequence);

        foreach ([[1, self::HMAC], [2, null]] as [$sequence, $previous]) {
            try {
                self::draft(['sequence' => $sequence, 'previous_hmac' => $previous]);
                self::fail(sprintf('Expected row %d to be refused.', $sequence));
            } catch (\InvalidArgumentException $exception) {
                self::assertSame($message, $exception->getMessage());
            }
        }

        $bare = self::draft(['kind' => JournalKind::PRUNE_RUN, 'authority' => null, 'reason' => null, 'external_reference' => null, 'hold_id' => null]);

        self::assertNull($bare->authorityType);
        self::assertNull($bare->authorityId);
        self::assertNull($bare->holdId);
        self::assertSame(JournalKind::PRUNE_RUN, $bare->kind);
    }

    /**
     * Rows of `[kind]`: the kinds an owner's keys journal, each asked for by an
     * operator.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind}>
     */
    public static function providePrivacyKinds(): iterable
    {
        yield from [
            'an erasure'           => [JournalKind::ERASURE],
            'a reinstatement'      => [JournalKind::REINSTATE],
            'a rewrap batch'       => [JournalKind::REWRAP],
            'a reconciled restore' => [JournalKind::RESTORE_RECONCILED],
        ];
    }

    /**
     * A privacy kind's row holds the authority that asked for it, its reason
     * and its reference, and no hold, through its draft, its signed fields, its
     * insert row and the stored row read back.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind  $kind
     * @return void
     */
    #[DataProvider('providePrivacyKinds')]
    public function testEachPrivacyKindKeepsItsAuthorityThroughItsRow(JournalKind $kind): void
    {
        $signed = self::draft(['kind' => $kind, 'hold_id' => null, 'payload' => ['owner_fingerprint' => str_repeat('c', 64)]])->withSignature('k2026', self::HMAC);
        $stored = $signed->toRow();
        $read   = JournalRow::fromRow($stored, true);

        self::assertTrue($kind->carriesAuthority());
        self::assertSame($kind->value, $signed->signedFields()['kind']);
        self::assertSame([$kind->value, 'App\Models\User', '7', 'case.review', 'CASE-2026-001', null], [
            $stored['kind'], $stored['authority_type'], $stored['authority_id'], $stored['reason'], $stored['external_reference'], $stored['hold_id'],
        ]);
        self::assertSame($kind, $read->kind);
        self::assertSame(['App\Models\User', '7'], [$read->authorityType, $read->authorityId]);
        self::assertSame($signed->signedFields(), $read->signedFields());
        self::assertSame($signed->payload, $read->payload);
    }

    /**
     * A privacy kind's row is refused with half an authority: an empty
     * authority type when drafted, and a stored type without its id or an id
     * without its type, each naming the column and never its value. That every
     * privacy kind must carry a whole authority is the journal's check, made
     * from the kind's `carriesAuthority()`.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind  $kind
     * @return void
     */
    #[DataProvider('providePrivacyKinds')]
    public function testEachPrivacyKindIsRefusedWithoutAWholeAuthority(JournalKind $kind): void
    {
        try {
            self::draft(['kind' => $kind, 'authority' => ['', '7']]);
            self::fail(sprintf('Expected the `%s` draft to be refused.', $kind->value));
        } catch (\InvalidArgumentException $exception) {
            self::assertStringStartsWith('A journal row\'s `authority_type` must be null', $exception->getMessage());
        }

        $stored = self::draft(['kind' => $kind])->withSignature('k2026', self::HMAC)->toRow();

        foreach (['authority_id' => [...$stored, 'authority_id' => null], 'authority_type' => [...$stored, 'authority_type' => null]] as $missing => $row) {
            try {
                JournalRow::fromRow($row, true);
                self::fail(sprintf('Expected the `%s` row without its `%s` to be refused.', $kind->value, $missing));
            } catch (\UnexpectedValueException $exception) {
                self::assertSame('A stored journal row\'s `authority_id` is malformed.', $exception->getMessage(), $missing);
                self::assertStringNotContainsString('App\Models\User', $exception->getMessage());
            }
        }
    }

    /**
     * Rows of `[column, stored value, what it reads as]`: the forms the engines
     * return, integers as their decimal strings and times with as many
     * fractional digits as an engine keeps.
     *
     * @return iterable<string, array{0: string, 1: int|string, 2: int|string}>
     */
    public static function provideEngineForms(): iterable
    {
        yield from [
            'a sequence as an integer'     => ['sequence', 1, 1],
            'a sequence as its digits'     => ['sequence', '1', 1],
            'a time with six digits'       => ['occurred_at', '2026-10-31 23:42:00.000000', '2026-10-31T23:42:00.000000Z'],
            'a time with no fraction'      => ['occurred_at', '2026-10-31 23:42:00', '2026-10-31T23:42:00.000000Z'],
            'a time with one digit'        => ['occurred_at', '2026-10-31 23:42:00.5', '2026-10-31T23:42:00.500000Z'],
            'a time with its microseconds' => ['occurred_at', '2026-10-31 23:42:00.000001', '2026-10-31T23:42:00.000001Z'],
        ];
    }

    /**
     * A stored row is read in every form an engine returns, and reads back as
     * the row it was written from.
     *
     * @param  string  $column
     * @param  int|string  $stored
     * @param  int|string  $read
     * @return void
     */
    #[DataProvider('provideEngineForms')]
    public function testFromRowReadsEveryEngineForm(string $column, int|string $stored, int|string $read): void
    {
        $row = JournalRow::fromRow([...self::storedRow(), $column => $stored], true);

        self::assertSame($read, $column === 'sequence' ? $row->sequence : $row->occurredAt);
        self::assertSame(self::signed()->signedFields(), $column === 'sequence' ? $row->signedFields() : self::signed()->signedFields());
        self::assertSame(self::signed()->payload, $row->payload);
    }

    /**
     * A stored row reads back as the row it was written from, its payload kept
     * only when asked for.
     *
     * @return void
     */
    public function testFromRowReadsTheStoredRow(): void
    {
        $signed  = self::signed();
        $read    = JournalRow::fromRow([...self::storedRow(), 'extra' => 'ignored'], true);
        $without = JournalRow::fromRow(self::storedRow(), false);

        self::assertSame($signed->signedFields(), $read->signedFields());
        self::assertSame($signed->hmac, $read->hmac);
        self::assertSame($signed->payload, $read->payload);
        self::assertNull($without->payload);
        self::assertNull($without->payloadMap());
        self::assertTrue($without->hasPayloadOfItsDigest());
        self::assertSame($signed->digest(), $without->digest());
    }

    /**
     * Rows of `[column]`: every column a stored row must have but its payload.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideColumns(): iterable
    {
        foreach (self::COLUMNS as $column) {
            yield $column => [$column];
        }
    }

    /**
     * A stored row missing any column is refused naming it; a column holding
     * `null` is present, and one missing is never read as `null`.
     *
     * @param  string  $column
     * @return void
     */
    #[DataProvider('provideColumns')]
    public function testFromRowRefusesAMissingColumnNamingIt(string $column): void
    {
        $stored = self::storedRow();

        unset($stored[$column]);

        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage(sprintf('A stored journal row has no `%s` column; every column is required to read it.', $column));

        JournalRow::fromRow($stored, false);
    }

    /**
     * A row read without its payload needs no payload column; one read with it
     * does.
     *
     * @return void
     */
    public function testThePayloadColumnIsReadOnlyWhenAsked(): void
    {
        $stored = self::storedRow();

        unset($stored['payload']);

        self::assertNull(JournalRow::fromRow($stored, false)->payload);

        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('A stored journal row has no `payload` column; every column is required to read it.');

        JournalRow::fromRow($stored, true);
    }

    /**
     * A stored row that breaks the first row's rule is read, not refused: a
     * first row with a previous HMAC, or a later one without, is evidence the
     * chain reports as a gap.
     *
     * @return void
     */
    public function testFromRowLeavesTheFirstRowsRuleToTheChain(): void
    {
        $linked   = JournalRow::fromRow([...self::storedRow(), 'previous_hmac' => self::HMAC], true);
        $unlinked = JournalRow::fromRow([...self::storedRow(), 'sequence' => 2], true);

        self::assertSame(1, $linked->sequence);
        self::assertSame(self::HMAC, $linked->previousHmac);
        self::assertSame(2, $unlinked->sequence);
        self::assertNull($unlinked->previousHmac);
    }

    /**
     * Rows of `[column, malformed stored value]`: a wrong type, a malformed
     * form, and a value the row refuses, each holding the planted text where it
     * can.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: string, 1: mixed}>
     */
    public static function provideMalformedStoredValues(): iterable
    {
        yield from [
            'an id that is null'               => ['id', null],
            'an id that is no UUID'            => ['id', 's3cr3t'],
            'a sequence that is no integer'    => ['sequence', 's3cr3t'],
            'a sequence of 0'                  => ['sequence', '0'],
            'a sequence padded with a zero'    => ['sequence', '01'],
            'a log id outside the grammar'     => ['log_id', 's3cr3t/log'],
            'a kind that is no kind'           => ['kind', 's3cr3t'],
            'a kind that is no string'         => ['kind', 42],
            'an operation id that is no UUID'  => ['operation_id', 's3cr3t'],
            'a time that is no time'           => ['occurred_at', 's3cr3t'],
            'a time in the package form'       => ['occurred_at', '2026-10-31T23:42:00.000000Z'],
            'an authority type with a NUL'     => ['authority_type', "s3cr3t\0"],
            'an authority id without its type' => ['authority_type', null],
            'an authority type without its id' => ['authority_id', null],
            'a reason outside the grammar'     => ['reason', 'S3CR3T'],
            'a reference that is no string'    => ['external_reference', ['s3cr3t']],
            'a seal id that is no UUID'        => ['seal_id', 's3cr3t'],
            'a hold id that is no UUID'        => ['hold_id', 's3cr3t'],
            'a payload digest that is upper'   => ['payload_digest', 'S3CR3T' . str_repeat('A', 58)],
            'a previous HMAC that is short'    => ['previous_hmac', str_repeat('a', 63)],
            'a key id outside the grammar'     => ['key_id', 's3cr3t key'],
            'an empty key id'                  => ['key_id', ''],
            'an empty HMAC'                    => ['hmac', ''],
            'an HMAC that is upper'            => ['hmac', 'S3CR3T' . str_repeat('A', 58)],
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
     */
    #[DataProvider('provideMalformedStoredValues')]
    public function testFromRowNeverQuotesAValue(string $column, mixed $value): void
    {
        $expected = match ($column) {
            'authority_type' => $value === null ? 'authority_id' : 'authority_type',
            default          => $column,
        };

        try {
            JournalRow::fromRow([...self::storedRow(), $column => $value], true);
            self::fail('Expected the stored row to be refused.');
        } catch (\UnexpectedValueException $exception) {
            self::assertSame(sprintf(self::STORED_MALFORMED, $expected), $exception->getMessage());
            self::assertStringNotContainsStringIgnoringCase('s3cr3t', $exception->getMessage());
            self::assertNull($exception->getPrevious());
        }
    }

    /**
     * Rows of `[stored payload]`: text that is valid JSON of a map but not its
     * canonical encoding, or not JSON of a map at all.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideNonCanonicalPayloads(): iterable
    {
        yield from [
            'keys out of order'  => ['{"z":1,"a":2}'],
            'a space'            => ['{"a": 1}'],
            'an escaped slash'   => ['{"a":"x\/y"}'],
            'an escaped unicode' => ['{"a":"' . chr(92) . 'u00e9"}'],
            'a float'            => ['{"a":1.5}'],
            'an integer too big' => ['{"a":99999999999999999999}'],
            'a list'             => ['["a"]'],
            'the empty list'     => ['[]'],
            'a string'           => ['"s3cr3t"'],
            'null'               => ['null'],
            'not JSON'           => ['{s3cr3t'],
            'too deep'           => [str_repeat('{"a":', 64) . '1' . str_repeat('}', 64)],
            'a trailing newline' => ["{\"a\":1}\n"],
        ];
    }

    /**
     * A payload that is not the canonical JSON text of a map is malformed, so a
     * payload rewritten in another form is never read as the one signed.
     *
     * @param  string  $payload
     * @return void
     */
    #[DataProvider('provideNonCanonicalPayloads')]
    public function testANonCanonicalPayloadIsMalformed(string $payload): void
    {
        try {
            JournalRow::fromRow([...self::storedRow(), 'payload' => $payload], true);
            self::fail('Expected the payload to be refused.');
        } catch (\UnexpectedValueException $exception) {
            self::assertSame(sprintf(self::STORED_MALFORMED, 'payload'), $exception->getMessage());
            self::assertNull($exception->getPrevious());
        }

        self::assertNull(JournalRow::fromRow([...self::storedRow(), 'payload' => $payload], false)->payload);
    }

    /**
     * A canonical payload that is not the one its digest was taken of reads,
     * and says so, for the chain to report.
     *
     * @return void
     */
    public function testAnEditedCanonicalPayloadIsNotOfItsDigest(): void
    {
        $edited = JournalRow::fromRow([...self::storedRow(), 'payload' => '{"hold_id":"01932b4e-d000-7000-8000-000000000002"}'], true);

        self::assertFalse($edited->hasPayloadOfItsDigest());
        self::assertSame(['hold_id' => '01932b4e-d000-7000-8000-000000000002'], $edited->payloadMap());
    }

    /**
     * The insert row holds every column in table order, the time in the form
     * the database stores.
     *
     * @return void
     */
    public function testToRowIsTheInsertRow(): void
    {
        $signed = self::signed();

        self::assertSame([
            'id'                 => '01932b4e-b000-7000-8000-000000000001',
            'sequence'           => 1,
            'log_id'             => 'app-eu-1',
            'kind'               => 'hold',
            'operation_id'       => '01932b4e-c000-7000-8000-000000000001',
            'occurred_at'        => '2026-10-31 23:42:00.000000',
            'authority_type'     => 'App\Models\User',
            'authority_id'       => '7',
            'reason'             => 'case.review',
            'external_reference' => 'CASE-2026-001',
            'seal_id'            => null,
            'hold_id'            => '01932b4e-d000-7000-8000-000000000001',
            'payload'            => $signed->payload,
            'payload_digest'     => $signed->payloadDigest,
            'previous_hmac'      => null,
            'key_id'             => 'k2026',
            'hmac'               => self::HMAC,
        ], $signed->toRow());
    }

    /**
     * An unsigned draft, and a row read without its payload, are never stored.
     *
     * @return void
     */
    public function testAnUnsignedOrPartialRowIsNeverStored(): void
    {
        foreach (['an unsigned draft' => self::draft(), 'a row without its payload' => JournalRow::fromRow(self::storedRow(), false)] as $what => $row) {
            try {
                $row->toRow();
                self::fail(sprintf('Expected %s to be refused.', $what));
            } catch (\LogicException $exception) {
                self::assertSame('Only a signed journal row that holds its payload is stored.', $exception->getMessage(), $what);
            }
        }
    }

    /**
     * The golden rows' drafts reproduce the golden payload texts and digests,
     * signed fields, canonical forms and digests, byte for byte.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheGoldenRowsReproduce(): void
    {
        $rows = self::goldenRows();

        self::assertCount(2, $rows);

        foreach ($rows as $index => $vector) {
            $input = $vector['input'];

            self::assertIsArray($input);

            $row = self::draft([...$input, 'log_id' => 'app-eu-1', 'previous_hmac' => $vector['previous_hmac']])->withSignature('k2026', self::text($vector, 'hmac'));

            self::assertSame($vector['payload'], $row->payload, (string) $index);
            self::assertSame($vector['payload_digest'], $row->payloadDigest, (string) $index);
            self::assertSame($vector['signed_fields'], $row->signedFields(), (string) $index);
            self::assertSame($vector['canonical'], CanonicalEncoder::encode($row->signedFields()), (string) $index);
            self::assertSame($vector['digest'], $row->digest(), (string) $index);
            self::assertSame($vector['signed_fields'], JournalRow::fromRow($row->toRow(), true)->signedFields(), (string) $index);
        }

        self::assertSame($rows[0]['hmac'], $rows[1]['previous_hmac']);
    }

    /**
     * The golden first row, drafted with the overrides given: a hold, the first
     * row of the chain. A field of the wrong type fails the test rather than
     * the row.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $overrides
     * @return \SineMacula\Laravel\AuditLog\Integrity\JournalRow
     *
     * @throws \InvalidArgumentException
     */
    private static function draft(array $overrides = []): JournalRow
    {
        $fields = [
            'id'                 => '01932b4e-b000-7000-8000-000000000001',
            'sequence'           => 1,
            'log_id'             => 'app-eu-1',
            'kind'               => JournalKind::HOLD,
            'operation_id'       => '01932b4e-c000-7000-8000-000000000001',
            'occurred_at'        => '2026-10-31T23:42:00.000000Z',
            'authority'          => ['App\Models\User', '7'],
            'reason'             => 'case.review',
            'external_reference' => 'CASE-2026-001',
            'seal_id'            => null,
            'hold_id'            => '01932b4e-d000-7000-8000-000000000001',
            'payload'            => ['hold_id' => '01932b4e-d000-7000-8000-000000000001'],
            'previous_hmac'      => null,
            ...$overrides,
        ];

        $kind      = $fields['kind'];
        $authority = $fields['authority'];
        $payload   = $fields['payload'];
        $sequence  = $fields['sequence'];

        return JournalRow::draft(
            self::text($fields, 'id'),
            is_int($sequence) ? $sequence : self::fail('The sequence is not an integer.'),
            self::text($fields, 'log_id'),
            $kind instanceof JournalKind ? $kind : JournalKind::from(self::text($fields, 'kind')),
            self::text($fields, 'operation_id'),
            self::text($fields, 'occurred_at'),
            $authority === null ? null : [self::text($authority, 0), self::text($authority, 1)],
            self::optionalText($fields, 'reason'),
            self::optionalText($fields, 'external_reference'),
            self::optionalText($fields, 'seal_id'),
            self::optionalText($fields, 'hold_id'),
            is_array($payload) ? $payload : self::fail('The payload is not an array.'),
            self::optionalText($fields, 'previous_hmac'),
        );
    }

    /**
     * The string under the key, failing the test otherwise.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $fields
     * @param  int|string  $key
     * @return string
     */
    private static function text(mixed $fields, int|string $key): string
    {
        $value = is_array($fields) ? $fields[$key] ?? null : null;

        return is_string($value) ? $value : self::fail(sprintf('`%s` is not a string.', $key));
    }

    /**
     * The string under the key, or `null` when it holds `null`, failing the
     * test otherwise.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $fields
     * @param  string  $key
     * @return ?string
     */
    private static function optionalText(array $fields, string $key): ?string
    {
        return $fields[$key] === null ? null : self::text($fields, $key);
    }

    /**
     * The golden first row, drafted and given a signature.
     *
     * @return \SineMacula\Laravel\AuditLog\Integrity\JournalRow
     */
    private static function signed(): JournalRow
    {
        return self::draft()->withSignature('k2026', self::HMAC);
    }

    /**
     * The signed first row as an engine returns it.
     *
     * @return array<string, int|string|null>
     */
    private static function storedRow(): array
    {
        return self::signed()->toRow();
    }

    /**
     * The golden journal's rows, decoded.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return list<array<array-key, mixed>>
     *
     * @throws \JsonException
     */
    private static function goldenRows(): array
    {
        $golden = json_decode((string) file_get_contents(self::GOLDEN), true, 512, JSON_THROW_ON_ERROR);
        $rows   = is_array($golden) ? $golden['rows'] ?? null : null;

        if (!is_array($rows) || !array_is_list($rows)) {
            self::fail('The golden journal has no rows.');
        }

        return array_map(static fn (mixed $row): array => is_array($row) ? $row : self::fail('A golden row is not a map.'), $rows);
    }
}
