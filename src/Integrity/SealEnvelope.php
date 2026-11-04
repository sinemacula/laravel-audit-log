<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

use SineMacula\Laravel\AuditLog\Config\IntegerSetting;
use SineMacula\Laravel\AuditLog\Support\StoredTime;

/**
 * The immutable fields of one seal and their canonical digest, under seal
 * version 1.
 *
 * The digest is SHA-256 over the canonical encoding of all sixteen fields, so
 * the log, the place in the chain, the link to the seal before, the members,
 * the times, how the seal is signed and the lifecycle journal's head it commits
 * to are all covered, and none can change without changing it. The members
 * digest is SHA-256 over the canonical encoding of the members' entry ids and
 * HMACs, sorted bytewise by entry id, so it never depends on the order rows
 * were read in. The journal's head is its last row's sequence and HMAC, both
 * `null` when the journal had no row, so the journal is anchored exactly as the
 * entries are.
 *
 * Every field is checked as it is built, and a stored seal is read through
 * `fromRow()`, which refuses a missing or malformed column with an
 * `UnexpectedValueException` naming the column and never its value. Neither
 * enforces the genesis rule nor the pairing of the previous fields or of the
 * journal's: a stored seal that breaks them is evidence that verification must
 * report, not a row it may refuse to load.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SealEnvelope
{
    /** @var int The version of the envelope every seal is built under. */
    public const int VERSION = 1;

    /** @var int The algorithm version every new seal is signed under. */
    public const int ALGORITHM_VERSION = 1;

    /** @var list<int> The algorithm versions this release verifies. */
    public const array SUPPORTED_ALGORITHM_VERSIONS = [1];

    /** @var string How every seal is signed: HMAC-SHA256 under the seal key. */
    public const string SIGNER = 'hmac';

    /** @var int Most members one seal holds. */
    public const int MAX_MEMBERS = 50000;

    /** @var string A log id: 1 to 64 path-safe characters, starting with a letter or a digit. */
    public const string LOG_ID_PATTERN = '/\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\z/';

    /** @var string A UUID as every engine returns it. */
    public const string UUID_PATTERN = '/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/';

    /** @var string SHA-256 or HMAC-SHA256 as lower-case hex. */
    public const string DIGEST_PATTERN = '/\A[0-9a-f]{64}\z/';

    /** @var array<string, string> The pattern each string field must match, by its column. */
    private const array PATTERNS = [
        'log_id'          => self::LOG_ID_PATTERN,
        'id'              => self::UUID_PATTERN,
        'previous_id'     => self::UUID_PATTERN,
        'previous_digest' => self::DIGEST_PATTERN,
        'members_digest'  => self::DIGEST_PATTERN,
        'signer'          => '/\A' . self::SIGNER . '\z/',
        'key_id'          => IntegrityKey::ID_PATTERN,
        'journal_head'    => self::DIGEST_PATTERN,
    ];

    /** @var list<string> The fields that may be `null`: the link to the seal before, which genesis has not, and the journal's head, which an empty journal has not. */
    private const array NULLABLE = ['previous_id', 'previous_digest', 'journal_sequence', 'journal_head'];

    /** @var list<string> The fields that are instants. */
    private const array TIMES = ['first_recorded_at', 'last_recorded_at', 'sealed_at'];

    /** @var string What a refused UUID field must be, after its name. */
    private const string UUID = ' must be a lower-case UUID, the form every engine stores and returns.';

    /** @var string What a refused digest field must be, after its name. */
    private const string DIGEST = ' must be 64 lower-case hexadecimal characters.';

    /** @var string What a refused time field must be, after its name. */
    private const string TIME = ' must be ISO-8601 UTC with microseconds.';

    /** @var array<string, string> Why each field is refused, by its column. */
    private const array MESSAGES = [
        'log_id'            => 'A seal\'s `log_id` must be 1 to 64 letters, digits, dots, underscores or hyphens, starting with a letter or a digit.',
        'id'                => 'A seal\'s `id`' . self::UUID,
        'sequence'          => 'A seal\'s `sequence` must be at least 1.',
        'previous_id'       => 'A seal\'s `previous_id` must be null or a lower-case UUID.',
        'previous_digest'   => 'A seal\'s `previous_digest` must be null or 64 lower-case hexadecimal characters.',
        'member_count'      => 'A seal\'s `member_count` must be from 1 to 50000.',
        'members_digest'    => 'A seal\'s `members_digest`' . self::DIGEST,
        'first_recorded_at' => 'A seal\'s `first_recorded_at`' . self::TIME,
        'last_recorded_at'  => 'A seal\'s `last_recorded_at` must be ISO-8601 UTC with microseconds, and not before its `first_recorded_at`.',
        'sealed_at'         => 'A seal\'s `sealed_at`' . self::TIME,
        'signer'            => 'A seal\'s `signer` must be `hmac`.',
        'key_id'            => 'A seal\'s `key_id` must be 1 to 32 letters, digits, dots, underscores or hyphens, starting with a letter or a digit.',
        'algorithm_version' => 'A seal\'s `algorithm_version` is not supported by this release.',
        'seal_digest'       => 'A seal\'s `seal_digest`' . self::DIGEST,
        'signature'         => 'A seal\'s `signature`' . self::DIGEST,
        'journal_sequence'  => 'A seal\'s `journal_sequence` must be null or at least 1.',
        'journal_head'      => 'A seal\'s `journal_head` must be null or 64 lower-case hexadecimal characters.',
    ];

    /** @var string Why a stored column is refused, by the column it names. */
    private const string STORED_MALFORMED = 'A stored seal\'s `%s` is malformed.';

    /**
     * Constructor.
     *
     * @param  string  $logId
     * @param  string  $id
     * @param  int  $sequence
     * @param  ?string  $previousId
     * @param  ?string  $previousDigest
     * @param  int  $memberCount
     * @param  string  $membersDigest
     * @param  string  $firstRecordedAt
     * @param  string  $lastRecordedAt
     * @param  string  $sealedAt
     * @param  string  $keyId
     * @param  int  $algorithmVersion
     * @param  string  $signer
     * @param  ?int  $journalSequence
     * @param  ?string  $journalHead
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The log the seal belongs to: one chain never mixes two. */
        public string $logId,

        /** The seal's id, a lower-case UUID. */
        public string $id,

        /** The seal's place in the chain: 1 at genesis, then one more than the seal before. */
        public int $sequence,

        /** The id of the seal before, or `null` at genesis. */
        public ?string $previousId,

        /** The digest of the seal before, or `null` at genesis. */
        public ?string $previousDigest,

        /** How many entries the seal holds, from 1 to `MAX_MEMBERS`. */
        public int $memberCount,

        /** SHA-256 over the canonical, sorted list of the members' entry ids and HMACs. */
        public string $membersDigest,

        /** When the earliest member was recorded, ISO-8601 UTC with microseconds. */
        public string $firstRecordedAt,

        /** When the latest member was recorded, ISO-8601 UTC with microseconds; never before the earliest. */
        public string $lastRecordedAt,

        /** When the seal was made, ISO-8601 UTC with microseconds. */
        public string $sealedAt,

        /** The id of the ring key whose seal key signs the seal. */
        public string $keyId,

        /** The algorithm version the seal is signed under. */
        public int $algorithmVersion = self::ALGORITHM_VERSION,

        /** How the seal is signed. */
        public string $signer = self::SIGNER,

        /** The sequence of the lifecycle journal's last row when the seal was made, or `null` when it had none. */
        public ?int $journalSequence = null,

        /** The HMAC of the lifecycle journal's last row when the seal was made, or `null` when it had none. */
        public ?string $journalHead = null,
    ) {
        $fields = $this->toArray();

        unset($fields['v']);

        $malformed = self::malformedField($fields);

        if ($malformed !== null) {
            throw new \InvalidArgumentException(self::MESSAGES[$malformed]);
        }
    }

    /**
     * The members digest: SHA-256, in hex, over the canonical encoding of the
     * members' entry ids and HMACs, sorted bytewise by entry id. An empty list,
     * an entry given twice, an id that is not a lower-case UUID and an HMAC
     * that is not 64 lower-case hex are refused.
     *
     * @param  list<array{0: string, 1: string}>  $members
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public static function membersDigest(array $members): string
    {
        if ($members === []) {
            throw new \InvalidArgumentException('A seal must have at least one member.');
        }

        $sorted = [];

        foreach ($members as [$entryId, $hmac]) {
            self::checkMember($entryId, $hmac);

            $sorted[] = [$entryId, $hmac];
        }

        if (count(array_unique(array_column($sorted, 0))) !== count($sorted)) {
            throw new \InvalidArgumentException('A seal\'s members must each be a different entry.');
        }

        usort($sorted, static fn (array $left, array $right): int => strcmp($left[0], $right[0]));

        return hash('sha256', CanonicalEncoder::encode($sorted));
    }

    /**
     * The envelope of a decoded stored seal: each of the thirteen envelope
     * columns is required, and the journal's two are read as `null` when they
     * are not given; times are read in any form an engine returns and integers
     * as an integer or its decimal string. A missing or malformed column is
     * refused naming the column, never quoting its value; the digest and the
     * signature are the caller's to read.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $stored
     * @return self
     *
     * @throws \UnexpectedValueException
     */
    public static function fromRow(array $stored): self
    {
        $fields = [
            'log_id'            => self::storedText($stored, 'log_id'),
            'id'                => self::storedText($stored, 'id'),
            'sequence'          => self::storedInteger($stored, 'sequence'),
            'previous_id'       => self::storedOptionalText($stored, 'previous_id'),
            'previous_digest'   => self::storedOptionalText($stored, 'previous_digest'),
            'member_count'      => self::storedInteger($stored, 'member_count'),
            'members_digest'    => self::storedText($stored, 'members_digest'),
            'first_recorded_at' => self::storedTime($stored, 'first_recorded_at'),
            'last_recorded_at'  => self::storedTime($stored, 'last_recorded_at'),
            'sealed_at'         => self::storedTime($stored, 'sealed_at'),
            'signer'            => self::storedText($stored, 'signer'),
            'key_id'            => self::storedText($stored, 'key_id'),
            'algorithm_version' => self::storedInteger($stored, 'algorithm_version'),
            'journal_sequence'  => array_key_exists('journal_sequence', $stored) && $stored['journal_sequence'] !== null ? self::storedInteger($stored, 'journal_sequence') : null,
            'journal_head'      => array_key_exists('journal_head', $stored) ? self::storedOptionalText($stored, 'journal_head') : null,
        ];

        $malformed = self::malformedField($fields);

        if ($malformed !== null) {
            throw new \UnexpectedValueException(sprintf(self::STORED_MALFORMED, $malformed));
        }

        return new self(
            $fields['log_id'],
            $fields['id'],
            $fields['sequence'],
            $fields['previous_id'],
            $fields['previous_digest'],
            $fields['member_count'],
            $fields['members_digest'],
            $fields['first_recorded_at'],
            $fields['last_recorded_at'],
            $fields['sealed_at'],
            $fields['key_id'],
            $fields['algorithm_version'],
            $fields['signer'],
            $fields['journal_sequence'],
            $fields['journal_head'],
        );
    }

    /**
     * The sixteen fields the digest covers, each under its canonical key. The
     * order is irrelevant: the canonical encoding sorts the keys.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return array{v: int, log_id: string, id: string, sequence: int, previous_id: ?string, previous_digest: ?string, member_count: int, members_digest: string, first_recorded_at: string, last_recorded_at: string, sealed_at: string, signer: string, key_id: string, algorithm_version: int, journal_sequence: ?int, journal_head: ?string}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public function toArray(): array
    {
        return [
            'v'                 => self::VERSION,
            'log_id'            => $this->logId,
            'id'                => $this->id,
            'sequence'          => $this->sequence,
            'previous_id'       => $this->previousId,
            'previous_digest'   => $this->previousDigest,
            'member_count'      => $this->memberCount,
            'members_digest'    => $this->membersDigest,
            'first_recorded_at' => $this->firstRecordedAt,
            'last_recorded_at'  => $this->lastRecordedAt,
            'sealed_at'         => $this->sealedAt,
            'signer'            => $this->signer,
            'key_id'            => $this->keyId,
            'algorithm_version' => $this->algorithmVersion,
            'journal_sequence'  => $this->journalSequence,
            'journal_head'      => $this->journalHead,
        ];
    }

    /**
     * The seal digest: SHA-256, in hex, over the canonical encoding of the
     * sixteen fields.
     *
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    public function digest(): string
    {
        return hash('sha256', CanonicalEncoder::encode($this->toArray()));
    }

    /**
     * The row that stores the seal, in table order: the thirteen envelope
     * columns and the journal's two, with times in the form the database
     * stores, and the digest and signature given. The anchor columns are left
     * out, so they start `null`.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  string  $sealDigest
     * @param  string  $signature
     * @return array{id: string, sequence: int, log_id: string, previous_id: ?string, previous_digest: ?string, member_count: int, members_digest: string, seal_digest: string, first_recorded_at: string, last_recorded_at: string, sealed_at: string, signer: string, key_id: string, algorithm_version: int, journal_sequence: ?int, journal_head: ?string, signature: string}
     *
     * @throws \InvalidArgumentException
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public function toRow(string $sealDigest, string $signature): array
    {
        foreach (['seal_digest' => $sealDigest, 'signature' => $signature] as $column => $value) {
            if (preg_match(self::DIGEST_PATTERN, $value) !== 1) {
                throw new \InvalidArgumentException(self::MESSAGES[$column]);
            }
        }

        return [
            'id'                => $this->id,
            'sequence'          => $this->sequence,
            'log_id'            => $this->logId,
            'previous_id'       => $this->previousId,
            'previous_digest'   => $this->previousDigest,
            'member_count'      => $this->memberCount,
            'members_digest'    => $this->membersDigest,
            'seal_digest'       => $sealDigest,
            'first_recorded_at' => StoredTime::toStorage($this->firstRecordedAt),
            'last_recorded_at'  => StoredTime::toStorage($this->lastRecordedAt),
            'sealed_at'         => StoredTime::toStorage($this->sealedAt),
            'signer'            => $this->signer,
            'key_id'            => $this->keyId,
            'algorithm_version' => $this->algorithmVersion,
            'journal_sequence'  => $this->journalSequence,
            'journal_head'      => $this->journalHead,
            'signature'         => $signature,
        ];
    }

    /**
     * The first field, in the order given, that is malformed, or `null` when
     * none is. The latest member's time is malformed, too, when it is before
     * the earliest's; both are in one fixed form, so comparing them as strings
     * orders them as instants.
     *
     * @param  array<string, int|string|null>  $fields
     * @return ?string
     */
    private static function malformedField(array $fields): ?string
    {
        foreach ($fields as $field => $value) {
            if (!self::isWellFormed($field, $value)) {
                return $field;
            }
        }

        return strcmp((string) $fields['first_recorded_at'], (string) $fields['last_recorded_at']) > 0 ? 'last_recorded_at' : null;
    }

    /**
     * Whether the field's value is one its column may hold.
     *
     * @param  string  $field
     * @param  int|string|null  $value
     * @return bool
     */
    private static function isWellFormed(string $field, int|string|null $value): bool
    {
        return match (true) {
            $value === null                     => in_array($field, self::NULLABLE, true),
            is_int($value)                      => self::isInRange($field, $value),
            in_array($field, self::TIMES, true) => StoredTime::isInstant($value),
            default                             => array_key_exists($field, self::PATTERNS) && preg_match(self::PATTERNS[$field], $value) === 1,
        };
    }

    /**
     * Whether the integer field's value is in its range: a supported algorithm
     * version, a member count from 1 to the most members, or a sequence, the
     * seal's or the journal's, of at least 1.
     *
     * @param  string  $field
     * @param  int  $value
     * @return bool
     */
    private static function isInRange(string $field, int $value): bool
    {
        return match ($field) {
            'algorithm_version' => in_array($value, self::SUPPORTED_ALGORITHM_VERSIONS, true),
            'member_count'      => $value >= 1 && $value <= self::MAX_MEMBERS,
            default             => $value >= 1,
        };
    }

    /**
     * Refuse a member whose entry id is not a lower-case UUID, or whose HMAC is
     * not 64 lower-case hex.
     *
     * @param  string  $entryId
     * @param  string  $hmac
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function checkMember(string $entryId, string $hmac): void
    {
        if (preg_match(self::UUID_PATTERN, $entryId) !== 1) {
            throw new \InvalidArgumentException('A seal member\'s entry id' . self::UUID);
        }

        if (preg_match(self::DIGEST_PATTERN, $hmac) !== 1) {
            throw new \InvalidArgumentException('A seal member\'s HMAC' . self::DIGEST);
        }
    }

    /**
     * The stored column's value, refused when the column is missing.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $stored
     * @param  string  $column
     * @return mixed
     *
     * @throws \UnexpectedValueException
     */
    private static function storedColumn(array $stored, string $column): mixed
    {
        if (!array_key_exists($column, $stored)) {
            throw new \UnexpectedValueException(sprintf('A stored seal has no `%s` column; every envelope column is required to read it.', $column));
        }

        return $stored[$column];
    }

    /**
     * The stored column as a string, refused when it is anything else.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $stored
     * @param  string  $column
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    private static function storedText(array $stored, string $column): string
    {
        $value = self::storedColumn($stored, $column);

        return is_string($value) ? $value : throw new \UnexpectedValueException(sprintf(self::STORED_MALFORMED, $column));
    }

    /**
     * The stored column as a string, or `null` when it holds `null`.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $stored
     * @param  string  $column
     * @return ?string
     *
     * @throws \UnexpectedValueException
     */
    private static function storedOptionalText(array $stored, string $column): ?string
    {
        return self::storedColumn($stored, $column) === null ? null : self::storedText($stored, $column);
    }

    /**
     * The stored column as an integer, read from an integer or the decimal
     * string an engine may return for one.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $stored
     * @param  string  $column
     * @return int
     *
     * @throws \UnexpectedValueException
     */
    private static function storedInteger(array $stored, string $column): int
    {
        return IntegerSetting::parse(self::storedColumn($stored, $column)) ?? throw new \UnexpectedValueException(sprintf(self::STORED_MALFORMED, $column));
    }

    /**
     * The stored time in the package's form, read in any form an engine
     * returns.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $stored
     * @param  string  $column
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    private static function storedTime(array $stored, string $column): string
    {
        $value = self::storedText($stored, $column);

        try {
            return StoredTime::fromStorage($value);
        } catch (\UnexpectedValueException) {
            throw new \UnexpectedValueException(sprintf(self::STORED_MALFORMED, $column));
        }
    }
}
