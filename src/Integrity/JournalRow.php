<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

use SineMacula\Laravel\AuditLog\Config\IntegerSetting;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Support\StoredTime;
use SineMacula\Laravel\AuditLog\Support\TextSanitizer;

/**
 * One row of the lifecycle journal, as it is drafted, signed and stored: its
 * place in the chain, the log it belongs to, its kind, the operation it records
 * and when, the authority that asked for it, the seal or the hold it names, its
 * payload and the payload's digest, the HMAC of the row before, and its own
 * signature.
 *
 * The payload is the canonical JSON text of a map, stored as text and never in
 * a JSON column, so the digest the signature covers is the digest of the bytes
 * stored. The signature covers the payload through that digest alone, so the
 * chain verifies from the small columns, and a reader that needs a payload
 * reads it and checks it against the digest. A row read without its payload
 * holds `null` for it.
 *
 * Every field is checked as it is built: a draft is refused with an
 * `InvalidArgumentException` naming the field, and a stored row read through
 * `fromRow()` with an `UnexpectedValueException` naming the column and never
 * its value. A draft is the first row of the chain exactly when it has no
 * previous HMAC; a stored row that breaks that rule is read, since it is
 * evidence the chain must report as a gap, not a row it may refuse to load. A
 * draft holds no key id and no HMAC until it is signed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class JournalRow
{
    /** @var int The version of the signed fields every row is built under. */
    public const int VERSION = 1;

    /** @var string A reason code: the grammar of the read path's reasons. */
    public const string REASON_PATTERN = '/\A[a-z0-9_.:-]{1,64}\z/';

    /** @var int Longest authority type, authority id or external reference, in characters. */
    public const int MAX_TEXT_CHARACTERS = 191;

    /** @var string The key id and HMAC of a draft, until it is signed. */
    private const string UNSIGNED = '';

    /** @var array<string, string> The pattern each string field must match, by its column. */
    private const array PATTERNS = [
        'id'             => SealEnvelope::UUID_PATTERN,
        'log_id'         => SealEnvelope::LOG_ID_PATTERN,
        'operation_id'   => SealEnvelope::UUID_PATTERN,
        'reason'         => self::REASON_PATTERN,
        'seal_id'        => SealEnvelope::UUID_PATTERN,
        'hold_id'        => SealEnvelope::UUID_PATTERN,
        'payload_digest' => SealEnvelope::DIGEST_PATTERN,
        'previous_hmac'  => SealEnvelope::DIGEST_PATTERN,
        'key_id'         => IntegrityKey::ID_PATTERN,
        'hmac'           => SealEnvelope::DIGEST_PATTERN,
    ];

    /** @var list<string> The fields that may be `null`. */
    private const array NULLABLE = ['authority_type', 'authority_id', 'reason', 'external_reference', 'seal_id', 'hold_id', 'payload', 'previous_hmac'];

    /** @var list<string> The fields that are clean text of 1 to 191 characters. */
    private const array TEXTS = ['authority_type', 'authority_id', 'external_reference'];

    /** @var string What a refused UUID field must be, after its name. */
    private const string UUID = ' must be a lower-case UUID.';

    /** @var string What a refused digest field must be, after its name. */
    private const string DIGEST = ' must be 64 lower-case hexadecimal characters.';

    /** @var string What a refused text field must be, after its name. */
    private const string TEXT = ' must be null or 1 to 191 characters, with no control characters.';

    /** @var array<string, string> Why each field is refused, by its column. */
    private const array MESSAGES = [
        'id'                 => 'A journal row\'s `id`' . self::UUID,
        'sequence'           => 'A journal row\'s `sequence` must be at least 1.',
        'log_id'             => 'A journal row\'s `log_id` must be 1 to 64 letters, digits, dots, underscores or hyphens, starting with a letter or a digit.',
        'kind'               => 'A journal row\'s `kind` must be a journal kind.',
        'operation_id'       => 'A journal row\'s `operation_id`' . self::UUID,
        'occurred_at'        => 'A journal row\'s `occurred_at` must be ISO-8601 UTC with microseconds.',
        'authority_type'     => 'A journal row\'s `authority_type`' . self::TEXT,
        'authority_id'       => 'A journal row\'s `authority_id`' . self::TEXT . ' It is set exactly when the authority type is.',
        'reason'             => 'A journal row\'s `reason` must be null or 1 to 64 lower-case letters, digits, dots, underscores, colons or hyphens.',
        'external_reference' => 'A journal row\'s `external_reference`' . self::TEXT,
        'seal_id'            => 'A journal row\'s `seal_id` must be null or a lower-case UUID.',
        'hold_id'            => 'A journal row\'s `hold_id` must be null or a lower-case UUID.',
        'payload'            => 'A journal row\'s `payload` must be a map with a canonical encoding.',
        'payload_digest'     => 'A journal row\'s `payload_digest`' . self::DIGEST,
        'previous_hmac'      => 'A journal row\'s `previous_hmac` must be null on the first row and 64 lower-case hexadecimal characters on every other.',
        'key_id'             => 'A journal row\'s `key_id` must be 1 to 32 letters, digits, dots, underscores or hyphens, starting with a letter or a digit.',
        'hmac'               => 'A journal row\'s `hmac`' . self::DIGEST,
    ];

    /** @var string Why a stored column is refused, by the column it names. */
    private const string STORED_MALFORMED = 'A stored journal row\'s `%s` is malformed.';

    /**
     * Constructor.
     *
     * @param  string  $id
     * @param  int  $sequence
     * @param  string  $logId
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind  $kind
     * @param  string  $operationId
     * @param  string  $occurredAt
     * @param  ?string  $authorityType
     * @param  ?string  $authorityId
     * @param  ?string  $reason
     * @param  ?string  $externalReference
     * @param  ?string  $sealId
     * @param  ?string  $holdId
     * @param  ?string  $payload
     * @param  string  $payloadDigest
     * @param  ?string  $previousHmac
     * @param  string  $keyId
     * @param  string  $hmac
     *
     * @throws \InvalidArgumentException
     */
    private function __construct(

        /** The row's id, a lower-case UUID. */
        public string $id,

        /** The row's place in the chain: 1 first, then one more than the row before. */
        public int $sequence,

        /** The log the row belongs to: the seals' log. */
        public string $logId,

        /** What the row records. */
        public JournalKind $kind,

        /** The id of the operation the row belongs to, a lower-case UUID. */
        public string $operationId,

        /** When the row was written, ISO-8601 UTC with microseconds. */
        public string $occurredAt,

        /** The type of the authority that asked for the operation, or `null` when none did. */
        public ?string $authorityType,

        /** The id of the authority that asked for the operation, or `null` when none did. */
        public ?string $authorityId,

        /** The reason code the authority gave, or `null`. */
        public ?string $reason,

        /** The reference the authority gave, such as a case number, or `null`. */
        public ?string $externalReference,

        /** The seal a prune row's record covers, or `null`. */
        public ?string $sealId,

        /** The hold a hold or a release row names, or `null`. */
        public ?string $holdId,

        /** The canonical JSON text of the payload, or `null` when the row was read without it. */
        public ?string $payload,

        /** SHA-256, lower-case hex, of the payload's text. */
        public string $payloadDigest,

        /** The HMAC of the row before, or `null` on the first row. */
        public ?string $previousHmac,

        /** The id of the ring key whose journal key signs the row; empty until it is signed. */
        public string $keyId,

        /** HMAC-SHA256, lower-case hex, over the kind's label and the digest of the signed fields; empty until it is signed. */
        public string $hmac,
    ) {
        $malformed = self::malformedField($this->columns(), $keyId === self::UNSIGNED && $hmac === self::UNSIGNED);

        if ($malformed !== null) {
            throw new \InvalidArgumentException(self::MESSAGES[$malformed]);
        }
    }

    /**
     * An unsigned row: its payload the canonical JSON text of the map given,
     * `{}` for an empty one, and its digest taken, with no key id and no HMAC
     * until it is signed. The authority is `null` or its type and id, and the
     * previous HMAC is `null` exactly on the first row.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $id
     * @param  int  $sequence
     * @param  string  $logId
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind  $kind
     * @param  string  $operationId
     * @param  string  $occurredAt
     * @param  ?array{0: string, 1: string}  $authority
     * @param  ?string  $reason
     * @param  ?string  $externalReference
     * @param  ?string  $sealId
     * @param  ?string  $holdId
     * @param  array<array-key, mixed>  $payload
     * @param  ?string  $previousHmac
     * @return self
     *
     * @throws \InvalidArgumentException
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @SuppressWarnings("php:S107")
     */
    public static function draft(
        string $id,
        int $sequence,
        string $logId,
        JournalKind $kind,
        string $operationId,
        string $occurredAt,
        ?array $authority,
        ?string $reason,
        ?string $externalReference,
        ?string $sealId,
        ?string $holdId,
        #[\SensitiveParameter]
        array $payload,
        ?string $previousHmac,
    ): self {
        $text = self::canonicalPayload($payload);

        [$authorityType, $authorityId] = $authority ?? [null, null];

        $draft = new self(
            $id,
            $sequence,
            $logId,
            $kind,
            $operationId,
            $occurredAt,
            $authorityType,
            $authorityId,
            $reason,
            $externalReference,
            $sealId,
            $holdId,
            $text,
            hash('sha256', $text),
            $previousHmac,
            self::UNSIGNED,
            self::UNSIGNED,
        );

        if (($previousHmac === null) !== ($sequence === 1)) {
            throw new \InvalidArgumentException(self::MESSAGES['previous_hmac']);
        }

        return $draft;
    }

    /**
     * The row of a decoded stored row, with its payload when asked: integers
     * are read as an integer or its decimal string and times in any form an
     * engine returns. A missing or malformed column is refused naming the
     * column, never quoting its value, and so is a payload that is not the
     * canonical JSON text of a map.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $stored
     * @param  bool  $withPayload
     * @return self
     *
     * @throws \UnexpectedValueException
     */
    public static function fromRow(#[\SensitiveParameter] array $stored, bool $withPayload): self
    {
        $kind = JournalKind::tryFrom(self::storedText($stored, 'kind')) ?? throw new \UnexpectedValueException(sprintf(self::STORED_MALFORMED, 'kind'));

        $fields = [
            'id'                 => self::storedText($stored, 'id'),
            'sequence'           => self::storedInteger($stored, 'sequence'),
            'log_id'             => self::storedText($stored, 'log_id'),
            'operation_id'       => self::storedText($stored, 'operation_id'),
            'occurred_at'        => self::storedTime($stored, 'occurred_at'),
            'authority_type'     => self::storedOptionalText($stored, 'authority_type'),
            'authority_id'       => self::storedOptionalText($stored, 'authority_id'),
            'reason'             => self::storedOptionalText($stored, 'reason'),
            'external_reference' => self::storedOptionalText($stored, 'external_reference'),
            'seal_id'            => self::storedOptionalText($stored, 'seal_id'),
            'hold_id'            => self::storedOptionalText($stored, 'hold_id'),
            'payload'            => $withPayload ? self::storedPayload($stored) : null,
            'payload_digest'     => self::storedText($stored, 'payload_digest'),
            'previous_hmac'      => self::storedOptionalText($stored, 'previous_hmac'),
            'key_id'             => self::storedText($stored, 'key_id'),
            'hmac'               => self::storedText($stored, 'hmac'),
        ];

        $malformed = self::malformedField($fields, false);

        if ($malformed !== null) {
            throw new \UnexpectedValueException(sprintf(self::STORED_MALFORMED, $malformed));
        }

        return new self(
            $fields['id'],
            $fields['sequence'],
            $fields['log_id'],
            $kind,
            $fields['operation_id'],
            $fields['occurred_at'],
            $fields['authority_type'],
            $fields['authority_id'],
            $fields['reason'],
            $fields['external_reference'],
            $fields['seal_id'],
            $fields['hold_id'],
            $fields['payload'],
            $fields['payload_digest'],
            $fields['previous_hmac'],
            $fields['key_id'],
            $fields['hmac'],
        );
    }

    /**
     * The row signed: the key id and the HMAC given, every other field as it
     * is.
     *
     * @param  string  $keyId
     * @param  string  $hmac
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function withSignature(string $keyId, string $hmac): self
    {
        if ($keyId === self::UNSIGNED) {
            throw new \InvalidArgumentException(self::MESSAGES['key_id']);
        }

        return new self(
            $this->id,
            $this->sequence,
            $this->logId,
            $this->kind,
            $this->operationId,
            $this->occurredAt,
            $this->authorityType,
            $this->authorityId,
            $this->reason,
            $this->externalReference,
            $this->sealId,
            $this->holdId,
            $this->payload,
            $this->payloadDigest,
            $this->previousHmac,
            $keyId,
            $hmac,
        );
    }

    /**
     * The fields the HMAC covers, each under its canonical key: every column
     * but the HMAC and the payload, whose digest stands for it. The order is
     * irrelevant: the canonical encoding sorts the keys.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return array{v: int, id: string, sequence: int, log_id: string, kind: string, operation_id: string, occurred_at: string, authority_type: ?string, authority_id: ?string, reason: ?string, external_reference: ?string, seal_id: ?string, hold_id: ?string, payload_digest: string, previous_hmac: ?string, key_id: string}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public function signedFields(): array
    {
        return [
            'v'                  => self::VERSION,
            'id'                 => $this->id,
            'sequence'           => $this->sequence,
            'log_id'             => $this->logId,
            'kind'               => $this->kind->value,
            'operation_id'       => $this->operationId,
            'occurred_at'        => $this->occurredAt,
            'authority_type'     => $this->authorityType,
            'authority_id'       => $this->authorityId,
            'reason'             => $this->reason,
            'external_reference' => $this->externalReference,
            'seal_id'            => $this->sealId,
            'hold_id'            => $this->holdId,
            'payload_digest'     => $this->payloadDigest,
            'previous_hmac'      => $this->previousHmac,
            'key_id'             => $this->keyId,
        ];
    }

    /**
     * The row's digest: SHA-256, in hex, over the canonical encoding of the
     * signed fields.
     *
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    public function digest(): string
    {
        return hash('sha256', CanonicalEncoder::encode($this->signedFields()));
    }

    /**
     * Whether the payload's text is the text its digest was taken of; a row
     * read without its payload holds nothing to compare, and does.
     *
     * @return bool
     */
    public function hasPayloadOfItsDigest(): bool
    {
        return $this->payload === null || hash_equals($this->payloadDigest, hash('sha256', $this->payload));
    }

    /**
     * The payload decoded as a map, or `null` when the row was read without it.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return ?array<array-key, mixed>
     *
     * @throws \JsonException
     */
    public function payloadMap(): ?array
    {
        if ($this->payload === null) {
            return null;
        }

        $decoded = json_decode($this->payload, true, 64, JSON_THROW_ON_ERROR);

        return is_array($decoded) ? $decoded : [];
    }

    /**
     * The row that stores the signed row, in table order, with its time in the
     * form the database stores. A row that is unsigned, or read without its
     * payload, is never stored.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return array{id: string, sequence: int, log_id: string, kind: string, operation_id: string, occurred_at: string, authority_type: ?string, authority_id: ?string, reason: ?string, external_reference: ?string, seal_id: ?string, hold_id: ?string, payload: string, payload_digest: string, previous_hmac: ?string, key_id: string, hmac: string}
     *
     * @throws \LogicException
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public function toRow(): array
    {
        if ($this->hmac === self::UNSIGNED || $this->payload === null) {
            throw new \LogicException('Only a signed journal row that holds its payload is stored.');
        }

        return [
            'id'                 => $this->id,
            'sequence'           => $this->sequence,
            'log_id'             => $this->logId,
            'kind'               => $this->kind->value,
            'operation_id'       => $this->operationId,
            'occurred_at'        => StoredTime::toStorage($this->occurredAt),
            'authority_type'     => $this->authorityType,
            'authority_id'       => $this->authorityId,
            'reason'             => $this->reason,
            'external_reference' => $this->externalReference,
            'seal_id'            => $this->sealId,
            'hold_id'            => $this->holdId,
            'payload'            => $this->payload,
            'payload_digest'     => $this->payloadDigest,
            'previous_hmac'      => $this->previousHmac,
            'key_id'             => $this->keyId,
            'hmac'               => $this->hmac,
        ];
    }

    /**
     * Every field the row checks, by its column, the kind left out: it is a
     * journal kind by its type.
     *
     * @return array<string, int|string|null>
     */
    private function columns(): array
    {
        return [
            'id'                 => $this->id,
            'sequence'           => $this->sequence,
            'log_id'             => $this->logId,
            'operation_id'       => $this->operationId,
            'occurred_at'        => $this->occurredAt,
            'authority_type'     => $this->authorityType,
            'authority_id'       => $this->authorityId,
            'reason'             => $this->reason,
            'external_reference' => $this->externalReference,
            'seal_id'            => $this->sealId,
            'hold_id'            => $this->holdId,
            'payload'            => $this->payload,
            'payload_digest'     => $this->payloadDigest,
            'previous_hmac'      => $this->previousHmac,
            'key_id'             => $this->keyId,
            'hmac'               => $this->hmac,
        ];
    }

    /**
     * The canonical JSON text of the payload: a map, `{}` when it is empty, and
     * never a list.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $payload
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private static function canonicalPayload(#[\SensitiveParameter] array $payload): string
    {
        if ($payload === []) {
            return CanonicalEncoder::encode(new \stdClass);
        }

        try {
            return array_is_list($payload) ? throw new \InvalidArgumentException(self::MESSAGES['payload']) : CanonicalEncoder::encode($payload);
        } catch (\UnexpectedValueException) {
            throw new \InvalidArgumentException(self::MESSAGES['payload']);
        }
    }

    /**
     * The first field, in the order given, that is malformed, or `null` when
     * none is. An authority names its type and id together, and an unsigned
     * row's key id and HMAC are left unchecked.
     *
     * @param  array<string, int|string|null>  $fields
     * @param  bool  $unsigned
     * @return ?string
     */
    private static function malformedField(array $fields, bool $unsigned): ?string
    {
        if ($unsigned) {
            unset($fields['key_id'], $fields['hmac']);
        }

        foreach ($fields as $field => $value) {
            if (!self::isWellFormed($field, $value)) {
                return $field;
            }
        }

        return ($fields['authority_type'] === null) !== ($fields['authority_id'] === null) ? 'authority_id' : null;
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
            is_int($value)                      => $value >= 1,
            $field === 'occurred_at'            => StoredTime::isInstant($value),
            $field === 'payload'                => true,
            in_array($field, self::TEXTS, true) => self::isCleanText($value),
            default                             => array_key_exists($field, self::PATTERNS) && preg_match(self::PATTERNS[$field], $value) === 1,
        };
    }

    /**
     * Whether the text is 1 to 191 characters, with no control characters: an
     * authority's type or id, or an external reference.
     *
     * @param  string  $value
     * @return bool
     */
    private static function isCleanText(string $value): bool
    {
        return $value !== '' && mb_strlen($value, 'UTF-8') <= self::MAX_TEXT_CHARACTERS && TextSanitizer::isClean($value);
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
    private static function storedColumn(#[\SensitiveParameter] array $stored, string $column): mixed
    {
        if (!array_key_exists($column, $stored)) {
            throw new \UnexpectedValueException(sprintf('A stored journal row has no `%s` column; every column is required to read it.', $column));
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
    private static function storedText(#[\SensitiveParameter] array $stored, string $column): string
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
    private static function storedOptionalText(#[\SensitiveParameter] array $stored, string $column): ?string
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
    private static function storedInteger(#[\SensitiveParameter] array $stored, string $column): int
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
    private static function storedTime(#[\SensitiveParameter] array $stored, string $column): string
    {
        $value = self::storedText($stored, $column);

        try {
            return StoredTime::fromStorage($value);
        } catch (\UnexpectedValueException) {
            throw new \UnexpectedValueException(sprintf(self::STORED_MALFORMED, $column));
        }
    }

    /**
     * The stored payload, refused unless it is the canonical JSON text of a
     * map: decoding it and encoding it canonically again gives the same text.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $stored
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    private static function storedPayload(#[\SensitiveParameter] array $stored): string
    {
        $text = self::storedText($stored, 'payload');

        try {
            $decoded = json_decode($text, false, 64, JSON_THROW_ON_ERROR);

            if ($decoded instanceof \stdClass && CanonicalEncoder::encode($decoded) === $text) {
                return $text;
            }
        } catch (\JsonException|\UnexpectedValueException) {
            // Neither JSON nor a canonical value: refused below, as any other
            // text that is not a canonical map
        }

        throw new \UnexpectedValueException(sprintf(self::STORED_MALFORMED, 'payload'));
    }
}
