<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

use SineMacula\Laravel\AuditLog\Config\IntegerSetting;
use SineMacula\Laravel\AuditLog\Contracts\KeyWrapper;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Integrity\Enums\KeyState;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Support\StoredTime;
use SineMacula\Laravel\AuditLog\Support\TextSanitizer;

/**
 * One generation of an owner's key unit, as it is drafted, signed and stored:
 * its id, which an envelope names as `k`; the unit, the owner with the record's
 * tenant and the definition's category, and the digest of the unit; its
 * generation; its state; the data key wrapped and the id of the wrapping key;
 * when it was made; the erasure that destroyed it; and its signature.
 *
 * The signature covers what never changes, the id, the unit's columns and
 * digest, the generation and the creation time, so a row moved to another owner
 * or generation no longer verifies. What changes is bound elsewhere: the
 * wrapped key by its wrap context, which names the row, its unit, its
 * generation and its wrapping key, and the state by the journal. The unit's
 * digest is the SHA-256, unkeyed, of the canonical encoding of the unit's
 * columns, and a row whose digest is not its columns' is refused.
 *
 * A row holds a wrapped key exactly when its state holds a key, with the id of
 * the key that wrapped it, and an erasure id exactly when it is erased. Every
 * field is checked as it is built: a draft is refused with an
 * `InvalidArgumentException` naming the field, and a stored row read through
 * `fromRow()` with an `UnexpectedValueException` naming the column and never
 * its value. A draft is live, and holds no key id and no HMAC until it is
 * signed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SubjectKeyRow
{
    /** @var int The version of the signed fields every row is built under. */
    public const int VERSION = 1;

    /** @var int Longest wrapped key, in bytes: the column. */
    public const int MAX_WRAPPED_BYTES = 65535;

    /** @var int Greatest generation: the column's integer. */
    public const int MAX_GENERATION = 2147483647;

    /** @var string The domain a wrap context names, so it is never another structure's. */
    private const string WRAP_DOMAIN = 'sinemacula/audit-log:wrap:v1';

    /** @var string The key id and HMAC of a draft, until it is signed. */
    private const string UNSIGNED = '';

    /** @var array<string, 'integer'|'optional'|'text'|'time'> How each stored column is read, in table order, but the state. */
    private const array STORED = [
        'id'          => 'text',
        'owner_type'  => 'text',
        'owner_id'    => 'text',
        'tenant_type' => 'optional',
        'tenant_id'   => 'optional',
        'category'    => 'text',
        'unit'        => 'text',
        'generation'  => 'integer',
        'wrapped_key' => 'optional',
        'wrap_key_id' => 'optional',
        'created_at'  => 'time',
        'erasure_id'  => 'optional',
        'key_id'      => 'text',
        'hmac'        => 'text',
    ];

    /** @var array<string, string> The pattern each patterned field must match, by its column. */
    private const array PATTERNS = [
        'id'          => SealEnvelope::UUID_PATTERN,
        'category'    => EventDefinition::CATEGORY_PATTERN,
        'unit'        => SealEnvelope::DIGEST_PATTERN,
        'wrap_key_id' => KeyWrapper::KEY_ID_PATTERN,
        'erasure_id'  => SealEnvelope::UUID_PATTERN,
        'key_id'      => IntegrityKey::ID_PATTERN,
        'hmac'        => SealEnvelope::DIGEST_PATTERN,
    ];

    /** @var list<string> The fields that may be `null`. */
    private const array NULLABLE = ['tenant_type', 'tenant_id', 'wrapped_key', 'wrap_key_id', 'erasure_id'];

    /** @var string What a refused text field must be, after its name. */
    private const string TEXT = ' must be 1 to 191 characters, with no control characters.';

    /** @var array<string, string> Why each field is refused, by its column. */
    private const array MESSAGES = [
        'id'          => 'A subject key row\'s `id` must be a lower-case UUID.',
        'owner_type'  => 'A subject key row\'s `owner_type`' . self::TEXT,
        'owner_id'    => 'A subject key row\'s `owner_id`' . self::TEXT,
        'tenant_type' => 'A subject key row\'s `tenant_type` must be null or 1 to 191 characters, with no control characters.',
        'tenant_id'   => 'A subject key row\'s `tenant_id` must be null or 1 to 191 characters, with no control characters. It is set exactly when the tenant type is.',
        'category'    => 'A subject key row\'s `category` must be a lower-case letter, then up to 63 lower-case letters, digits or underscores.',
        'unit'        => 'A subject key row\'s `unit` must be the lower-case hexadecimal SHA-256 of its unit\'s canonical encoding.',
        'generation'  => 'A subject key row\'s `generation` must be from 1 to 2147483647.',
        'wrapped_key' => 'A subject key row\'s `wrapped_key` must be 1 to 65535 bytes of clean text exactly when its state holds a key.',
        'wrap_key_id' => 'A subject key row\'s `wrap_key_id` must be a wrapping key id, set whenever it holds a wrapped key.',
        'created_at'  => 'A subject key row\'s `created_at` must be ISO-8601 UTC with microseconds.',
        'erasure_id'  => 'A subject key row\'s `erasure_id` must be a lower-case UUID exactly when it is erased.',
        'key_id'      => 'A subject key row\'s `key_id` must be 1 to 32 letters, digits, dots, underscores or hyphens, starting with a letter or a digit.',
        'hmac'        => 'A subject key row\'s `hmac` must be 64 lower-case hexadecimal characters.',
    ];

    /** @var string Why a stored column is refused, by the column it names. */
    private const string STORED_MALFORMED = 'A stored subject key row\'s `%s` is malformed.';

    /**
     * Constructor.
     *
     * @param  string  $id
     * @param  string  $ownerType
     * @param  string  $ownerId
     * @param  ?string  $tenantType
     * @param  ?string  $tenantId
     * @param  string  $category
     * @param  string  $unit
     * @param  int  $generation
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\KeyState  $state
     * @param  ?string  $wrappedKey
     * @param  ?string  $wrapKeyId
     * @param  string  $createdAt
     * @param  ?string  $erasureId
     * @param  string  $keyId
     * @param  string  $hmac
     *
     * @throws \InvalidArgumentException
     */
    private function __construct(

        /** The row's id, a lower-case UUID: the `k` an envelope names. */
        public string $id,

        /** The owner's type. */
        #[\SensitiveParameter]
        public string $ownerType,

        /** The owner's id. */
        #[\SensitiveParameter]
        public string $ownerId,

        /** The tenant's type, or `null` for a tenantless unit. */
        #[\SensitiveParameter]
        public ?string $tenantType,

        /** The tenant's id, or `null` for a tenantless unit. */
        #[\SensitiveParameter]
        public ?string $tenantId,

        /** The category of the definitions whose fields the unit encrypts. */
        public string $category,

        /** The unit's digest: lower-case hex SHA-256 of the canonical encoding of its columns. */
        public string $unit,

        /** The unit's generation, from 1. */
        public int $generation,

        /** Whether the key encrypts, only decrypts, or was erased. */
        public KeyState $state,

        /** The data key wrapped by the key wrapper, or `null` once erased. */
        #[\SensitiveParameter]
        public ?string $wrappedKey,

        /** The id of the wrapping key the data key is wrapped under, or `null`. */
        public ?string $wrapKeyId,

        /** When the key was made, ISO-8601 UTC with microseconds. */
        public string $createdAt,

        /** The id of the erasure that destroyed the key, or `null`. */
        public ?string $erasureId,

        /** The id of the ring key that signs the row; empty until it is signed. */
        public string $keyId,

        /** HMAC-SHA256, lower-case hex, over the label and the digest of the signed fields; empty until it is signed. */
        public string $hmac,
    ) {
        $malformed = self::malformedField($this->columns(), $keyId === self::UNSIGNED && $hmac === self::UNSIGNED)
            ?? self::brokenRuleOf($state, ['wrapped_key' => $wrappedKey, 'wrap_key_id' => $wrapKeyId, 'erasure_id' => $erasureId]);

        if ($malformed !== null) {
            throw new \InvalidArgumentException(self::MESSAGES[$malformed]);
        }
    }

    /**
     * An unsigned live row for the unit of the owner, the tenant and the
     * category: its digest taken, its data key wrapped under the wrapping key
     * named, with no key id and no HMAC until it is signed.
     *
     * @param  string  $id
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $tenant
     * @param  string  $category
     * @param  int  $generation
     * @param  string  $wrapped
     * @param  string  $wrapKeyId
     * @param  string  $createdAt
     * @return self
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     *
     * @SuppressWarnings("php:S107")
     */
    public static function draft(
        string $id,
        #[\SensitiveParameter]
        Reference $owner,
        #[\SensitiveParameter]
        ?Reference $tenant,
        string $category,
        int $generation,
        #[\SensitiveParameter]
        string $wrapped,
        string $wrapKeyId,
        string $createdAt,
    ): self {
        $unit = preg_match(EventDefinition::CATEGORY_PATTERN, $category) === 1 ? self::unitOf($owner->type, $owner->id, $tenant?->type, $tenant?->id, $category) : '';

        return new self(
            $id,
            $owner->type,
            $owner->id,
            $tenant?->type,
            $tenant?->id,
            $category,
            $unit,
            $generation,
            KeyState::LIVE,
            $wrapped,
            $wrapKeyId,
            $createdAt,
            null,
            self::UNSIGNED,
            self::UNSIGNED,
        );
    }

    /**
     * The row of a decoded stored row: integers are read as an integer or its
     * decimal string and times in any form an engine returns. A missing or
     * malformed column is refused naming the column, never quoting its value,
     * and so is a unit that is not its columns' digest and a wrapped key, a
     * wrapping key id or an erasure id its state does not allow.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $stored
     * @return self
     *
     * @throws \UnexpectedValueException
     */
    public static function fromRow(#[\SensitiveParameter] array $stored): self
    {
        $fields = [];

        foreach (self::STORED as $column => $how) {
            $fields[$column] = self::storedValue($stored, $column, $how);
        }

        $state     = KeyState::tryFrom((string) self::storedValue($stored, 'state', 'text'));
        $malformed = $state === null ? 'state' : (self::malformedField($fields, false) ?? self::brokenRuleOf($state, $fields));

        if ($state === null || $malformed !== null) {
            throw new \UnexpectedValueException(sprintf(self::STORED_MALFORMED, $malformed));
        }

        // phpcs:disable Generic.Files.LineLength.TooLong
        /** @var array{id: string, owner_type: string, owner_id: string, tenant_type: ?string, tenant_id: ?string, category: string, unit: string, generation: int, wrapped_key: ?string, wrap_key_id: ?string, created_at: string, erasure_id: ?string, key_id: string, hmac: string} $fields */
        // phpcs:enable Generic.Files.LineLength.TooLong
        return new self(
            $fields['id'],
            $fields['owner_type'],
            $fields['owner_id'],
            $fields['tenant_type'],
            $fields['tenant_id'],
            $fields['category'],
            $fields['unit'],
            $fields['generation'],
            $state,
            $fields['wrapped_key'],
            $fields['wrap_key_id'],
            $fields['created_at'],
            $fields['erasure_id'],
            $fields['key_id'],
            $fields['hmac'],
        );
    }

    /**
     * The digest of a key unit: lower-case hex SHA-256, unkeyed, of the
     * canonical encoding of the owner's type and id, the tenant's type and id,
     * or `null` for none, and the category.
     *
     * @param  string  $ownerType
     * @param  string  $ownerId
     * @param  ?string  $tenantType
     * @param  ?string  $tenantId
     * @param  string  $category
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    public static function unitOf(
        #[\SensitiveParameter] string $ownerType,
        #[\SensitiveParameter] string $ownerId,
        ?string $tenantType,
        ?string $tenantId,
        string $category,
    ): string {
        return hash('sha256', CanonicalEncoder::encode([$ownerType, $ownerId, $tenantType, $tenantId, $category]));
    }

    /**
     * The additional data a data key is wrapped with: the canonical JSON of the
     * wrap domain, the generation, the key row's id, the unit's digest and the
     * wrapping key's id, so a wrapped key moved to another row, unit,
     * generation or wrapping key does not unwrap.
     *
     * @param  string  $keyRowId
     * @param  string  $unit
     * @param  int  $generation
     * @param  string  $wrapKeyId
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    public static function wrapContextOf(string $keyRowId, string $unit, int $generation, string $wrapKeyId): string
    {
        return CanonicalEncoder::encode(['d' => self::WRAP_DOMAIN, 'generation' => $generation, 'k' => $keyRowId, 'unit' => $unit, 'wrap_key_id' => $wrapKeyId]);
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
            $this->ownerType,
            $this->ownerId,
            $this->tenantType,
            $this->tenantId,
            $this->category,
            $this->unit,
            $this->generation,
            $this->state,
            $this->wrappedKey,
            $this->wrapKeyId,
            $this->createdAt,
            $this->erasureId,
            $keyId,
            $hmac,
        );
    }

    /**
     * The fields the HMAC covers, each under its canonical key: every column
     * that never changes, and the key id. The state, the wrapped key, its
     * wrapping key id and the erasure id are left out.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return array{v: int, id: string, owner_type: string, owner_id: string, tenant_type: ?string, tenant_id: ?string, category: string, unit: string, generation: int, created_at: string, key_id: string}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public function signedFields(): array
    {
        return [
            'v'           => self::VERSION,
            'id'          => $this->id,
            'owner_type'  => $this->ownerType,
            'owner_id'    => $this->ownerId,
            'tenant_type' => $this->tenantType,
            'tenant_id'   => $this->tenantId,
            'category'    => $this->category,
            'unit'        => $this->unit,
            'generation'  => $this->generation,
            'created_at'  => $this->createdAt,
            'key_id'      => $this->keyId,
        ];
    }

    /**
     * The row's wrap context, under the wrapping key it names.
     *
     * @return string
     *
     * @throws \LogicException
     */
    public function wrapContext(): string
    {
        if ($this->wrapKeyId === null) {
            throw new \LogicException('A subject key row that names no wrapping key has no wrap context.');
        }

        return self::wrapContextOf($this->id, $this->unit, $this->generation, $this->wrapKeyId);
    }

    /**
     * SHA-256, lower-case hex, of the stored wrapped key, or `null` when the
     * row holds none: what the journal records of a wrapped key.
     *
     * @return ?string
     */
    public function wrappedDigest(): ?string
    {
        return $this->wrappedKey === null ? null : hash('sha256', $this->wrappedKey);
    }

    /**
     * The row that stores the signed row, in table order, with its time in the
     * form the database stores. An unsigned row is never stored.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return array{id: string, owner_type: string, owner_id: string, tenant_type: ?string, tenant_id: ?string, category: string, unit: string, generation: int, state: string, wrapped_key: ?string, wrap_key_id: ?string, created_at: string, erasure_id: ?string, key_id: string, hmac: string}
     *
     * @throws \LogicException
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public function toRow(): array
    {
        if ($this->hmac === self::UNSIGNED) {
            throw new \LogicException('Only a signed subject key row is stored.');
        }

        return [
            'id'          => $this->id,
            'owner_type'  => $this->ownerType,
            'owner_id'    => $this->ownerId,
            'tenant_type' => $this->tenantType,
            'tenant_id'   => $this->tenantId,
            'category'    => $this->category,
            'unit'        => $this->unit,
            'generation'  => $this->generation,
            'state'       => $this->state->value,
            'wrapped_key' => $this->wrappedKey,
            'wrap_key_id' => $this->wrapKeyId,
            'created_at'  => StoredTime::toStorage($this->createdAt),
            'erasure_id'  => $this->erasureId,
            'key_id'      => $this->keyId,
            'hmac'        => $this->hmac,
        ];
    }

    /**
     * Every field the row checks, by its column, the state left out: it is a
     * key state by its type.
     *
     * @return array<string, int|string|null>
     */
    private function columns(): array
    {
        return [
            'id'          => $this->id,
            'owner_type'  => $this->ownerType,
            'owner_id'    => $this->ownerId,
            'tenant_type' => $this->tenantType,
            'tenant_id'   => $this->tenantId,
            'category'    => $this->category,
            'unit'        => $this->unit,
            'generation'  => $this->generation,
            'wrapped_key' => $this->wrappedKey,
            'wrap_key_id' => $this->wrapKeyId,
            'created_at'  => $this->createdAt,
            'erasure_id'  => $this->erasureId,
            'key_id'      => $this->keyId,
            'hmac'        => $this->hmac,
        ];
    }

    /**
     * The field whose presence the state does not allow: a wrapped key exactly
     * when the state holds a key, a wrapping key id beside every wrapped key,
     * and an erasure id exactly when the key is erased.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\KeyState  $state
     * @param  array<string, int|string|null>  $fields
     * @return ?string
     */
    private static function brokenRuleOf(KeyState $state, #[\SensitiveParameter] array $fields): ?string
    {
        $wrapped = ($fields['wrapped_key'] ?? null) !== null;

        return match (true) {
            $wrapped !== $state->holdsAKey()                                             => 'wrapped_key',
            $wrapped && ($fields['wrap_key_id'] ?? null) === null                        => 'wrap_key_id',
            (($fields['erasure_id'] ?? null) !== null) !== ($state === KeyState::ERASED) => 'erasure_id',
            default                                                                      => null,
        };
    }

    /**
     * The first field, in table order, that is malformed, or `null` when none
     * is. A tenant names its type and id together, the unit must be its
     * columns' digest, and an unsigned row's key id and HMAC are left
     * unchecked.
     *
     * @param  array<string, int|string|null>  $fields
     * @param  bool  $unsigned
     * @return ?string
     */
    private static function malformedField(#[\SensitiveParameter] array $fields, bool $unsigned): ?string
    {
        if ($unsigned) {
            unset($fields['key_id'], $fields['hmac']);
        }

        foreach ($fields as $field => $value) {
            if (!self::isWellFormed($field, $value)) {
                return $field;
            }
        }

        if (($fields['tenant_type'] === null) !== ($fields['tenant_id'] === null)) {
            return 'tenant_id';
        }

        return self::isItsUnit($fields) ? null : 'unit';
    }

    /**
     * Whether the field's value is one its column may hold.
     *
     * @param  string  $field
     * @param  int|string|null  $value
     * @return bool
     */
    private static function isWellFormed(string $field, #[\SensitiveParameter] int|string|null $value): bool
    {
        if ($value === null) {
            return in_array($field, self::NULLABLE, true);
        }

        if (is_int($value)) {
            return $field === 'generation' && $value >= 1 && $value <= self::MAX_GENERATION;
        }

        return match ($field) {
            'owner_type', 'owner_id', 'tenant_type', 'tenant_id' => self::isCleanText($value),
            'wrapped_key'                                        => self::isWrappedKey($value),
            'created_at'                                         => StoredTime::isInstant($value),
            default                                              => array_key_exists($field, self::PATTERNS) && preg_match(self::PATTERNS[$field], $value) === 1,
        };
    }

    /**
     * Whether the text is 1 to 191 characters, with no control characters: an
     * owner's or a tenant's type or id.
     *
     * @param  string  $value
     * @return bool
     */
    private static function isCleanText(#[\SensitiveParameter] string $value): bool
    {
        return $value !== '' && mb_strlen($value, 'UTF-8') <= Reference::MAX_CHARACTERS && TextSanitizer::isClean($value);
    }

    /**
     * Whether the text is a wrapped key the column can hold: 1 to 65535 bytes
     * of clean text.
     *
     * @param  string  $value
     * @return bool
     */
    private static function isWrappedKey(#[\SensitiveParameter] string $value): bool
    {
        return $value !== '' && strlen($value) <= self::MAX_WRAPPED_BYTES && TextSanitizer::isClean($value);
    }

    /**
     * Whether the unit is the digest of the well-formed columns beside it.
     *
     * @param  array<string, int|string|null>  $fields
     * @return bool
     */
    private static function isItsUnit(#[\SensitiveParameter] array $fields): bool
    {
        $tenantType = $fields['tenant_type'] === null ? null : (string) $fields['tenant_type'];
        $tenantId   = $fields['tenant_id']   === null ? null : (string) $fields['tenant_id'];
        $unit       = self::unitOf((string) $fields['owner_type'], (string) $fields['owner_id'], $tenantType, $tenantId, (string) $fields['category']);

        return hash_equals($unit, (string) $fields['unit']);
    }

    /**
     * The stored column read as it is asked: a string, a string or `null`, an
     * integer from an integer or its decimal string, or a time in the package's
     * form from any form an engine returns. A missing column, and a value of
     * another form, is refused naming the column.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $stored
     * @param  string  $column
     * @param  'integer'|'optional'|'text'|'time'  $how
     * @return int|string|null
     *
     * @throws \UnexpectedValueException
     */
    private static function storedValue(#[\SensitiveParameter] array $stored, string $column, string $how): int|string|null
    {
        if (!array_key_exists($column, $stored)) {
            throw new \UnexpectedValueException(sprintf('A stored subject key row has no `%s` column; every column is required to read it.', $column));
        }

        $value     = $stored[$column];
        $malformed = sprintf(self::STORED_MALFORMED, $column);

        if ($how === 'optional' && $value === null) {
            return null;
        }

        if ($how === 'integer') {
            return IntegerSetting::parse($value) ?? throw new \UnexpectedValueException($malformed);
        }

        if (!is_string($value)) {
            throw new \UnexpectedValueException($malformed);
        }

        try {
            return $how === 'time' ? StoredTime::fromStorage($value) : $value;
        } catch (\UnexpectedValueException) {
            throw new \UnexpectedValueException($malformed);
        }
    }
}
