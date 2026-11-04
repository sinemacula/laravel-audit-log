<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Querying;

use Illuminate\Contracts\Debug\ExceptionHandler;
use SineMacula\Laravel\AuditLog\Contracts\FieldReader;
use SineMacula\Laravel\AuditLog\Integrity\ArtifactInspector;
use SineMacula\Laravel\AuditLog\Privacy\EncryptedField;
use SineMacula\Laravel\AuditLog\Privacy\Enums\FieldState;
use SineMacula\Laravel\AuditLog\Records\Enums\Origin;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Records\Enums\Provenance;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Support\StoredTime;

/**
 * Projects a stored entry as the entry a viewer is shown, privacy-safe by
 * construction, in this order: a reason is concealed when the stored properties
 * flag `concealed` as exactly `true`, read before anything is projected; the
 * properties are projected recursively, maps as associative arrays and lists as
 * lists, every encryption envelope through the field reader, and the manifest
 * descriptor lifted out; then the IP address, an encrypted one through the
 * field reader; then the context, read as the properties are; and last the
 * references, enums and times of the columns.
 *
 * An encryption envelope is a map of exactly `v`, an integer from 1, and `k`
 * and `c`, non-empty strings, wherever it sits, even when an application stored
 * that shape itself; one the field cannot hold is `unreadable`. Nothing the
 * stored entry holds is changed, so it stays evidence.
 *
 * Only a descriptor the artifact inspector accepts is shown, as its kind, count
 * and digest; any other is dropped from the display and shows as none, since
 * only a tampered row holds one, which verification reports, and a page is
 * never refused for it. A field reader that throws costs the field alone, shown
 * as `unreadable`: the failure is reported once for all the entries projected
 * together, a page's, naming only the reader's class, and what it threw is
 * discarded, because its message could hold the plaintext.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class EntryProjector
{
    /** @var string The key the package's metadata sits under in the properties. */
    private const string METADATA_KEY = '_audit';

    /** @var string The key the manifest descriptor sits under in the metadata. */
    private const string MANIFEST_KEY = 'manifest';

    /** @var string The key whose value `true` conceals the entry's reason. */
    private const string CONCEALED_KEY = 'concealed';

    /** @var list<string> The keys of an encryption envelope, sorted: exactly these and nothing else. */
    private const array ENVELOPE_KEYS = ['c', 'k', 'v'];

    /** @var int The JSON depth of an encrypted IP address: one object of scalars. */
    private const int IP_DEPTH = 2;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Contracts\FieldReader  $reader
     * @param  \Illuminate\Contracts\Debug\ExceptionHandler  $handler
     */
    public function __construct(

        /** What reads every encrypted fragment of an entry. */
        private FieldReader $reader,

        /** Where a failed field reader is reported. */
        private ExceptionHandler $handler,
    ) {}

    /**
     * The entries a viewer is shown of the stored entries, in their order; a
     * field reader that failed on any of them is reported once.
     *
     * @param  list<\SineMacula\Laravel\AuditLog\Querying\StoredEntry>  $stored
     * @return list<\SineMacula\Laravel\AuditLog\Querying\TrailEntry>
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    public function project(#[\SensitiveParameter] array $stored): array
    {
        $failed  = false;
        $entries = [];

        foreach ($stored as $entry) {
            $envelope = $entry->envelope;
            $id       = $entry->id();

            $concealed  = self::isConcealed($envelope['properties']);
            $properties = $this->displayedMap(self::withoutDescriptor($envelope['properties']), 'properties', $id, $failed);
            $ip         = $this->ip(self::nullable($envelope, 'ip'), $id, $failed);
            $context    = $this->displayedMap($envelope['context'], 'context', $id, $failed);

            $entries[] = self::entry($entry, $concealed, $properties, $context, $ip);
        }

        if ($failed) {
            $this->report();
        }

        return $entries;
    }

    /**
     * The shown entry of the stored entry's columns, with what was projected of
     * its properties, context and IP address.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\StoredEntry  $stored
     * @param  bool  $concealed
     * @param  array<array-key, mixed>  $properties
     * @param  array<array-key, mixed>  $context
     * @param  ?string  $ip
     * @return \SineMacula\Laravel\AuditLog\Querying\TrailEntry
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    private static function entry(
        #[\SensitiveParameter] StoredEntry $stored,
        bool $concealed,
        #[\SensitiveParameter] array $properties,
        #[\SensitiveParameter] array $context,
        #[\SensitiveParameter] ?string $ip,
    ): TrailEntry {
        $envelope = $stored->envelope;

        return new TrailEntry(
            id: $stored->id(),
            event: self::text($envelope, 'event'),
            eventVersion: self::integer($envelope, 'event_version'),
            recordVersion: self::integer($envelope, 'record_version'),
            integrityVersion: self::integer($envelope, 'integrity_version'),
            category: self::text($envelope, 'category'),
            outcome: Outcome::tryFrom(self::text($envelope, 'outcome')) ?? throw self::malformed('outcome'),
            reason: $concealed ? null : self::nullable($envelope, 'reason'),
            actor: self::reference($envelope, 'actor'),
            subject: self::reference($envelope, 'subject'),
            principal: self::reference($envelope, 'principal'),
            tenant: self::reference($envelope, 'tenant'),
            credentialId: self::nullable($envelope, 'credential_id'),
            guard: self::nullable($envelope, 'guard'),
            sessionId: self::nullable($envelope, 'session_id'),
            requestId: self::nullable($envelope, 'request_id'),
            traceId: self::nullable($envelope, 'trace_id'),
            correlationId: self::nullable($envelope, 'correlation_id'),
            origin: self::origin($envelope),
            provenance: Provenance::tryFrom(self::text($envelope, 'provenance')) ?? throw self::malformed('provenance'),
            sourceId: self::text($envelope, 'source_id'),
            sourceRegion: self::nullable($envelope, 'source_region'),
            sourceRecordId: self::nullable($envelope, 'source_record_id'),
            importBatchId: self::nullable($envelope, 'import_batch_id'),
            sourceDigest: self::nullable($envelope, 'source_digest'),
            ip: $ip,
            userAgent: self::nullable($envelope, 'user_agent'),
            context: $context,
            properties: $properties,
            occurredAt: StoredTime::instant(StoredTime::toStorage($stored->occurredAt())),
            recordedAt: StoredTime::instant(StoredTime::toStorage($stored->recordedAt())),
            keyId: $stored->keyId(),
            hmac: $stored->hmac(),
            manifest: self::manifest($stored),
        );
    }

    /**
     * Whether the stored properties conceal the entry's reason: a map whose
     * `concealed` is exactly `true`.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $properties
     * @return bool
     */
    private static function isConcealed(#[\SensitiveParameter] mixed $properties): bool
    {
        return $properties instanceof \stdClass && ($properties->{self::CONCEALED_KEY} ?? null) === true;
    }

    /**
     * The stored properties without the manifest descriptor, which the entry
     * shows on its own or not at all: a copy of the properties and of their
     * metadata, left out when the descriptor was all it held, and the stored
     * value itself, unchanged, when there is no descriptor.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $properties
     * @return mixed
     */
    private static function withoutDescriptor(#[\SensitiveParameter] mixed $properties): mixed
    {
        $members  = $properties instanceof \stdClass ? get_object_vars($properties) : [];
        $metadata = $members[self::METADATA_KEY] ?? null;

        if (!$metadata instanceof \stdClass || !property_exists($metadata, self::MANIFEST_KEY)) {
            return $properties;
        }

        $kept = get_object_vars($metadata);

        unset($kept[self::MANIFEST_KEY]);

        if ($kept === []) {
            unset($members[self::METADATA_KEY]);

            return $members;
        }

        $members[self::METADATA_KEY] = $kept;

        return $members;
    }

    /**
     * The JSON column projected for display, `null` as an empty array; a column
     * holding anything but an object or a list is refused.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @param  'context'|'properties'  $column
     * @param  string  $id
     * @param  bool  $failed
     * @return array<array-key, mixed>
     *
     * @throws \UnexpectedValueException
     */
    private function displayedMap(#[\SensitiveParameter] mixed $value, string $column, string $id, bool &$failed): array
    {
        $shown = $value === null ? [] : $this->displayed($value, $column, $id, $failed);

        return is_array($shown) ? $shown : throw self::malformed($column);
    }

    /**
     * The value at the path projected for display: an encryption envelope as
     * the field reader answers it, `unreadable` when the field cannot hold it,
     * a map as an associative array and a list as a list, each member projected
     * in turn, and anything else as it is.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @param  string  $path
     * @param  string  $id
     * @param  bool  $failed
     * @return mixed
     */
    private function displayed(#[\SensitiveParameter] mixed $value, #[\SensitiveParameter] string $path, string $id, bool &$failed): mixed
    {
        if (!$value instanceof \stdClass && !is_array($value)) {
            return $value;
        }

        $members = $value instanceof \stdClass ? get_object_vars($value) : $value;

        if (self::isEnvelope($members)) {
            $field = EncryptedField::fromEnvelope($id, $path, $members);

            return $field === null ? FieldState::UNREADABLE->marker() : $this->read($field, $failed);
        }

        $shown = [];

        foreach ($members as $key => $member) {
            $shown[$key] = $this->displayed($member, $path . '.' . $key, $id, $failed);
        }

        return $shown;
    }

    /**
     * What the field reader shows of the field, or `unreadable` when it throws,
     * which marks the projection failed and is otherwise discarded.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \SineMacula\Laravel\AuditLog\Privacy\EncryptedField  $field
     * @param  bool  $failed
     * @return array<array-key, mixed>|scalar|null
     */
    private function read(#[\SensitiveParameter] EncryptedField $field, bool &$failed): array|bool|float|int|string|null
    {
        try {
            return $this->reader->read($field)->display();
        } catch (\Throwable) {
            // What was thrown could hold the plaintext in its message, so it is
            // never kept: the field shows as unreadable and the failure is
            // reported naming the reader alone
            $failed = true;

            return FieldState::UNREADABLE->marker();
        }
    }

    /**
     * The IP address for display: one stored as an encrypted envelope as the
     * field reader answers it at `ip`, a string, `unreadable` for any other
     * value beginning `{`, and any other value as stored.
     *
     * @param  ?string  $ip
     * @param  string  $id
     * @param  bool  $failed
     * @return ?string
     */
    private function ip(#[\SensitiveParameter] ?string $ip, string $id, bool &$failed): ?string
    {
        if ($ip === null || !str_starts_with($ip, '{')) {
            return $ip;
        }

        $decoded = json_decode($ip, false, self::IP_DEPTH);
        $field   = $decoded instanceof \stdClass ? EncryptedField::fromEnvelope($id, 'ip', $decoded) : null;
        $shown   = $field === null ? null : $this->read($field, $failed);

        return is_string($shown) ? $shown : FieldState::UNREADABLE->marker();
    }

    /**
     * Report, once, that the field reader failed, naming only its class. A
     * reporter that fails too is ignored: the field already shows as
     * unreadable, and there is nowhere left to say so.
     *
     * @return void
     */
    private function report(): void
    {
        try {
            $this->handler->report(new \UnexpectedValueException(sprintf('The field reader %s failed.', get_debug_type($this->reader))));
        } catch (\Throwable) {
            // The entry is still being shown; a broken reporter must not undo
            // the containment of the failure it was told about
        }
    }

    /**
     * Whether the members are an encryption envelope: exactly `v`, an integer
     * from 1, and `k` and `c`, non-empty strings.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $members
     * @return bool
     */
    private static function isEnvelope(#[\SensitiveParameter] array $members): bool
    {
        $keys = array_map(strval(...), array_keys($members));

        sort($keys);

        if ($keys !== self::ENVELOPE_KEYS) {
            return false;
        }

        ['v' => $version, 'k' => $key, 'c' => $ciphertext] = $members;

        return is_int($version) && $version >= 1 && self::isFilled($key) && self::isFilled($ciphertext);
    }

    /**
     * Whether the value is a non-empty string.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @return bool
     */
    private static function isFilled(#[\SensitiveParameter] mixed $value): bool
    {
        return is_string($value) && $value !== '';
    }

    /**
     * The entry's manifest descriptor as its kind, count and digest, when the
     * artifact inspector accepts it as exactly a descriptor, or `null`.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\StoredEntry  $stored
     * @return ?array{kind: string, count: int, digest: string}
     */
    private static function manifest(#[\SensitiveParameter] StoredEntry $stored): ?array
    {
        $descriptor = $stored->descriptor();

        if ($descriptor === null || !ArtifactInspector::isDescriptor($descriptor)) {
            return null;
        }

        return ['kind' => $descriptor['kind'], 'count' => $descriptor['count'], 'digest' => $descriptor['digest']];
    }

    /**
     * The reference of the pair of columns, or `null` unless both are stored.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $envelope
     * @param  'actor'|'principal'|'subject'|'tenant'  $pair
     * @return ?\SineMacula\Laravel\AuditLog\Records\Reference
     *
     * @throws \InvalidArgumentException
     */
    private static function reference(#[\SensitiveParameter] array $envelope, string $pair): ?Reference
    {
        $type = self::nullable($envelope, $pair . '_type');
        $id   = self::nullable($envelope, $pair . '_id');

        return $type === null || $id === null ? null : Reference::of($type, $id);
    }

    /**
     * The entry's origin, or `null` when none is stored.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $envelope
     * @return ?\SineMacula\Laravel\AuditLog\Records\Enums\Origin
     *
     * @throws \UnexpectedValueException
     */
    private static function origin(#[\SensitiveParameter] array $envelope): ?Origin
    {
        $origin = self::nullable($envelope, 'origin');

        return $origin === null ? null : Origin::tryFrom($origin) ?? throw self::malformed('origin');
    }

    /**
     * The column the row codec read as a string.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $envelope
     * @param  string  $column
     * @return string
     */
    private static function text(#[\SensitiveParameter] array $envelope, string $column): string
    {
        $value = $envelope[$column];

        // The codec reads each of these columns as a string or refuses the row
        assert(is_string($value));

        return $value;
    }

    /**
     * The column the row codec read as a string or `null`.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $envelope
     * @param  string  $column
     * @return ?string
     */
    private static function nullable(#[\SensitiveParameter] array $envelope, string $column): ?string
    {
        $value = $envelope[$column];

        // The codec reads each of these columns as a string or null, or refuses
        // the row
        assert($value === null || is_string($value));

        return $value;
    }

    /**
     * The column the row codec read as an integer.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $envelope
     * @param  string  $column
     * @return int
     */
    private static function integer(#[\SensitiveParameter] array $envelope, string $column): int
    {
        $value = $envelope[$column];

        // The codec reads each of these columns as an integer or refuses the
        // row
        assert(is_int($value));

        return $value;
    }

    /**
     * The refusal of a column whose stored value the shown entry cannot hold,
     * naming the column, never its value.
     *
     * @param  string  $column
     * @return \UnexpectedValueException
     */
    private static function malformed(string $column): \UnexpectedValueException
    {
        return new \UnexpectedValueException(sprintf('A stored entry\'s `%s` cannot be shown.', $column));
    }
}
