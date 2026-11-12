<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Querying;

use Illuminate\Contracts\Debug\ExceptionHandler;
use SineMacula\Laravel\AuditLog\Contracts\FieldReader;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException;
use SineMacula\Laravel\AuditLog\Privacy\EncryptedField;
use SineMacula\Laravel\AuditLog\Privacy\Enums\FieldState;
use SineMacula\Laravel\AuditLog\Privacy\FieldReading;

/**
 * Projects a page's stored entries as the entries a viewer is shown, reading
 * every encrypted field in one call to the field reader, and only from rows
 * whose signature verifies, when the scope reveals them.
 *
 * A malformed descriptor shows as none; only a tampered row holds one, and
 * verification reports it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class EntryProjector
{
    /** @var string The package's metadata key in the properties. */
    private const string METADATA_KEY = '_audit';

    /** @var string The manifest descriptor's key in the metadata. */
    private const string MANIFEST_KEY = 'manifest';

    /** @var string The key whose value `true` conceals the entry's reason. */
    private const string CONCEALED_KEY = 'concealed';

    /** @var list<string> The keys of an encryption envelope, sorted. */
    private const array ENVELOPE_KEYS = ['c', 'k', 'v'];

    /** @var int The JSON depth of an encrypted IP address: one object of scalars. */
    private const int IP_DEPTH = 2;

    /** @var string The column, and the one segment, of an encrypted IP address. */
    private const string IP = 'ip';

    /** @var string The count of the fragments the field reader revealed. */
    private const string REVEALED = 'revealed';

    /** @var array{encrypted: int, erased: int, revealed: int, unreadable: int} Zero counts. */
    private const array NO_FRAGMENT = ['encrypted' => 0, 'erased' => 0, 'revealed' => 0, 'unreadable' => 0];

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Contracts\FieldReader  $reader
     * @param  \Illuminate\Contracts\Debug\ExceptionHandler  $handler
     * @param  \SineMacula\Laravel\AuditLog\Integrity\RecordSigner  $signer
     */
    public function __construct(

        /** Reads the encrypted fields under a scope that reveals them. */
        private FieldReader $reader,

        /** Where a failed field reader is reported. */
        private ExceptionHandler $handler,

        /** Verifies each row's signature before any of its fields is read. */
        private RecordSigner $signer,
    ) {}

    /**
     * The entries a viewer is shown, in order, and what the page disclosed.
     *
     * @param  list<\SineMacula\Laravel\AuditLog\Querying\StoredEntry>  $stored
     * @param  bool  $reveal
     * @return \SineMacula\Laravel\AuditLog\Querying\ProjectedPage
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    public function project(#[\SensitiveParameter] array $stored, bool $reveal): ProjectedPage
    {
        $page  = ['fields' => [], 'counts' => self::NO_FRAGMENT];
        $parts = [];

        foreach ($stored as $entry) {
            $envelope = $entry->envelope;
            $id       = $entry->id();
            $sealedAs = $reveal ? $this->sealedAs($entry) : FieldState::ENCRYPTED;

            $concealed  = self::isConcealed($envelope['properties']);
            $properties = $this->displayedMap(self::withoutDescriptor($envelope['properties']), 'properties', $id, $sealedAs, $page);
            $ip         = $this->ip(EntryColumns::nullable($envelope, self::IP), $id, $sealedAs, $page);
            $context    = $this->displayedMap($envelope['context'], 'context', $id, $sealedAs, $page);

            $parts[] = [$entry, $concealed, $properties, $context, $ip];
        }

        $displays = $this->displays($page);
        $entries  = [];

        foreach ($parts as [$entry, $concealed, $properties, $context, $ip]) {
            $shownProperties = self::resolvedMap($properties, $displays);
            $shownContext    = self::resolvedMap($context, $displays);

            $entries[] = EntryColumns::entry($entry, $concealed, $shownProperties, $shownContext, self::resolvedIp($ip, $displays));
        }

        return new ProjectedPage($entries, new FieldDisclosure($reveal, ...$page['counts']));
    }

    /**
     * `null` when the row verifies and its fields may be read, else
     * `unreadable`.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\StoredEntry  $entry
     * @return ?\SineMacula\Laravel\AuditLog\Privacy\Enums\FieldState
     */
    private function sealedAs(#[\SensitiveParameter] StoredEntry $entry): ?FieldState
    {
        try {
            return $this->signer->verifies($entry->envelope) ? null : FieldState::UNREADABLE;
        } catch (\UnexpectedValueException|UnknownKeyException) {
            // An unauthenticated row never reaches the reader
            return FieldState::UNREADABLE;
        }
    }

    /**
     * The JSON column projected for display, `null` as an empty array.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @param  'context'|'properties'  $column
     * @param  string  $id
     * @param  ?\SineMacula\Laravel\AuditLog\Privacy\Enums\FieldState  $sealedAs
     * @param  array{fields: list<\SineMacula\Laravel\AuditLog\Privacy\EncryptedField>, counts: array{encrypted: int, erased: int, revealed: int, unreadable: int}}  $page
     * @return array<array-key, mixed>
     *
     * @throws \UnexpectedValueException
     */
    private function displayedMap(#[\SensitiveParameter] mixed $value, string $column, string $id, ?FieldState $sealedAs, array &$page): array
    {
        $shown = $value === null ? [] : $this->displayed($value, [$column], $id, $sealedAs, $page);

        if (is_array($shown)) {
            return $shown;
        }

        throw self::malformed($column);
    }

    /**
     * The value projected recursively, each envelope as its field or marker.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @param  non-empty-list<int|string>  $segments
     * @param  string  $id
     * @param  ?\SineMacula\Laravel\AuditLog\Privacy\Enums\FieldState  $sealedAs
     * @param  array{fields: list<\SineMacula\Laravel\AuditLog\Privacy\EncryptedField>, counts: array{encrypted: int, erased: int, revealed: int, unreadable: int}}  $page
     * @return mixed
     */
    private function displayed(#[\SensitiveParameter] mixed $value, #[\SensitiveParameter] array $segments, string $id, ?FieldState $sealedAs, array &$page): mixed
    {
        if (!$value instanceof \stdClass && !is_array($value)) {
            return $value;
        }

        $map     = $value instanceof \stdClass;
        $members = $map ? get_object_vars($value) : $value;

        if (self::isEnvelope($members)) {
            return self::envelope($members, $segments, $id, $sealedAs, $page);
        }

        $shown = [];

        foreach ($members as $key => $member) {
            $shown[$key] = $this->displayed($member, [...$segments, EncryptedField::segment($key)], $id, $sealedAs, $page);
        }

        return $shown;
    }

    /**
     * The IP address for display; a malformed envelope is `unreadable`.
     *
     * @param  ?string  $ip
     * @param  string  $id
     * @param  ?\SineMacula\Laravel\AuditLog\Privacy\Enums\FieldState  $sealedAs
     * @param  array{fields: list<\SineMacula\Laravel\AuditLog\Privacy\EncryptedField>, counts: array{encrypted: int, erased: int, revealed: int, unreadable: int}}  $page
     * @return \SineMacula\Laravel\AuditLog\Privacy\EncryptedField|string|null
     */
    private function ip(#[\SensitiveParameter] ?string $ip, string $id, ?FieldState $sealedAs, array &$page): EncryptedField|string|null
    {
        if ($ip === null || !str_starts_with($ip, '{')) {
            return $ip;
        }

        $decoded = json_decode($ip, false, self::IP_DEPTH);
        $members = $decoded instanceof \stdClass ? get_object_vars($decoded) : [];

        if (!self::isEnvelope($members)) {
            $page['counts'][FieldState::UNREADABLE->value]++;

            return FieldState::UNREADABLE->marker();
        }

        return self::envelope($members, [self::IP], $id, $sealedAs, $page);
    }

    /**
     * The display of each read field by object id, counted by state.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array{fields: list<\SineMacula\Laravel\AuditLog\Privacy\EncryptedField>, counts: array{encrypted: int, erased: int, revealed: int, unreadable: int}}  $page
     * @return array<int, array<array-key, mixed>|scalar|null>
     */
    private function displays(#[\SensitiveParameter] array &$page): array
    {
        $readings = $this->readings($page['fields']);
        $displays = [];

        foreach ($page['fields'] as $index => $field) {
            $reading = $readings[$index] ?? FieldReading::sealed(FieldState::UNREADABLE);
            $display = $reading->display();
            $state   = $reading->state->value ?? self::REVEALED;

            if ($field->segments === [self::IP] && !is_string($display)) {
                $display = FieldState::UNREADABLE->marker();
                $state   = FieldState::UNREADABLE->value;
            }

            $page['counts'][$state]++;
            $displays[spl_object_id($field)] = $display;
        }

        return $displays;
    }

    /**
     * The readings of the page's fields from one call to the field reader, or
     * none, once reported, when it fails.
     *
     * @param  list<\SineMacula\Laravel\AuditLog\Privacy\EncryptedField>  $fields
     * @return list<\SineMacula\Laravel\AuditLog\Privacy\FieldReading>
     */
    private function readings(#[\SensitiveParameter] array $fields): array
    {
        if ($fields === []) {
            return [];
        }

        try {
            $readings = $this->reader->readAll($fields);
        } catch (\Throwable) {
            // Discarded: its message could hold the plaintext
            $readings = null;
        }

        if (self::isReadingOf($readings, count($fields))) {
            return $readings;
        }

        $this->report();

        return [];
    }

    /**
     * Report that the field reader failed, naming only its class.
     *
     * @return void
     */
    private function report(): void
    {
        try {
            $this->handler->report(new \UnexpectedValueException(sprintf('The field reader %s failed.', get_debug_type($this->reader))));
        } catch (\Throwable) {
            // A broken reporter must not stop the page being shown
        }
    }

    /**
     * The envelope as its field to be read, or as its counted marker.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $members
     * @param  non-empty-list<int|string>  $segments
     * @param  string  $id
     * @param  ?\SineMacula\Laravel\AuditLog\Privacy\Enums\FieldState  $sealedAs
     * @param  array{fields: list<\SineMacula\Laravel\AuditLog\Privacy\EncryptedField>, counts: array{encrypted: int, erased: int, revealed: int, unreadable: int}}  $page
     * @return \SineMacula\Laravel\AuditLog\Privacy\EncryptedField|string
     *
     * @throws \InvalidArgumentException
     */
    private static function envelope(
        #[\SensitiveParameter]
        array $members,
        #[\SensitiveParameter]
        array $segments,
        string $id,
        ?FieldState $sealedAs,
        array &$page,
    ): EncryptedField|string {
        $field = $sealedAs === null ? EncryptedField::fromEnvelope($id, $segments, $members) : null;

        if ($field !== null) {
            $page['fields'][] = $field;

            return $field;
        }

        $state = $sealedAs !== null && EncryptedField::isWellFormed($members) ? $sealedAs : FieldState::UNREADABLE;

        $page['counts'][$state->value]++;

        return $state->marker();
    }

    /**
     * The projected map with each field replaced by its display.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $shown
     * @param  array<int, array<array-key, mixed>|scalar|null>  $displays
     * @return array<array-key, mixed>
     */
    private static function resolvedMap(#[\SensitiveParameter] array $shown, #[\SensitiveParameter] array $displays): array
    {
        if ($displays === []) {
            return $shown;
        }

        foreach ($shown as $key => $member) {
            if ($member instanceof EncryptedField) {
                $shown[$key] = $displays[spl_object_id($member)];

                continue;
            }

            if (!is_array($member)) {
                continue;
            }

            $shown[$key] = self::resolvedMap($member, $displays);
        }

        return $shown;
    }

    /**
     * The IP address with its field, if any, replaced by its string display.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \SineMacula\Laravel\AuditLog\Privacy\EncryptedField|string|null  $ip
     * @param  array<int, array<array-key, mixed>|scalar|null>  $displays
     * @return ?string
     */
    private static function resolvedIp(#[\SensitiveParameter] EncryptedField|string|null $ip, #[\SensitiveParameter] array $displays): ?string
    {
        if (!$ip instanceof EncryptedField) {
            return $ip;
        }

        $display = $displays[spl_object_id($ip)];

        return is_string($display) ? $display : FieldState::UNREADABLE->marker();
    }

    /**
     * Whether the answer is a list of exactly the count of readings.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @phpstan-assert-if-true list<\SineMacula\Laravel\AuditLog\Privacy\FieldReading> $answer
     *
     * @param  mixed  $answer
     * @param  int  $count
     * @return bool
     */
    private static function isReadingOf(#[\SensitiveParameter] mixed $answer, int $count): bool
    {
        if (!is_array($answer) || !array_is_list($answer) || count($answer) !== $count) {
            return false;
        }

        foreach ($answer as $reading) {
            if (!$reading instanceof FieldReading) {
                return false;
            }
        }

        return true;
    }

    /**
     * Whether the properties' `concealed` is exactly `true`.
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
     * A copy of the properties without the manifest descriptor, which the entry
     * shows on its own; the stored value is never changed.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $properties
     * @return mixed
     */
    private static function withoutDescriptor(#[\SensitiveParameter] mixed $properties): mixed
    {
        $metadata = $properties instanceof \stdClass ? ($properties->{self::METADATA_KEY} ?? null) : null;

        if (!$metadata instanceof \stdClass || !property_exists($metadata, self::MANIFEST_KEY)) {
            return $properties;
        }

        $copy = clone $properties;
        $kept = clone $metadata;

        unset($kept->{self::MANIFEST_KEY});

        if (get_object_vars($kept) === []) {
            unset($copy->{self::METADATA_KEY});

            return $copy;
        }

        $copy->{self::METADATA_KEY} = $kept;

        return $copy;
    }

    /**
     * Whether the members are exactly `v` from 1 and non-empty `k` and `c`.
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
     * The refusal of a column the shown entry cannot hold.
     *
     * @param  string  $column
     * @return \UnexpectedValueException
     */
    private static function malformed(string $column): \UnexpectedValueException
    {
        return EntryColumns::malformed($column);
    }
}
