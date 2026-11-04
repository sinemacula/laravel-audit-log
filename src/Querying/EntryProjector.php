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
 * Projects the stored entries of a page as the entries a viewer is shown,
 * privacy-safe by construction, each in this order: a reason is concealed when
 * the stored properties flag `concealed` as exactly `true`, read before
 * anything is projected; the properties are projected recursively, maps as
 * associative arrays and lists as lists, and the manifest descriptor lifted
 * out; then the IP address; then the context, read as the properties are; and
 * last the references, enums and times of the columns.
 *
 * An encryption envelope is a map of exactly `v`, an integer from 1, and `k`
 * and `c`, non-empty strings, wherever it sits, even when an application stored
 * that shape itself, and an encrypted IP address is one stored as its JSON; one
 * whose parts its rules refuse is `unreadable`. Under a scope that does not
 * reveal the encrypted fields every envelope is shown as `encrypted` and the
 * field reader is never asked. Under one that does, each row's signature is
 * verified first: every envelope of a row that fails it, or whose signing key
 * the ring does not hold, is `unreadable` and never reaches the reader; every
 * envelope of the rows that pass is a field, at its segments, and every field
 * of the page is read in one call to the field reader. Nothing the stored entry
 * holds is changed, so it stays evidence.
 *
 * A field reader that throws, or answers another count or anything but
 * readings, costs every field of the page, each shown as `unreadable`: the
 * failure is reported once for the page, naming only the reader's class, and
 * what it threw is discarded, because its message could hold the plaintext. An
 * address the reader reveals as anything but a string is `unreadable`. The page
 * counts the fragments it shows in each state, never naming one.
 *
 * Only a descriptor the artifact inspector accepts is shown, as its kind, count
 * and digest; any other is dropped from the display and shows as none, since
 * only a tampered row holds one, which verification reports, and a page is
 * never refused for it.
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

    /** @var string The column, and the one segment, of an encrypted IP address. */
    private const string IP = 'ip';

    /** @var string The count of the fragments the field reader revealed. */
    private const string REVEALED = 'revealed';

    /** @var array{encrypted: int, erased: int, revealed: int, unreadable: int} A page's counts before any fragment is shown. */
    private const array NO_FRAGMENT = ['encrypted' => 0, 'erased' => 0, 'revealed' => 0, 'unreadable' => 0];

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Contracts\FieldReader  $reader
     * @param  \Illuminate\Contracts\Debug\ExceptionHandler  $handler
     * @param  \SineMacula\Laravel\AuditLog\Integrity\RecordSigner  $signer
     */
    public function __construct(

        /** What reads the encrypted fields of a page under a scope that reveals them. */
        private FieldReader $reader,

        /** Where a failed field reader is reported. */
        private ExceptionHandler $handler,

        /** What verifies each row's signature before any of its fields is read. */
        private RecordSigner $signer,
    ) {}

    /**
     * The entries a viewer is shown of the stored entries, in their order, with
     * the encrypted fields revealed through one call to the field reader when
     * the scope reveals them, and what the page disclosed of them.
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
     * How the stored entry's envelopes are shown under a scope that reveals
     * them: `null`, each read through the field reader, when its row's
     * signature verifies, and `unreadable` when it does not, or its signing key
     * is not in the ring, or the row cannot be judged.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\StoredEntry  $entry
     * @return ?\SineMacula\Laravel\AuditLog\Privacy\Enums\FieldState
     */
    private function sealedAs(#[\SensitiveParameter] StoredEntry $entry): ?FieldState
    {
        try {
            return $this->signer->verifies($entry->envelope) ? null : FieldState::UNREADABLE;
        } catch (\UnexpectedValueException|UnknownKeyException) {
            // A row whose key is not held, or that cannot be judged, is not
            // authenticated, so none of what it holds reaches the reader
            return FieldState::UNREADABLE;
        }
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
     * The value at the segments projected for display: an encryption envelope
     * as its field, to be read, or its marker, a map as an associative array
     * and a list as a list, each member projected in turn at its key as
     * `EncryptedField::segment()` names it, which the writer named it by, and
     * anything else as it is.
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
     * The IP address for display: one stored as an encrypted envelope as its
     * field at `ip`, to be read, or its marker; any other value beginning `{`
     * as `unreadable`; and any other value as stored.
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
     * What is shown, once the page's fields are read, of each field by its
     * object's id, each counted by its state: the reading's display, or
     * `unreadable` for every field when the field reader failed, which is
     * reported once, and for an address revealed as anything but a string.
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
     * The readings of the page's fields, in order, from one call to the field
     * reader, which is never asked for none; or nothing, once reported, when it
     * throws or answers another count or anything but readings.
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
            // What was thrown could hold the plaintext in its message, so it is
            // never kept: every field shows as unreadable and the failure is
            // reported naming the reader alone
            $readings = null;
        }

        if (self::isReadingOf($readings, count($fields))) {
            return $readings;
        }

        $this->report();

        return [];
    }

    /**
     * Report, once, that the field reader failed, naming only its class. A
     * reporter that fails too is ignored: the fields already show as
     * unreadable, and there is nowhere left to say so.
     *
     * @return void
     */
    private function report(): void
    {
        try {
            $this->handler->report(new \UnexpectedValueException(sprintf('The field reader %s failed.', get_debug_type($this->reader))));
        } catch (\Throwable) {
            // The page is still being shown; a broken reporter must not undo
            // the containment of the failure it was told about
        }
    }

    /**
     * The envelope's members for display: under a scope that reveals the fields
     * and a row that verified, its field, kept to be read, and otherwise the
     * marker of the state it is sealed as; one whose parts its rules refuse is
     * `unreadable`. Each marker is counted.
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
     * The projected map with each field in it replaced by what is shown of it.
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
     * The IP address with its field, if it is one, replaced by what is shown of
     * it, which is always a string.
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
     * Whether the field reader's answer is exactly a list of as many readings
     * as it was asked for.
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
     * metadata, still maps, left out when the descriptor was all it held, and
     * the stored value itself, unchanged, when there is no descriptor.
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
     * The refusal of a column whose stored value the shown entry cannot hold,
     * naming the column, never its value.
     *
     * @param  string  $column
     * @return \UnexpectedValueException
     */
    private static function malformed(string $column): \UnexpectedValueException
    {
        return EntryColumns::malformed($column);
    }
}
