<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Privacy;

use SineMacula\Laravel\AuditLog\Contracts\FieldReader;
use SineMacula\Laravel\AuditLog\Contracts\KeyWrapper;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\JournalRow;
use SineMacula\Laravel\AuditLog\Integrity\JournalSigner;
use SineMacula\Laravel\AuditLog\Integrity\SealSettings;
use SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow;
use SineMacula\Laravel\AuditLog\Integrity\SubjectKeySigner;
use SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException;
use SineMacula\Laravel\AuditLog\Keys\KeyStore;
use SineMacula\Laravel\AuditLog\Privacy\Enums\FieldState;

/**
 * Opens what the package's encrypter sealed; a key is `erased` only when a
 * verified erasure row lists it, and nothing is kept between pages.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SubjectKeyFieldReader implements FieldReader
{
    /** @var string The payload key an erasure row lists the keys it destroyed under. */
    private const string DESTROYED = 'destroyed';

    /** @var string The key each destroyed key's id is listed under. */
    private const string KEY_ID = 'key_id';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Keys\KeyStore  $keys
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SubjectKeySigner  $keySigner
     * @param  \SineMacula\Laravel\AuditLog\Contracts\KeyWrapper  $wrapper
     * @param  \SineMacula\Laravel\AuditLog\Integrity\JournalSigner  $journalSigner
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealSettings  $settings
     */
    public function __construct(

        /** Where a page's keys and their erasure rows are read, on the writer. */
        private KeyStore $keys,

        /** Verifies each key row's signature before it is believed. */
        private SubjectKeySigner $keySigner,

        /** Unwraps each key's data key, bound to its row. */
        private KeyWrapper $wrapper,

        /** Verifies each erasure row's signature before it proves an erasure. */
        private JournalSigner $journalSigner,

        /** Where the log id envelopes and erasure rows are bound to is read from. */
        private SealSettings $settings,
    ) {}

    /**
     * Each field, in the order given: its typed value, `erased` for a key a
     * verified erasure destroyed, or `unreadable`.
     *
     * @param  list<\SineMacula\Laravel\AuditLog\Privacy\EncryptedField>  $fields
     * @return list<\SineMacula\Laravel\AuditLog\Privacy\FieldReading>
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function readAll(#[\SensitiveParameter] array $fields): array
    {
        if ($fields === []) {
            return [];
        }

        $logId    = $this->settings->logId();
        $keyRows  = $this->authenticated($this->keys->byIds(array_map(static fn (EncryptedField $field): string => $field->keyReference, $fields)));
        $erased   = $this->erased($keyRows, $logId);
        $dataKeys = $this->unwrapped($keyRows);
        $readings = [];

        foreach ($fields as $field) {
            $readings[] = match (true) {
                isset($erased[$field->keyReference])   => FieldReading::sealed(FieldState::ERASED),
                isset($dataKeys[$field->keyReference]) => self::opened($field, $dataKeys[$field->keyReference], $logId),
                default                                => FieldReading::sealed(FieldState::UNREADABLE),
            };
        }

        return $readings;
    }

    /**
     * The key rows whose signature verifies; the fields of any other read as
     * unknown.
     *
     * @param  array<string, \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow>  $keyRows
     * @return array<string, \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow>
     */
    private function authenticated(#[\SensitiveParameter] array $keyRows): array
    {
        return array_filter($keyRows, $this->verifies(...));
    }

    /**
     * Whether the key row's signature verifies; a malformed signature or
     * unknown signing key does not.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow  $keyRow
     * @return bool
     */
    private function verifies(#[\SensitiveParameter] SubjectKeyRow $keyRow): bool
    {
        try {
            return $this->keySigner->verifies($keyRow);
        } catch (\UnexpectedValueException|UnknownKeyException) {
            // A row that cannot be judged is not authenticated
            return false;
        }
    }

    /**
     * The ids of the erased keys a verified erasure row lists as destroyed,
     * reading the journal only when the page holds an erased key.
     *
     * @param  array<string, \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow>  $keyRows
     * @param  string  $logId
     * @return array<string, true>
     *
     * @throws \InvalidArgumentException
     */
    private function erased(#[\SensitiveParameter] array $keyRows, string $logId): array
    {
        $claimed = [];

        foreach ($keyRows as $id => $keyRow) {
            // A key row names an erasure exactly when it is erased
            if ($keyRow->erasureId === null) {
                continue;
            }

            $claimed[$id] = $keyRow->erasureId;
        }

        if ($claimed === []) {
            return [];
        }

        $destroyed = array_map(fn (JournalRow $erasure): array => $this->destroyedBy($erasure, $logId), $this->keys->erasureRows(array_values(array_unique($claimed))));
        $erased    = [];

        foreach ($claimed as $id => $erasureId) {
            if (!isset($destroyed[$erasureId][$id])) {
                continue;
            }

            $erased[$id] = true;
        }

        return $erased;
    }

    /**
     * The key ids a verified erasure row of this log lists as destroyed; none
     * for any other row.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\JournalRow  $erasure
     * @param  string  $logId
     * @return array<string, true>
     */
    private function destroyedBy(#[\SensitiveParameter] JournalRow $erasure, string $logId): array
    {
        try {
            if ($erasure->kind !== JournalKind::ERASURE || $erasure->logId !== $logId || !$erasure->hasPayloadOfItsDigest() || !$this->journalSigner->verifies($erasure)) {
                return [];
            }

            $listed = $erasure->payloadMap()[self::DESTROYED] ?? null;
        } catch (\JsonException|\UnexpectedValueException|UnknownKeyException) {
            // An unreadable or unverifiable row proves no erasure
            return [];
        }

        return is_array($listed) ? self::keyIdsIn($listed) : [];
    }

    /**
     * The data key of each key row that holds one, by id; a key that fails to
     * unwrap or has the wrong length is left out.
     *
     * @param  array<string, \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow>  $keyRows
     * @return array<string, string>
     */
    private function unwrapped(#[\SensitiveParameter] array $keyRows): array
    {
        $dataKeys = [];

        foreach ($keyRows as $id => $keyRow) {
            if ($keyRow->wrappedKey === null || $keyRow->wrapKeyId === null) {
                continue;
            }

            try {
                $dataKey = $this->wrapper->unwrap($keyRow->wrappedKey, $keyRow->wrapKeyId, $keyRow->wrapContext());
            } catch (\Throwable) {
                // Unreadable either way, and what was thrown could name the key
                continue;
            }

            if (strlen($dataKey) !== FieldCipher::DATA_KEY_BYTES) {
                continue;
            }

            $dataKeys[$id] = $dataKey;
        }

        return $dataKeys;
    }

    /**
     * The field opened and revealed as its typed value, or `unreadable` when it
     * does not open or decode.
     *
     * @param  \SineMacula\Laravel\AuditLog\Privacy\EncryptedField  $field
     * @param  string  $dataKey
     * @param  string  $logId
     * @return \SineMacula\Laravel\AuditLog\Privacy\FieldReading
     */
    private static function opened(#[\SensitiveParameter] EncryptedField $field, #[\SensitiveParameter] string $dataKey, string $logId): FieldReading
    {
        try {
            $plaintext = FieldCipher::open($dataKey, $field->keyReference, $field->version, $field->ciphertext, $field->entryId, $field->segments, $logId);

            return FieldReading::revealed(TypedPlaintext::decode($plaintext));
        } catch (\UnexpectedValueException) {
            // A moved, altered or foreign envelope fails authentication
            return FieldReading::sealed(FieldState::UNREADABLE);
        }
    }

    /**
     * The string `key_id` of each map in a destroyed list.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $listed
     * @return array<string, true>
     */
    private static function keyIdsIn(array $listed): array
    {
        $ids = [];

        foreach ($listed as $entry) {
            $id = is_array($entry) ? ($entry[self::KEY_ID] ?? null) : null;

            if (!is_string($id)) {
                continue;
            }

            $ids[$id] = true;
        }

        return $ids;
    }
}
