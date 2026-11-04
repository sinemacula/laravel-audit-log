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
 * The field reader that opens what the package's encrypter sealed: each field
 * of a page under its owner's key, read from the key store, as its typed value,
 * `erased` once a verified erasure destroyed the key, or `unreadable`.
 *
 * A page's keys are read by id in one statement on the storage connection's
 * writer, so a replica lagging an erasure never hands back a key the erasure
 * revoked, and each key row's signature is verified before anything it holds is
 * believed. A key is `erased` only when the erasure row its `erasure_id` names,
 * read by id from the journal in one more statement on the writer and only when
 * the page holds an erased key, is an `erasure` of this log whose payload is
 * its digest's and whose signature verifies, and lists the key as destroyed.
 * Every other field is `unreadable` when its key is unknown, names no canonical
 * id, fails its signature or names a signing key the ring does not hold, is
 * erased without such a row, or fails to unwrap; and when its envelope fails to
 * open, which it does anywhere but the entry, the path and the log it was
 * sealed for, or holds a plaintext that does not decode. Any other field
 * reveals its typed value.
 *
 * Nothing is kept between pages: the key rows, data keys and field keys of a
 * page live in the call that reads it, so the next page reads the key store
 * again and sees an erasure that committed in between. A field shown before an
 * erasure cannot be recalled.
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

        /** The settings the log id every envelope and erasure row is bound to is read from. */
        private SealSettings $settings,
    ) {}

    /**
     * Each field, in the order given and as many: its typed value revealed,
     * `erased` for a key a verified erasure destroyed, and `unreadable`
     * otherwise.
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
     * The key rows whose signature verifies under the signing key each names;
     * one that does not, or names a key the ring does not hold, is left out,
     * and its fields read as unknown.
     *
     * @param  array<string, \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow>  $keyRows
     * @return array<string, \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow>
     */
    private function authenticated(#[\SensitiveParameter] array $keyRows): array
    {
        return array_filter($keyRows, $this->verifies(...));
    }

    /**
     * Whether the key row's signature verifies under the signing key it names;
     * a malformed signature and a key the ring does not hold do not.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow  $keyRow
     * @return bool
     */
    private function verifies(#[\SensitiveParameter] SubjectKeyRow $keyRow): bool
    {
        try {
            return $this->keySigner->verifies($keyRow);
        } catch (\UnexpectedValueException|UnknownKeyException) {
            // A row that cannot be judged is not authenticated, so nothing it
            // holds decides how a field is shown
            return false;
        }
    }

    /**
     * The ids of the erased keys a verified erasure row lists as destroyed,
     * each erased key's row read by the id it names in one read of the journal,
     * made only when the page holds an erased key.
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
     * The ids of the keys the journal row lists as destroyed, when it is an
     * erasure of this log whose payload is its digest's and whose signature
     * verifies; none for any other row.
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
            // A row that cannot be read or judged proves no erasure, as a
            // missing one proves none
            return [];
        }

        return is_array($listed) ? self::keyIdsIn($listed) : [];
    }

    /**
     * The data key of each key row that holds one, by id, unwrapped under the
     * wrapping key it names and bound to its row; a key that fails to unwrap,
     * or unwraps to anything but a data key's length, is left out, and its
     * fields read as unknown.
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
                // Any failure to unwrap, a substituted or moved wrapped key, an
                // unknown wrapping key or the wrapper's own, leaves the key's
                // fields unreadable, and what was thrown could name the key
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
     * The field opened under the data key at its entry, its path and the log,
     * and revealed as its typed value; `unreadable` when it does not open or
     * its plaintext does not decode.
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
            // An envelope moved, altered or sealed under another key fails its
            // authentication, and nothing of it is shown
            return FieldReading::sealed(FieldState::UNREADABLE);
        }
    }

    /**
     * The key ids a destroyed list names, each listed as a map with a string
     * `key_id`; anything else in the list names none.
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
