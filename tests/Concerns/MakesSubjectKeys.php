<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Database\Connection;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Contracts\KeyWrapper;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\Enums\KeyState;
use SineMacula\Laravel\AuditLog\Integrity\Enums\MarkerTransition;
use SineMacula\Laravel\AuditLog\Integrity\JournalRow;
use SineMacula\Laravel\AuditLog\Integrity\OwnerFingerprint;
use SineMacula\Laravel\AuditLog\Integrity\SealSettings;
use SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow;
use SineMacula\Laravel\AuditLog\Integrity\SubjectKeySigner;
use SineMacula\Laravel\AuditLog\Keys\KeyCreator;
use SineMacula\Laravel\AuditLog\Keys\KeyStore;
use SineMacula\Laravel\AuditLog\Keys\KeyUnit;
use SineMacula\Laravel\AuditLog\Keys\LocalKeyWrapper;
use SineMacula\Laravel\AuditLog\Keys\OwnerMarker;
use SineMacula\Laravel\AuditLog\Keys\OwnerMarkers;
use SineMacula\Laravel\AuditLog\Privacy\FieldCipher;
use SineMacula\Laravel\AuditLog\Privacy\TypedPlaintext;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Support\StoredTime;

/**
 * Makes owners' keys, envelopes and erasures as the package does, without the
 * encrypter or the eraser, on the storage connection at the container's clock.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait MakesSubjectKeys
{
    use WritesTheJournal;

    /** @var string The category every key is made in, unless a test gives another. */
    protected const string KEY_CATEGORY = 'default';

    /**
     * The container's key creator, the package's own key wrapper bound first
     * when no wrapper is.
     *
     * @return \SineMacula\Laravel\AuditLog\Keys\KeyCreator
     */
    protected function keyCreator(): KeyCreator
    {
        $this->keyWrapper();

        return app(KeyCreator::class);
    }

    /**
     * The container's key wrapper, the package's own bound first when none is.
     *
     * @return \SineMacula\Laravel\AuditLog\Contracts\KeyWrapper
     */
    protected function keyWrapper(): KeyWrapper
    {
        app()->bindIf(KeyWrapper::class, LocalKeyWrapper::class);

        $wrapper = app(KeyWrapper::class);

        self::assertInstanceOf(KeyWrapper::class, $wrapper);

        return $wrapper;
    }

    /**
     * The unit's live key and its data key, made through the key creator, or
     * the one it already has; a test fails when none is given, as for an erased
     * owner.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $tenant
     * @param  string  $category
     * @return array{0: \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow, 1: string}
     */
    protected function makeSubjectKey(Reference $owner, ?Reference $tenant = null, string $category = self::KEY_CATEGORY): array
    {
        $made = $this->keyCreator()->create(new KeyUnit($owner, $tenant, $category));

        self::assertNotNull($made, 'No key was made for the unit.');

        return $made;
    }

    /**
     * A live key row of the unit at the generation, its data key wrapped by the
     * container's wrapper and the row signed, but not stored.
     *
     * @param  \SineMacula\Laravel\AuditLog\Keys\KeyUnit  $unit
     * @param  int  $generation
     * @param  string  $dataKey
     * @param  ?string  $id
     * @return \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow
     */
    protected function signedSubjectKey(KeyUnit $unit, int $generation, string $dataKey, ?string $id = null): SubjectKeyRow
    {
        $wrapper = $this->keyWrapper();
        $now     = app(Clock::class)->now();
        $id ??= Str::uuid7($now)->toString();
        $wrapKeyId = $wrapper->currentKeyId();
        $wrapped   = $wrapper->wrap($dataKey, $wrapKeyId, SubjectKeyRow::wrapContextOf($id, $unit->digest(), $generation, $wrapKeyId));
        $draft     = SubjectKeyRow::draft($id, $unit->owner, $unit->tenant, $unit->category, $generation, $wrapped, $wrapKeyId, StoredTime::format($now));

        return app(SubjectKeySigner::class)->sign($draft);
    }

    /**
     * Store the key row as it is, on the storage connection.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow  $keyRow
     * @return void
     */
    protected function insertSubjectKey(SubjectKeyRow $keyRow): void
    {
        $this->keyConnection()->table(KeyTables::subjectKeysTable())->insert($keyRow->toRow());
    }

    /**
     * The value sealed under the data key as an envelope naming the key, at the
     * entry and the path, in the configured log, as the package's encrypter
     * seals one.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $dataKey
     * @param  string  $keyId
     * @param  mixed  $value
     * @param  string  $entryId
     * @param  non-empty-list<int|string>  $path
     * @return array{v: int, k: string, c: string}
     */
    protected function sealEnvelope(string $dataKey, string $keyId, mixed $value, string $entryId, array $path): array
    {
        $plaintext = TypedPlaintext::encode($value);

        self::assertNotNull($plaintext, 'The value is too large to seal.');

        return FieldCipher::seal($dataKey, $keyId, $plaintext, $entryId, $path, app(SealSettings::class)->logId());
    }

    /**
     * Erase the owner by hand, as an erasure commits it: an `erasure` row
     * appended to the journal listing every live or superseded key of the owner
     * as destroyed, but those kept with their reasons, those keys tombstoned
     * with the row's id, and an `erased` marker at the floor, the largest of
     * the owner's previous floor and every generation of its keys.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @param  array<string, list<string>>  $kept
     * @param  bool  $partial
     * @return \SineMacula\Laravel\AuditLog\Integrity\JournalRow
     */
    protected function eraseByHand(Reference $owner, array $kept = [], bool $partial = false): JournalRow
    {
        $connection = $this->keyConnection();
        $keys       = app(KeyStore::class)->ofOwner($connection, $owner);
        $previous   = app(OwnerMarkers::class)->latest($connection, $owner)->generationFloor ?? 0;
        $floor      = max([$previous, ...array_map(static fn (SubjectKeyRow $key): int => $key->generation, $keys)]);
        $destroyed  = array_values(array_filter($keys, static fn (SubjectKeyRow $key): bool => $key->state->holdsAKey() && !array_key_exists($key->id, $kept)));
        $ids        = array_map(static fn (SubjectKeyRow $key): string => $key->id, $destroyed);

        [$fingerprintKey, $fingerprint] = app(OwnerFingerprint::class)->of($owner);

        $row = $this->journalRow(JournalKind::ERASURE, [
            'owner_fingerprint' => $fingerprint,
            'fingerprint_key'   => $fingerprintKey,
            'generation_floor'  => $floor,
            'partial'           => $partial,
            'pending_accepted'  => false,
            'pending_rows'      => 0,
            'destroyed'         => array_map(self::destroyedEntry(...), $destroyed),
            'kept'              => self::keptEntries($keys, $kept),
            'entries_affected'  => $ids === [] ? 0 : $connection->table(KeyTables::keyUsesTable())->whereIn('key_id', $ids)->count(),
        ]);

        if ($ids !== []) {
            $connection->table(KeyTables::subjectKeysTable())->whereIn('id', $ids)->update([
                'state'       => KeyState::ERASED->value,
                'wrapped_key' => null,
                'erasure_id'  => $row->id,
            ]);
        }

        $this->insertMarker($row, $owner, MarkerTransition::ERASED, $floor);

        return $row;
    }

    /**
     * Reinstate the owner by hand, as a reinstatement commits it: a `reinstate`
     * row appended to the journal and a `reinstated` marker at the floor of the
     * owner's latest marker.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @return \SineMacula\Laravel\AuditLog\Integrity\JournalRow
     */
    protected function reinstateByHand(Reference $owner): JournalRow
    {
        $floor = app(OwnerMarkers::class)->latest($this->keyConnection(), $owner)->generationFloor ?? 0;

        [$fingerprintKey, $fingerprint] = app(OwnerFingerprint::class)->of($owner);

        $row = $this->journalRow(JournalKind::REINSTATE, ['owner_fingerprint' => $fingerprint, 'fingerprint_key' => $fingerprintKey, 'generation_floor' => $floor]);

        $this->insertMarker($row, $owner, MarkerTransition::REINSTATED, $floor);

        return $row;
    }

    /**
     * Every stored key row, by id, as the stored rows.
     *
     * @return array<string, \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow>
     */
    protected function storedSubjectKeys(): array
    {
        $keys = [];

        foreach ($this->keyConnection()->table(KeyTables::subjectKeysTable())->orderBy('id')->get() as $stored) {
            $keyRow = SubjectKeyRow::fromRow((array) $stored);

            $keys[$keyRow->id] = $keyRow;
        }

        return $keys;
    }

    /**
     * The storage connection, on which every key table lives.
     *
     * @return \Illuminate\Database\Connection
     */
    protected function keyConnection(): Connection
    {
        return DB::connection(StorageConnection::name());
    }

    /**
     * Insert the owner's marker of the journal row, at the floor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\JournalRow  $row
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\MarkerTransition  $transition
     * @param  int  $floor
     * @return void
     */
    private function insertMarker(JournalRow $row, Reference $owner, MarkerTransition $transition, int $floor): void
    {
        app(OwnerMarkers::class)->insert($this->keyConnection(), new OwnerMarker($row->id, $owner, $transition, $floor, $row->sequence, $row->occurredAt));
    }

    /**
     * What an erasure row lists of a key it destroyed: its id, unit and
     * generation, and its state, HMAC, wrapped key's digest and wrapping key
     * before, and its state after.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow  $key
     * @return array{key_id: string, unit: string, generation: int, before: array{state: string, hmac: string, wrapped_digest: ?string, wrap_key_id: ?string}, after: array{state: string}}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private static function destroyedEntry(SubjectKeyRow $key): array
    {
        return [
            'key_id'     => $key->id,
            'unit'       => $key->unit,
            'generation' => $key->generation,
            'before'     => ['state' => $key->state->value, 'hmac' => $key->hmac, 'wrapped_digest' => $key->wrappedDigest(), 'wrap_key_id' => $key->wrapKeyId],
            'after'      => ['state' => KeyState::ERASED->value],
        ];
    }

    /**
     * What an erasure row lists of the keys it kept, sorted by id: each one's
     * id, unit and generation, and the reasons it was kept, sorted.
     *
     * @param  list<\SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow>  $keys
     * @param  array<string, list<string>>  $kept
     * @return list<array{key_id: string, unit: string, generation: int, reasons: list<string>}>
     */
    private static function keptEntries(array $keys, array $kept): array
    {
        $entries = [];

        foreach ($keys as $key) {
            if (!array_key_exists($key->id, $kept)) {
                continue;
            }

            $reasons = $kept[$key->id];

            sort($reasons, SORT_STRING);

            $entries[] = ['key_id' => $key->id, 'unit' => $key->unit, 'generation' => $key->generation, 'reasons' => $reasons];
        }

        return $entries;
    }
}
