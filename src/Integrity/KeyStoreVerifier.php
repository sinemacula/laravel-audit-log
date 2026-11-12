<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Query\Builder;
use SineMacula\Laravel\AuditLog\Config\IntegerSetting;
use SineMacula\Laravel\AuditLog\Contracts\KeyWrapper;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\Enums\KeyState;
use SineMacula\Laravel\AuditLog\Keys\KeyStore;
use SineMacula\Laravel\AuditLog\Keys\UnknownWrappingKeyException;
use SineMacula\Laravel\AuditLog\Privacy\FieldCipher;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * Verifies the owners' key store on a run of the whole log: each key row
 * against its signature, its wrapping and the journal's believed erasures,
 * reinstatements and rewraps, and each key use against its key. Every read is
 * on the writer, so replica lag behind an erasure never reads as a restored
 * key.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class KeyStoreVerifier
{
    /** @var int Key rows, and keys named by a key use and no key row, read by one statement. */
    public const int PAGE = 1000;

    /** @var int Erasure, reinstatement and rewrap rows read by one statement, each with its payload. */
    public const int JOURNAL_PAGE = 100;

    /** @var list<string> The journal kinds the fold reads: an owner's transitions and its keys' rewraps. */
    private const array TRANSITIONS = [JournalKind::ERASURE->value, JournalKind::REINSTATE->value, JournalKind::REWRAP->value];

    /** @var string The least canonical UUID: the leading bound of the first page of key uses. */
    private const string LEAST_UUID = '00000000-0000-0000-0000-000000000000';

    /** @var string The payload key an erasure row lists the keys it destroyed under. */
    private const string DESTROYED = 'destroyed';

    /** @var string The payload key an erasure row lists the keys it kept under. */
    private const string KEPT = 'kept';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Database\DatabaseManager  $database
     * @param  \SineMacula\Laravel\AuditLog\Keys\KeyStore  $keys
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SubjectKeySigner  $keySigner
     * @param  \SineMacula\Laravel\AuditLog\Integrity\JournalSigner  $journalSigner
     * @param  \SineMacula\Laravel\AuditLog\Integrity\OwnerFingerprint  $fingerprints
     * @param  \SineMacula\Laravel\AuditLog\Contracts\KeyWrapper  $wrapper
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealSettings  $settings
     */
    public function __construct(

        /** The connections the storage connection is resolved from on every run. */
        private DatabaseManager $database,

        /** Where the keys are read a page at a time, and an erased key's erasure row by id. */
        private KeyStore $keys,

        /** Verifies each key row's signature. */
        private SubjectKeySigner $keySigner,

        /** Verifies each erasure and reinstatement row before it is believed. */
        private JournalSigner $journalSigner,

        /** Fingerprints each key's owner under each key the journal's rows were taken under. */
        private OwnerFingerprint $fingerprints,

        /** Unwraps each key's data key, bound to its row, to confirm its wrapping. */
        private KeyWrapper $wrapper,

        /** The settings the log id every believed journal row must name is read from. */
        private SealSettings $settings,
    ) {}

    /**
     * Verify the key store into the tally and summarise it; skipped when the
     * package's key store is not in use, and the wrapper is never called
     * without unwrapping.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\VerificationTally  $tally
     * @param  bool  $packageKeys
     * @param  bool  $unwrap
     * @return \SineMacula\Laravel\AuditLog\Integrity\KeyStoreSummary
     *
     * @throws \InvalidArgumentException
     */
    public function verify(VerificationTally $tally, bool $packageKeys, bool $unwrap = true): KeyStoreSummary
    {
        if (!$packageKeys) {
            return KeyStoreSummary::skipped();
        }

        $connection      = $this->database->connection(StorageConnection::name());
        $found           = [];
        $commitments     = new RewrapCommitments;
        $owners          = $this->fold($connection, $commitments);
        [$keys, $erased] = $this->checkKeys($connection, [$owners, $commitments], $unwrap, $found);

        self::checkUses($connection, $found);

        return new KeyStoreSummary($keys, $erased, self::report($found, $tally));
    }

    /**
     * Fold the believed erasures and reinstatements per fingerprint key and
     * owner fingerprint, and each believed rewrap into the commitments, a page
     * at a time.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  \SineMacula\Laravel\AuditLog\Integrity\RewrapCommitments  $commitments
     * @return array<int|string, array<string, array{erased: bool, sequence: int, floor: int, kept: array<string, true>, keptAt: int}>>
     *
     * @throws \InvalidArgumentException
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function fold(Connection $connection, RewrapCommitments $commitments): array
    {
        $owners = [];
        $logId  = $this->settings->logId();
        $after  = 0;

        do {
            $page = $connection->table(LifecycleTables::journalTable())
                ->useWritePdo()
                ->whereIn('kind', self::TRANSITIONS)
                ->where('sequence', '>', $after)
                ->orderBy('sequence')
                ->limit(self::JOURNAL_PAGE)
                ->get()
                ->all();

            $full  = count($page) === self::JOURNAL_PAGE;
            $after = $page        === [] ? null : IntegerSetting::parse($page[array_key_last($page)]->sequence ?? null);

            foreach ($page as $stored) {
                $journalRow = $this->believed((array) $stored, $logId);

                if ($journalRow?->kind === JournalKind::REWRAP) {
                    $commitments->fold($journalRow);

                    continue;
                }

                self::foldInto($owners, $journalRow);
            }

            // Released before the next page is read, so no two are ever held
            unset($page);
        } while ($full && $after !== null);

        return $owners;
    }

    /**
     * The stored journal row, when it is believed, and `null` when it cannot be
     * read or is not believed: the journal's own verification reports it, and
     * it proves nothing of an owner.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $stored
     * @param  string  $logId
     * @return ?\SineMacula\Laravel\AuditLog\Integrity\JournalRow
     */
    private function believed(#[\SensitiveParameter] array $stored, string $logId): ?JournalRow
    {
        try {
            $journalRow = JournalRow::fromRow($stored, true);
        } catch (\UnexpectedValueException) {
            return null;
        }

        return $this->isAuthentic($journalRow, $logId) ? $journalRow : null;
    }

    /**
     * Whether the journal row is believed: of this log, its payload the text
     * its digest was taken of, and its signature its own under a key the ring
     * holds.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\JournalRow  $journalRow
     * @param  string  $logId
     * @return bool
     */
    private function isAuthentic(#[\SensitiveParameter] JournalRow $journalRow, string $logId): bool
    {
        try {
            return $journalRow->logId === $logId && $journalRow->hasPayloadOfItsDigest() && $this->journalSigner->verifies($journalRow);
        } catch (\UnexpectedValueException|UnknownKeyException) {
            // A row that cannot be judged is not believed
            return false;
        }
    }

    /**
     * Check every key, a page at a time by id, noting each finding at its id;
     * returns how many keys were read and how many hold no key.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  array{0: array<int|string, array<string, array{erased: bool, sequence: int, floor: int, kept: array<string, true>, keptAt: int}>>, 1: \SineMacula\Laravel\AuditLog\Integrity\RewrapCommitments}  $journal
     * @param  bool  $unwrap
     * @param  array<string, array{0: ?string, 1: int}>  $found
     * @return array{0: int, 1: int}
     *
     * @throws \InvalidArgumentException
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function checkKeys(Connection $connection, #[\SensitiveParameter] array $journal, bool $unwrap, array &$found): array
    {
        $counts = [0, 0];
        $after  = null;

        do {
            $page   = $this->keys->page($connection, $after, self::PAGE);
            $listed = $this->listed($page);

            foreach ($page as $stored) {
                $id        = SegmentRows::textOf($stored['id'] ?? null);
                $destroyed = self::isDestroyed($stored);
                $counts    = [$counts[0] + 1, $counts[1] + (int) $destroyed];

                foreach ($this->findingsOf($stored, $destroyed, isset($listed[(string) $id]), $journal, $unwrap) as $finding) {
                    $found[$finding->value] ??= [$id, 0];
                    $found[$finding->value][1]++;
                }
            }

            $after = $page === [] ? null : SegmentRows::textOf($page[array_key_last($page)]['id'] ?? null);
        } while (count($page) === self::PAGE && $after !== null);

        return $counts;
    }

    /**
     * The ids of the page's keys that hold no key and that their verified
     * erasure row lists as destroyed, the rows read by id in one statement.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  list<array<string, mixed>>  $page
     * @return array<string, true>
     *
     * @throws \InvalidArgumentException
     */
    private function listed(#[\SensitiveParameter] array $page): array
    {
        $claims = [];

        foreach ($page as $stored) {
            $id        = SegmentRows::textOf($stored['id'] ?? null);
            $erasureId = SegmentRows::textOf($stored['erasure_id'] ?? null);

            if ($id === null || $erasureId === null || !self::isDestroyed($stored)) {
                continue;
            }

            $claims[$erasureId][] = $id;
        }

        $listed = [];
        $logId  = $this->settings->logId();

        foreach ($this->keys->erasureRows(array_map(strval(...), array_keys($claims))) as $erasureId => $erasure) {
            $destroyed = $this->destroyedBy($erasure, $logId);

            foreach (array_filter($claims[$erasureId] ?? [], static fn (string $id): bool => isset($destroyed[$id])) as $id) {
                $listed[$id] = true;
            }
        }

        return $listed;
    }

    /**
     * The ids of the keys the journal row lists as destroyed, when it is a
     * believed erasure; none for any other row.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\JournalRow  $erasure
     * @param  string  $logId
     * @return array<string, true>
     */
    private function destroyedBy(#[\SensitiveParameter] JournalRow $erasure, string $logId): array
    {
        if ($erasure->kind !== JournalKind::ERASURE || !$this->isAuthentic($erasure, $logId)) {
            return [];
        }

        try {
            return self::keyIdsIn(($erasure->payloadMap() ?? [])[self::DESTROYED] ?? null);
        } catch (\JsonException) {
            // A payload that cannot be read lists nothing
            return [];
        }
    }

    /**
     * The findings of one stored key row, each once; a row that is not the one
     * signed, or holds no key, says nothing more.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $stored
     * @param  bool  $destroyed
     * @param  bool  $listed
     * @param  array{0: array<int|string, array<string, array{erased: bool, sequence: int, floor: int, kept: array<string, true>, keptAt: int}>>, 1: \SineMacula\Laravel\AuditLog\Integrity\RewrapCommitments}  $journal
     * @param  bool  $unwrap
     * @return list<\SineMacula\Laravel\AuditLog\Integrity\Enums\Finding>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function findingsOf(#[\SensitiveParameter] array $stored, bool $destroyed, bool $listed, #[\SensitiveParameter] array $journal, bool $unwrap): array
    {
        $lost = $destroyed && !$listed ? Finding::KEY_DESTROYED_UNJOURNALLED : null;

        try {
            $keyRow = SubjectKeyRow::fromRow($stored);
        } catch (\UnexpectedValueException) {
            // Unreadable: lost when destroyed unjournalled, else substituted
            return [$lost ?? Finding::KEY_SUBSTITUTED];
        }

        $signature = $this->signatureFinding($keyRow);

        $found = $signature !== null || $destroyed
            ? [$signature ?? $lost]
            : [$this->wrapFinding($keyRow, $unwrap), $this->restoredFinding($keyRow, $journal[0]), $journal[1]->findingOf($keyRow)];

        // A key found substituted twice is counted once
        $values = array_unique(array_map(static fn (Finding $finding): string => $finding->value, array_filter($found)));

        return array_values(array_map(Finding::from(...), $values));
    }

    /**
     * The finding the key row's signature gives, or `null` when it is the row's
     * own under the key it names: one that does not match, or is malformed, is
     * `key_substituted`, and one under a key the ring does not hold
     * `key_unverifiable`.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow  $keyRow
     * @return ?\SineMacula\Laravel\AuditLog\Integrity\Enums\Finding
     */
    private function signatureFinding(#[\SensitiveParameter] SubjectKeyRow $keyRow): ?Finding
    {
        try {
            return $this->keySigner->verifies($keyRow) ? null : Finding::KEY_SUBSTITUTED;
        } catch (UnknownKeyException) {
            return Finding::KEY_UNVERIFIABLE;
        } catch (\UnexpectedValueException) {
            return Finding::KEY_SUBSTITUTED;
        }
    }

    /**
     * The finding the key row's wrapping gives, or `null` when it unwraps to a
     * data key or no unwrapping is asked for; the data key is dropped once its
     * length is known.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow  $keyRow
     * @param  bool  $unwrap
     * @return ?\SineMacula\Laravel\AuditLog\Integrity\Enums\Finding
     */
    private function wrapFinding(#[\SensitiveParameter] SubjectKeyRow $keyRow, bool $unwrap): ?Finding
    {
        if (!$unwrap || $keyRow->wrappedKey === null || $keyRow->wrapKeyId === null) {
            return null;
        }

        try {
            $length  = strlen($this->wrapper->unwrap($keyRow->wrappedKey, $keyRow->wrapKeyId, $keyRow->wrapContext()));
            $finding = $length === FieldCipher::DATA_KEY_BYTES ? null : Finding::KEY_SUBSTITUTED;
        } catch (UnknownWrappingKeyException) {
            $finding = Finding::KEY_UNVERIFIABLE;
        } catch (\Throwable) {
            // Not this row's wrapped key; the exception could name the key
            $finding = Finding::KEY_SUBSTITUTED;
        }

        return $finding;
    }

    /**
     * The finding the key's owner's journal gives a key that holds a key, or
     * `null` when it may: `key_restored` when the owner's latest transition is
     * an erasure that did not keep it, or a reinstatement while its generation
     * is at or below the floor and the erasure before it did not keep it.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow  $keyRow
     * @param  array<int|string, array<string, array{erased: bool, sequence: int, floor: int, kept: array<string, true>, keptAt: int}>>  $owners
     * @return ?\SineMacula\Laravel\AuditLog\Integrity\Enums\Finding
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function restoredFinding(#[\SensitiveParameter] SubjectKeyRow $keyRow, #[\SensitiveParameter] array $owners): ?Finding
    {
        $state = $owners === [] ? null : $this->stateOf($keyRow, $owners);

        if ($state === null || isset($state['kept'][$keyRow->id])) {
            return null;
        }

        return $state['erased'] || $keyRow->generation <= $state['floor'] ? Finding::KEY_RESTORED : null;
    }

    /**
     * The fold's state of the key's owner, or `null` when the journal holds no
     * transition of it: its latest transition and floor under whichever key its
     * fingerprints were taken, with the keys the latest erasure kept.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow  $keyRow
     * @param  array<int|string, array<string, array{erased: bool, sequence: int, floor: int, kept: array<string, true>, keptAt: int}>>  $owners
     * @return ?array{erased: bool, floor: int, kept: array<string, true>}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function stateOf(#[\SensitiveParameter] SubjectKeyRow $keyRow, #[\SensitiveParameter] array $owners): ?array
    {
        try {
            $owner = Reference::of($keyRow->ownerType, $keyRow->ownerId);
        } catch (\InvalidArgumentException) {
            // A verified row names a well-formed owner, so this one has none
            return null;
        }

        $states = [];

        foreach ($owners as $fingerprintKey => $fingerprints) {
            $states[] = $fingerprints[$this->fingerprintUnder((string) $fingerprintKey, $owner)] ?? null;
        }

        $states = array_values(array_filter($states));

        if ($states === []) {
            return null;
        }

        $latest = $states[0];
        $erased = $states[0];

        foreach ($states as $state) {
            $latest = $state['sequence'] > $latest['sequence'] ? $state : $latest;
            $erased = $state['keptAt']   > $erased['keptAt'] ? $state : $erased;
        }

        return ['erased' => $latest['erased'], 'floor' => $latest['floor'], 'kept' => $erased['kept']];
    }

    /**
     * The owner's fingerprint under the ring's key with the id, or an empty
     * string, which no fingerprint is, when the ring does not hold it.
     *
     * @param  string  $fingerprintKey
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @return string
     */
    private function fingerprintUnder(string $fingerprintKey, #[\SensitiveParameter] Reference $owner): string
    {
        try {
            return $this->fingerprints->under($fingerprintKey, $owner);
        } catch (UnknownKeyException) {
            // No row under a key the ring does not hold was ever believed
            return '';
        }
    }

    /**
     * Fold the believed row, if any, into its owner's state: an erasure sets
     * the latest transition, the floor and the keys it kept, and a
     * reinstatement the latest transition and the floor, keeping what the
     * erasure before it kept.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  array<int|string, array<string, array{erased: bool, sequence: int, floor: int, kept: array<string, true>, keptAt: int}>>  $owners
     * @param  ?\SineMacula\Laravel\AuditLog\Integrity\JournalRow  $journalRow
     * @return void
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private static function foldInto(#[\SensitiveParameter] array &$owners, #[\SensitiveParameter] ?JournalRow $journalRow): void
    {
        $transition = $journalRow === null ? null : self::transitionOf($journalRow);

        if ($journalRow === null || $transition === null) {
            return;
        }

        [$fingerprintKey, $fingerprint, $floor, $kept] = $transition;

        $previous = $owners[$fingerprintKey][$fingerprint] ?? ['kept' => [], 'keptAt' => 0];

        $owners[$fingerprintKey][$fingerprint] = [
            'erased'   => $kept !== null,
            'sequence' => $journalRow->sequence,
            'floor'    => $floor,
            'kept'     => $kept ?? $previous['kept'],
            'keptAt'   => $kept === null ? $previous['keptAt'] : $journalRow->sequence,
        ];
    }

    /**
     * What the believed row says of its owner: the key its fingerprint was
     * taken under, the fingerprint and the floor, and, for an erasure, the keys
     * it kept; or `null` when its payload does not name them.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\JournalRow  $journalRow
     * @return ?array{0: string, 1: string, 2: int, 3: ?array<string, true>}
     */
    private static function transitionOf(#[\SensitiveParameter] JournalRow $journalRow): ?array
    {
        try {
            $payload = $journalRow->payloadMap() ?? [];
        } catch (\JsonException) {
            // A payload that cannot be read names no owner
            return null;
        }

        $fingerprintKey = $payload['fingerprint_key']   ?? null;
        $fingerprint    = $payload['owner_fingerprint'] ?? null;
        $floor          = $payload['generation_floor']  ?? null;

        if (!is_string($fingerprintKey) || !is_string($fingerprint) || !is_int($floor)) {
            return null;
        }

        return [$fingerprintKey, $fingerprint, $floor, $journalRow->kind === JournalKind::ERASURE ? self::keyIdsIn($payload[self::KEPT] ?? null) : null];
    }

    /**
     * The key ids a payload's list names, each listed as a map with a string
     * `key_id`; anything else names none.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $listed
     * @return array<string, true>
     */
    private static function keyIdsIn(mixed $listed): array
    {
        $ids = [];

        foreach (is_array($listed) ? $listed : [] as $entry) {
            $id = is_array($entry) ? ($entry['key_id'] ?? null) : null;

            if (!is_string($id)) {
                continue;
            }

            $ids[$id] = true;
        }

        return $ids;
    }

    /**
     * Whether the stored key row holds no key: it is erased, or its wrapped key
     * is gone, whatever else it says.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $stored
     * @return bool
     */
    private static function isDestroyed(#[\SensitiveParameter] array $stored): bool
    {
        return ($stored['wrapped_key'] ?? null) === null || ($stored['state'] ?? null) === KeyState::ERASED->value;
    }

    /**
     * Note each key named by a key use and no key row as `key_missing`, a page
     * at a time in key order, so each page seeks the key uses' primary key.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  array<string, array{0: ?string, 1: int}>  $found
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function checkUses(Connection $connection, array &$found): void
    {
        $operator = '>=';
        $after    = self::LEAST_UUID;

        do {
            $page = $connection->table(KeyTables::keyUsesTable() . ' as u')
                ->useWritePdo()
                ->distinct()
                ->whereNotExists(static function (Builder $keys): void {
                    $keys->selectRaw('1')->from(KeyTables::subjectKeysTable() . ' as k')->whereColumn('k.id', 'u.key_id');
                })
                ->where('u.key_id', $operator, $after)
                ->orderBy('u.key_id')
                ->limit(self::PAGE)
                ->pluck('u.key_id')
                ->all();

            $page = array_values(array_filter($page, is_string(...)));

            foreach ($page as $keyId) {
                $found[Finding::KEY_MISSING->value] ??= [$keyId, 0];
                $found[Finding::KEY_MISSING->value][1]++;
            }

            $operator = '>';
            $after    = $page === [] ? $after : $page[array_key_last($page)];
        } while (count($page) === self::PAGE);
    }

    /**
     * Add each finding noted to the tally, in the order of the findings, and
     * return how many times they were found.
     *
     * @param  array<string, array{0: ?string, 1: int}>  $found
     * @param  \SineMacula\Laravel\AuditLog\Integrity\VerificationTally  $tally
     * @return int
     */
    private static function report(array $found, VerificationTally $tally): int
    {
        $count = 0;

        foreach (Finding::cases() as $finding) {
            if (!isset($found[$finding->value])) {
                continue;
            }

            [$firstId, $times] = $found[$finding->value];

            $tally->addFinding(new RunFinding($finding, $firstId, $times));

            $count += $times;
        }

        return $count;
    }
}
