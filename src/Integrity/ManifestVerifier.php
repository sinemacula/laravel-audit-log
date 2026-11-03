<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Contracts\Encryption\StringEncrypter;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Query\Builder;
use SineMacula\Laravel\AuditLog\Config\IntegerSetting;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Records\Manifest;

/**
 * Checks the artifact each verified entry's signed manifest names: that it is
 * stored, under the manifest's artifact id and for that entry, of the bulk
 * kind, counting the members the manifest signed, with its digest, and that its
 * members decrypt to exactly the canonical form the manifest describes: each
 * member once, in canonical order, as many as signed and giving the signed
 * digest.
 *
 * The descriptor is trusted only because its entry verified: a signed
 * descriptor cannot be malformed without the key, so one that is not exactly an
 * artifact id, a digest and a positive count is a mismatch. Entries are checked
 * in batches of `ENTRY_BATCH`, one statement reading the artifacts' columns and
 * the length of their members, and the members of those that match are then
 * read in sub-batches of at most `MEMBERS_BATCH_BYTES` stored bytes, so no
 * statement is made per entry and no read holds more than a bound of members.
 * An artifact the application's keys cannot decrypt cannot be checked; any
 * other difference shows the log was altered. An artifact missing with its
 * entry, both deleted by a prune that committed after the segment was read, is
 * no finding: the run reports the segment as it read it. Every statement reads
 * the writer. Nothing here writes or repairs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ManifestVerifier
{
    /** @var int How many manifest-bearing entries one statement reads the artifacts of. */
    public const int ENTRY_BATCH = 100;

    /** @var int The most stored bytes of members one statement reads, summed over its artifacts: 64 MiB. */
    public const int MEMBERS_BATCH_BYTES = 67108864;

    /** @var list<string> The keys of a descriptor, sorted: exactly these and nothing else. */
    private const array DESCRIPTOR_KEYS = ['artifact_id', 'count', 'digest'];

    /**
     * Constructor.
     *
     * @param  \Illuminate\Database\DatabaseManager  $database
     * @param  \Illuminate\Contracts\Encryption\StringEncrypter  $encrypter
     * @param  int  $membersBatchBytes
     */
    public function __construct(

        /** The connections the storage connection is resolved from on every check. */
        private DatabaseManager $database,

        /** The encrypter that opens each artifact's members, under the application's keys. */
        private StringEncrypter $encrypter,

        /** The most stored bytes of members one statement reads; `MEMBERS_BATCH_BYTES` unless a test lowers it. */
        private int $membersBatchBytes = self::MEMBERS_BATCH_BYTES,
    ) {}

    /**
     * The manifest descriptor of a verified entry row, read from its raw
     * `properties` at `_audit.manifest` as it is stored, or `null` when it
     * holds none. A stored value that is not a JSON object or list is given as
     * an empty one, which is no descriptor, so it is checked and found
     * malformed rather than skipped.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $entry
     * @return ?array<array-key, mixed>
     */
    public function descriptorOf(#[\SensitiveParameter] array $entry): ?array
    {
        $stored     = $entry['properties'] ?? null;
        $properties = is_string($stored) ? json_decode($stored, true) : null;
        $audit      = is_array($properties) ? ($properties['_audit'] ?? null) : null;

        if (!is_array($audit) || !array_key_exists('manifest', $audit)) {
            return null;
        }

        return is_array($audit['manifest']) ? $audit['manifest'] : [];
    }

    /**
     * The findings of the manifests, keyed by the id of the entry that signed
     * each: each finding once, at the earliest entry it was found at, bytewise,
     * in the order of `Enums\Finding`. No manifest costs no statement.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, array<array-key, mixed>>  $manifests
     * @return list<array{0: \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding, 1: ?string}>
     *
     * @throws \InvalidArgumentException
     */
    public function findings(array $manifests): array
    {
        $first = [];

        foreach (array_chunk($manifests, self::ENTRY_BATCH, true) as $batch) {
            foreach ($this->batchFindings($batch) as $entryId => $finding) {
                $first[$finding->value] = self::earliest($first[$finding->value] ?? null, (string) $entryId);
            }
        }

        $found = [];

        foreach (Finding::cases() as $finding) {
            if (!isset($first[$finding->value])) {
                continue;
            }

            $found[] = [$finding, $first[$finding->value]];
        }

        return $found;
    }

    /**
     * The finding of each entry of one batch that has one, by entry id: a
     * malformed descriptor or an entry id that is not a lower-case UUID is a
     * mismatch before any statement, an artifact that is not stored is missing,
     * one whose columns differ from the descriptor is a mismatch, and the
     * members of every other are opened and read.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, array<array-key, mixed>>  $batch
     * @return array<array-key, \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding>
     *
     * @throws \InvalidArgumentException
     */
    private function batchFindings(array $batch): array
    {
        [$descriptors, $findings] = self::partition($batch);

        if ($descriptors === []) {
            return $findings;
        }

        [$byEntry, $byId] = $this->artifactsOf($descriptors);
        $lengths          = [];

        foreach ($descriptors as $entryId => $descriptor) {
            $artifact = $byEntry[$entryId] ?? $byId[$descriptor['artifact_id']] ?? null;
            $finding  = self::columnsFinding($artifact, $entryId, $descriptor);

            if ($finding !== null) {
                $findings[$entryId] = $finding;

                continue;
            }

            $lengths[$entryId] = IntegerSetting::parse($artifact['members_length'] ?? null) ?? 0;
        }

        return $this->withoutPrunedEntries($findings + $this->membersFindings($descriptors, $lengths));
    }

    /**
     * The findings, less each missing artifact whose entry is gone too: the
     * segment read the entry before a prune that has since deleted both
     * committed, so the run reports the segment as it read it, and the next run
     * reads it pruned. An artifact missing beside its entry is missing. Only a
     * missing artifact costs this statement.
     *
     * @param  array<array-key, \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding>  $findings
     * @return array<array-key, \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding>
     *
     * @throws \InvalidArgumentException
     */
    private function withoutPrunedEntries(array $findings): array
    {
        $missing = array_map(strval(...), array_keys($findings, Finding::MANIFEST_MISSING, true));

        if ($missing === []) {
            return $findings;
        }

        $stored = $this->database->connection(StorageConnection::name())
            ->table(EntrySettings::table())
            ->whereIn('id', $missing)
            ->useWritePdo()
            ->pluck('id')
            ->all();

        return array_diff_key($findings, array_flip(array_diff($missing, $stored)));
    }

    /**
     * The stored artifacts of the batch's entries, or of the artifact ids their
     * descriptors name, in one statement on the writer: each one's columns and
     * the length of its members, never the members themselves, by the entry it
     * names and by its own id.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  array<string, array{artifact_id: string, count: int, digest: string}>  $descriptors
     * @return array{0: array<string, array<string, scalar|null>>, 1: array<string, array<string, scalar|null>>}
     *
     * @throws \InvalidArgumentException
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function artifactsOf(array $descriptors): array
    {
        $stored = $this->artifacts()
            ->whereIn('entry_id', array_keys($descriptors))
            ->orWhereIn('id', array_column($descriptors, 'artifact_id'))
            ->select(['id', 'entry_id', 'kind', 'member_count', 'digest'])
            ->selectRaw('length(members) as members_length')
            ->useWritePdo()
            ->get();

        $byEntry = [];
        $byId    = [];

        foreach ($stored as $artifact) {
            /** @var array<string, scalar|null> $columns */
            $columns = (array) $artifact;

            $byEntry[self::textOf($columns['entry_id'] ?? null)] = $columns;
            $byId[self::textOf($columns['id'] ?? null)]          = $columns;
        }

        return [$byEntry, $byId];
    }

    /**
     * The finding of each entry whose artifact's members do not open or are not
     * the canonical form its descriptor describes, by entry id, the members
     * read a sub-batch at a time: as many artifacts as fit the byte bound, and
     * one alone when it is larger than the bound.
     *
     * @param  array<string, array{artifact_id: string, count: int, digest: string}>  $descriptors
     * @param  array<string, int>  $lengths
     * @return array<string, \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding>
     *
     * @throws \InvalidArgumentException
     */
    private function membersFindings(array $descriptors, array $lengths): array
    {
        $findings = [];

        foreach ($this->subBatches($lengths) as $entryIds) {
            $artifactIds = array_map(static fn (string $entryId): string => $descriptors[$entryId]['artifact_id'], $entryIds);
            $members     = $this->membersOf($artifactIds);

            foreach ($entryIds as $entryId) {
                $descriptor = $descriptors[$entryId];
                $finding    = $this->membersFinding($members[$descriptor['artifact_id']] ?? null, $descriptor);

                if ($finding === null) {
                    continue;
                }

                $findings[$entryId] = $finding;
            }
        }

        return $findings;
    }

    /**
     * The entry ids in sub-batches whose summed members lengths are at most the
     * byte bound, in the order given; an artifact larger than the bound is a
     * sub-batch of its own.
     *
     * @param  array<string, int>  $lengths
     * @return list<non-empty-list<string>>
     */
    private function subBatches(array $lengths): array
    {
        $batches = [];
        $current = [];
        $bytes   = 0;

        foreach ($lengths as $entryId => $length) {
            if ($current !== [] && $bytes + $length > $this->membersBatchBytes) {
                $batches[] = $current;
                $current   = [];
                $bytes     = 0;
            }

            $current[] = $entryId;
            $bytes += $length;
        }

        if ($current !== []) {
            $batches[] = $current;
        }

        return $batches;
    }

    /**
     * The stored members of the artifacts, by artifact id, in one statement on
     * the writer.
     *
     * @param  list<string>  $artifactIds
     * @return array<string, scalar|null>
     *
     * @throws \InvalidArgumentException
     */
    private function membersOf(array $artifactIds): array
    {
        /** @var array<string, scalar|null> */
        return $this->artifacts()
            ->whereIn('id', $artifactIds)
            ->useWritePdo()
            ->pluck('members', 'id')
            ->all();
    }

    /**
     * The finding of an artifact's stored members, or `null` when they open
     * under the application's keys to exactly a canonical form of the
     * descriptor's count and digest: an artifact gone since its columns were
     * read is missing, members that do not open are unreadable, and any other
     * plaintext is a mismatch.
     *
     * @param  scalar|null  $members
     * @param  array{artifact_id: string, count: int, digest: string}  $descriptor
     * @return ?\SineMacula\Laravel\AuditLog\Integrity\Enums\Finding
     */
    private function membersFinding(#[\SensitiveParameter] bool|float|int|string|null $members, array $descriptor): ?Finding
    {
        if (!is_string($members)) {
            return $members === null ? Finding::MANIFEST_MISSING : Finding::MANIFEST_UNREADABLE;
        }

        $plaintext = $this->plaintextOf($members);

        if ($plaintext === null) {
            return Finding::MANIFEST_UNREADABLE;
        }

        $read = self::canonicalOf($plaintext);

        return $read !== null && $read['count'] === $descriptor['count'] && $read['digest'] === $descriptor['digest'] ? null : Finding::MANIFEST_MISMATCH;
    }

    /**
     * The stored members decrypted under the application's keys, or `null` when
     * no key opens them.
     *
     * @param  string  $members
     * @return ?string
     */
    private function plaintextOf(#[\SensitiveParameter] string $members): ?string
    {
        try {
            return $this->encrypter->decryptString($members);
        } catch (DecryptException) {
            return null;
        }
    }

    /**
     * A query of the artifacts table on the storage connection.
     *
     * @return \Illuminate\Database\Query\Builder
     *
     * @throws \InvalidArgumentException
     */
    private function artifacts(): Builder
    {
        return $this->database->connection(StorageConnection::name())->table(EntrySettings::artifactsTable());
    }

    /**
     * The batch's well-formed descriptors, by entry id, and a mismatch for each
     * entry whose descriptor is malformed or whose id is not a lower-case UUID,
     * which no statement is made for.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  array<array-key, array<array-key, mixed>>  $batch
     * @return array{0: array<string, array{artifact_id: string, count: int, digest: string}>, 1: array<array-key, \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding>}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private static function partition(array $batch): array
    {
        $descriptors = [];
        $findings    = [];

        foreach ($batch as $entryId => $descriptor) {
            if (!self::isDescriptor($descriptor) || preg_match(SealEnvelope::UUID_PATTERN, (string) $entryId) !== 1) {
                $findings[$entryId] = Finding::MANIFEST_MISMATCH;

                continue;
            }

            $descriptors[(string) $entryId] = $descriptor;
        }

        return [$descriptors, $findings];
    }

    /**
     * The finding of the entry's stored artifact, or `null` when it is the one
     * the entry's descriptor signed: its id, the entry it names, its kind, its
     * count and its digest. No artifact is missing; any difference is a
     * mismatch.
     *
     * @param  ?array<string, scalar|null>  $artifact
     * @param  string  $entryId
     * @param  array{artifact_id: string, count: int, digest: string}  $descriptor
     * @return ?\SineMacula\Laravel\AuditLog\Integrity\Enums\Finding
     */
    private static function columnsFinding(?array $artifact, string $entryId, array $descriptor): ?Finding
    {
        if ($artifact === null) {
            return Finding::MANIFEST_MISSING;
        }

        $stored = [
            $artifact['id']       ?? null,
            $artifact['entry_id'] ?? null,
            $artifact['kind']     ?? null,
            IntegerSetting::parse($artifact['member_count'] ?? null),
            $artifact['digest'] ?? null,
        ];

        $signed = [$descriptor['artifact_id'], $entryId, Manifest::KIND, $descriptor['count'], $descriptor['digest']];

        return $stored === $signed ? null : Finding::MANIFEST_MISMATCH;
    }

    /**
     * The count and digest of a plaintext that is exactly a canonical form, or
     * `null` for any other plaintext.
     *
     * @param  string  $plaintext
     * @return ?array{count: int, digest: string}
     */
    private static function canonicalOf(#[\SensitiveParameter] string $plaintext): ?array
    {
        try {
            return Manifest::readCanonical($plaintext);
        } catch (\JsonException) {
            return null;
        }
    }

    /**
     * Whether the value is exactly a descriptor: an artifact id that is a
     * lower-case UUID, a digest of 64 lower-case hex and a positive integer
     * count, and no other key.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $descriptor
     * @return bool
     *
     * @phpstan-assert-if-true array{artifact_id: string, count: int, digest: string} $descriptor
     */
    private static function isDescriptor(array $descriptor): bool
    {
        $keys   = array_keys($descriptor);
        $id     = $descriptor['artifact_id'] ?? null;
        $digest = $descriptor['digest']      ?? null;
        $count  = $descriptor['count']       ?? null;

        sort($keys);

        if ($keys !== self::DESCRIPTOR_KEYS || !is_string($id) || !is_string($digest) || !is_int($count)) {
            return false;
        }

        return $count >= 1 && preg_match(SealEnvelope::UUID_PATTERN, $id) === 1 && preg_match(SealEnvelope::DIGEST_PATTERN, $digest) === 1;
    }

    /**
     * The earlier, bytewise, of the id kept so far and the id given.
     *
     * @param  ?string  $kept
     * @param  string  $id
     * @return string
     */
    private static function earliest(?string $kept, string $id): string
    {
        return $kept === null || strcmp($id, $kept) < 0 ? $id : $kept;
    }

    /**
     * The stored value when it is a string, and an empty string otherwise.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @return string
     */
    private static function textOf(mixed $value): string
    {
        return is_string($value) ? $value : '';
    }
}
