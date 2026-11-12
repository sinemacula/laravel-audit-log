<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Database\Query\Builder;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Records\Enums\ArtifactKind;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;
use Tests\Fixtures\Records\RecordFactory;

/**
 * Writes entries with artifacts straight to the tables as the store leaves
 * them, members sealed under the test encrypter, and tampers with them
 * afterwards.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait SeedsArtifacts
{
    /**
     * Write a signed entry with an artifact of the kind holding the number of
     * members, in its builder's canonical form, and the artifact, and return
     * the entry's id.
     *
     * @param  int  $members
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\ArtifactKind  $kind
     * @return string
     */
    protected function seedBundle(int $members = 3, ArtifactKind $kind = ArtifactKind::BULK): string
    {
        if ($kind === ArtifactKind::BULK) {
            return $this->seedFinalisedBundle(RecordFactory::finalisedBundle($members));
        }

        return $this->seedArtifactOfKind($kind, RecordFactory::canonical($kind, $members), $members);
    }

    /**
     * Write a signed entry with an artifact of the kind holding exactly the
     * canonical form and count given, and the artifact, and return the entry's
     * id.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\ArtifactKind  $kind
     * @param  string  $canonical
     * @param  int  $count
     * @return string
     */
    protected function seedArtifactOfKind(ArtifactKind $kind, string $canonical, int $count): string
    {
        return $this->seedFinalisedBundle(RecordFactory::finalisedWithArtifact($kind, $canonical, $count));
    }

    /**
     * Write the finalised bundle's artifact and then its entry, as the store
     * does, and return the entry's id.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @return string
     */
    protected function seedFinalisedBundle(FinalisedRecord $record): string
    {
        $codec = app(RowCodec::class);

        $this->artifactsTable()->insert(self::artifactRowOf($record, $codec));
        $this->entriesTable()->insert($codec->encode($record));

        return $record->record->id;
    }

    /**
     * Write a bulk entry and its artifact for each of the number of bundles, a
     * chunk of entries and a chunk of artifacts at a time, and return the
     * entries' ids in the order written.
     *
     * @param  int  $bundles
     * @param  int  $members
     * @return list<string>
     */
    protected function seedBundles(int $bundles, int $members = 3): array
    {
        $codec     = app(RowCodec::class);
        $entries   = [];
        $artifacts = [];

        for ($index = 0; $index < $bundles; $index++) {
            $record      = RecordFactory::finalisedBundle($members);
            $entries[]   = $codec->encode($record);
            $artifacts[] = self::artifactRowOf($record, $codec);
        }

        foreach (array_chunk($artifacts, 20) as $chunk) {
            $this->artifactsTable()->insert($chunk);
        }

        foreach (array_chunk($entries, 20) as $chunk) {
            $this->entriesTable()->insert($chunk);
        }

        return array_map(static fn (array $entry): string => (string) $entry['id'], $entries);
    }

    /**
     * Write a signed entry whose `properties._audit.manifest` holds the value
     * given, as stored, with no artifact, and return its id.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $descriptor
     * @return string
     */
    protected function seedEntrySigning(mixed $descriptor): string
    {
        $base       = RecordFactory::captured();
        $properties = ['amount' => '1200.00', '_audit' => ['manifest' => $descriptor]];
        $record     = app(RecordSigner::class)->sign(RecordFactory::withFields(['properties' => $properties], $base), RecordFactory::RECORDED_AT);
        $entry      = app(RowCodec::class)->encode($record);

        $this->entriesTable()->insert($entry);

        return $record->record->id;
    }

    /**
     * Change the columns given of the artifact the entry names.
     *
     * @param  string  $entryId
     * @param  array<string, int|string|null>  $columns
     * @return void
     */
    protected function tamperWithArtifact(string $entryId, array $columns): void
    {
        $this->artifactsTable()->where('entry_id', $entryId)->update($columns);
    }

    /**
     * Swap the artifacts of the two entries, leaving each row otherwise
     * untouched; the first is moved aside first so the unique entry index never
     * holds two rows for one entry.
     *
     * @param  string  $entryA
     * @param  string  $entryB
     * @return void
     */
    protected function swapArtifacts(string $entryA, string $entryB): void
    {
        $aside = '01932b4e-9000-7000-8000-00000000aaaa';

        $this->tamperWithArtifact($entryA, ['entry_id' => $aside]);
        $this->tamperWithArtifact($entryB, ['entry_id' => $entryA]);
        $this->tamperWithArtifact($aside, ['entry_id' => $entryB]);
    }

    /**
     * The stored artifact the entry names, as its raw row, or `null` when it
     * has none.
     *
     * @param  string  $entryId
     * @return ?array<string, scalar|null>
     */
    protected function artifactOf(string $entryId): ?array
    {
        $artifact = $this->artifactsTable()->where('entry_id', $entryId)->first();

        /** @var ?array<string, scalar|null> */
        return $artifact === null ? null : (array) $artifact;
    }

    /**
     * A query of the artifacts table on the storage connection.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    protected function artifactsTable(): Builder
    {
        return DB::connection(StorageConnection::name())->table(EntrySettings::artifactsTable());
    }

    /**
     * A query of the entries table on the storage connection.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private function entriesTable(): Builder
    {
        return DB::connection(StorageConnection::name())->table(EntrySettings::table());
    }

    /**
     * The artifact row of the finalised bundle: the attachment as a bundle
     * carries it, created when its entry was recorded, in the stored form.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @param  \SineMacula\Laravel\AuditLog\Stores\RowCodec  $codec
     * @return array<string, int|string>
     */
    private static function artifactRowOf(FinalisedRecord $record, RowCodec $codec): array
    {
        $attachment = $record->record->attachment;

        self::assertNotNull($attachment, 'A bundle carries its attachment.');

        return [...$attachment->envelopeFor($record->record->id), 'created_at' => (string) $codec->encode($record)['recorded_at']];
    }
}
