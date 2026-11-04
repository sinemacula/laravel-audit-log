<?php

declare(strict_types = 1);

namespace Tests\Unit\Console;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Console\TableShape;
use Tests\Fixtures\Database\EntriesTableShape;

/**
 * Unit tests for the shapes the schema checks compare the package's tables
 * against: the entries table's is what its migration gives, column by column
 * and index by index, the artifacts', the outbox's, the deliveries', the
 * checkpoints', the checkpoint members', the integrity state's, the lifecycle
 * journal's, the holds', the lifecycle lock's, the import batches', the subject
 * keys', the owner erasures' and the key uses' are what theirs give, and each
 * names its table and describes a column the package does not write in its own
 * words.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TableShape::class)]
final class TableShapeTest extends TestCase
{
    /**
     * The entries shape lists every column the migration creates, in order,
     * each string column at the length the migration gives it, the other
     * columns in their families, the indexes the migration names, and the key
     * over `id` alone.
     *
     * @return void
     */
    public function testTheEntriesShapeIsWhatTheMigrationGives(): void
    {
        $shape   = TableShape::entries();
        $strings = array_filter($shape->columns, static fn (array $column): bool => $column[0] === 'string');

        self::assertSame(EntriesTableShape::STRING_LENGTHS, array_map(static fn (array $column): ?int => $column[1], $strings));
        self::assertSame([
            'id'                => ['uuid', 36, false],
            'record_version'    => ['smallint', null, false],
            'event_version'     => ['smallint', null, false],
            'import_batch_id'   => ['uuid', 36, true],
            'context'           => ['json', null, true],
            'properties'        => ['json', null, true],
            'occurred_at'       => ['datetime', 6, false],
            'recorded_at'       => ['datetime', 6, false],
            'integrity_version' => ['smallint', null, false],
        ], array_diff_key($shape->columns, $strings));
        self::assertSame(
            ['event', 'category', 'outcome', 'provenance', 'source_id', 'key_id', 'hmac'],
            array_keys(array_filter($strings, static fn (array $column): bool => !$column[2])),
        );
        self::assertSame([
            '_actor_index'     => [['actor_type', 'actor_id', 'occurred_at', 'id'], false],
            '_subject_index'   => [['subject_type', 'subject_id', 'occurred_at', 'id'], false],
            '_principal_index' => [['principal_type', 'principal_id', 'occurred_at', 'id'], false],
            '_tenant_index'    => [['tenant_type', 'tenant_id', 'occurred_at', 'id'], false],
            '_event_index'     => [['event', 'occurred_at', 'id'], false],
            '_category_index'  => [['category', 'occurred_at', 'id'], false],
            '_correlate_index' => [['correlation_id'], false],
            '_occurred_index'  => [['occurred_at', 'id'], false],
            '_recorded_index'  => [['recorded_at', 'id'], false],
            '_source_unique'   => [['source_id', 'source_record_id'], true],
        ], $shape->indexes);
        self::assertSame(['id'], $shape->primary);
    }

    /**
     * The artifacts shape is what its migration gives: the artifact's id as the
     * key, the entry it belongs to, its kind, its count and digest, the
     * encrypted members, when it was recorded, and an entry with at most one
     * artifact.
     *
     * @return void
     */
    public function testTheArtifactsShape(): void
    {
        $shape = TableShape::artifacts();

        self::assertSame([
            'id'           => ['uuid', 36, false],
            'entry_id'     => ['uuid', 36, false],
            'kind'         => ['string', 16, false],
            'member_count' => ['integer', null, false],
            'digest'       => ['string', 64, false],
            'members'      => ['longtext', null, false],
            'created_at'   => ['datetime', 6, false],
        ], $shape->columns);
        self::assertSame(['_entry_unique' => [['entry_id'], true]], $shape->indexes);
        self::assertSame(['id'], $shape->primary);
    }

    /**
     * The outbox shape is what its migration gives: the record's id as the key,
     * its encrypted payload, its attempts, its lease and its failure, and the
     * index a drain claims rows by.
     *
     * @return void
     */
    public function testTheOutboxShapeIsWhatTheMigrationGives(): void
    {
        $shape = TableShape::outbox();

        self::assertSame([
            'id'               => ['uuid', 36, false],
            'payload'          => ['longtext', null, false],
            'attempts'         => ['integer', null, false],
            'available_at'     => ['datetime', 6, false],
            'claimed_until'    => ['datetime', 6, true],
            'claimed_by'       => ['string', 64, true],
            'failed_at'        => ['datetime', 6, true],
            'last_error_class' => ['string', 191, true],
            'created_at'       => ['datetime', 6, false],
        ], $shape->columns);
        self::assertSame(['_due_index' => [['failed_at', 'available_at'], false], '_queued_index' => [['failed_at', 'created_at'], false]], $shape->indexes);
        self::assertSame(['id'], $shape->primary);
    }

    /**
     * The deliveries shape is what its migration gives: one receipt for each
     * entry and destination, which is its key, and no other index.
     *
     * @return void
     */
    public function testTheDeliveriesShapeIsWhatTheMigrationGives(): void
    {
        $shape = TableShape::deliveries();

        self::assertSame([
            'entry_id'           => ['uuid', 36, false],
            'destination'        => ['string', 64, false],
            'attempts'           => ['integer', null, false],
            'first_attempted_at' => ['datetime', 6, false],
            'delivered_at'       => ['datetime', 6, true],
            'last_error_class'   => ['string', 191, true],
        ], $shape->columns);
        self::assertSame([], $shape->indexes);
        self::assertSame(['entry_id', 'destination'], $shape->primary);
    }

    /**
     * The checkpoints shape is what its migration gives: the seal's id as the
     * key, its place in the chain, its members' digest, its times, the journal
     * head it commits to, its signature, the four anchor columns, one seal per
     * sequence and the index the anchorer reads the seals not yet anchored by.
     *
     * @return void
     */
    public function testTheCheckpointsShapeIsWhatTheMigrationGives(): void
    {
        $shape = TableShape::checkpoints();

        self::assertSame([
            'id'                 => ['uuid', 36, false],
            'sequence'           => ['bigint', null, false],
            'log_id'             => ['string', 64, false],
            'previous_id'        => ['uuid', 36, true],
            'previous_digest'    => ['string', 64, true],
            'member_count'       => ['integer', null, false],
            'members_digest'     => ['string', 64, false],
            'seal_digest'        => ['string', 64, false],
            'first_recorded_at'  => ['datetime', 6, false],
            'last_recorded_at'   => ['datetime', 6, false],
            'sealed_at'          => ['datetime', 6, false],
            'signer'             => ['string', 16, false],
            'key_id'             => ['string', 32, false],
            'algorithm_version'  => ['smallint', null, false],
            'journal_sequence'   => ['bigint', null, true],
            'journal_head'       => ['string', 64, true],
            'signature'          => ['string', 64, false],
            'anchor'             => ['string', 64, true],
            'anchor_receipt'     => ['json', null, true],
            'anchored_at'        => ['datetime', 6, true],
            'anchor_error_class' => ['string', 191, true],
        ], $shape->columns);
        self::assertSame([
            '_sequence_unique' => [['sequence'], true],
            '_anchored_index'  => [['anchored_at', 'sequence'], false],
            '_journal_index'   => [['journal_sequence'], false],
        ], $shape->indexes);
        self::assertSame(['id'], $shape->primary);
    }

    /**
     * The checkpoint members shape is what its migration gives: keyed by the
     * seal and the entry, the entry's HMAC, and an entry held by at most one
     * seal.
     *
     * @return void
     */
    public function testTheMembersShapeIsWhatTheMigrationGives(): void
    {
        $shape = TableShape::members();

        self::assertSame([
            'checkpoint_id' => ['uuid', 36, false],
            'entry_id'      => ['uuid', 36, false],
            'hmac'          => ['string', 64, false],
        ], $shape->columns);
        self::assertSame(['_entry_unique' => [['entry_id'], true]], $shape->indexes);
        self::assertSame(['checkpoint_id', 'entry_id'], $shape->primary);
    }

    /**
     * The integrity state shape is what its migration gives: one value for each
     * name, which is its key, when it was written, and no other index.
     *
     * @return void
     */
    public function testTheStateShapeIsWhatTheMigrationGives(): void
    {
        $shape = TableShape::state();

        self::assertSame([
            'name'       => ['string', 64, false],
            'value'      => ['text', null, false],
            'updated_at' => ['datetime', 6, false],
        ], $shape->columns);
        self::assertSame([], $shape->indexes);
        self::assertSame(['name'], $shape->primary);
    }

    /**
     * The entries shape holds the source digest, nullable, after the import
     * batch and before the address, so a schema without it is reported.
     *
     * @return void
     */
    public function testTheEntriesShapeHoldsTheSourceDigest(): void
    {
        $columns = array_keys(TableShape::entries()->columns);
        $at      = array_search('source_digest', $columns, true);

        self::assertSame(['string', 64, true], TableShape::entries()->columns['source_digest']);
        self::assertIsInt($at);
        self::assertSame(['import_batch_id', 'source_digest', 'ip'], array_slice($columns, $at - 1, 3));
        self::assertCount(37, $columns);
    }

    /**
     * The lifecycle journal shape is what its migration gives: the row's id as
     * the key, its place in the chain, its kind and operation, its authority,
     * the seal and the hold it names, its payload and digest, its link and its
     * signature, one row per sequence, and the lookups by seal, hold and kind.
     *
     * @return void
     */
    public function testTheJournalShapeIsWhatTheMigrationGives(): void
    {
        $shape = TableShape::journal();

        self::assertSame([
            'id'                 => ['uuid', 36, false],
            'sequence'           => ['bigint', null, false],
            'log_id'             => ['string', 64, false],
            'kind'               => ['string', 32, false],
            'operation_id'       => ['uuid', 36, false],
            'occurred_at'        => ['datetime', 6, false],
            'authority_type'     => ['string', 191, true],
            'authority_id'       => ['string', 191, true],
            'reason'             => ['string', 64, true],
            'external_reference' => ['string', 191, true],
            'seal_id'            => ['uuid', 36, true],
            'hold_id'            => ['uuid', 36, true],
            'payload'            => ['longtext', null, false],
            'payload_digest'     => ['string', 64, false],
            'previous_hmac'      => ['string', 64, true],
            'key_id'             => ['string', 32, false],
            'hmac'               => ['string', 64, false],
        ], $shape->columns);
        self::assertSame([
            '_sequence_unique' => [['sequence'], true],
            '_seal_index'      => [['seal_id'], false],
            '_hold_index'      => [['hold_id'], false],
            '_kind_index'      => [['kind', 'occurred_at'], false],
        ], $shape->indexes);
        self::assertSame(['id'], $shape->primary);
    }

    /**
     * The holds shape is what its migration gives: the hold's id as the key,
     * its scope and digest, its basis, batch and times, its authority, and the
     * operation and journal row that placed it, found by review date and by
     * import batch.
     *
     * @return void
     */
    public function testTheHoldsShapeIsWhatTheMigrationGives(): void
    {
        $shape = TableShape::holds();

        self::assertSame([
            'hold_id'            => ['uuid', 36, false],
            'scope'              => ['longtext', null, false],
            'scope_digest'       => ['string', 64, false],
            'basis'              => ['string', 32, false],
            'import_batch_id'    => ['uuid', 36, true],
            'placed_at'          => ['datetime', 6, false],
            'review_by'          => ['datetime', 6, true],
            'authority_type'     => ['string', 191, false],
            'authority_id'       => ['string', 191, false],
            'reason'             => ['string', 64, false],
            'external_reference' => ['string', 191, true],
            'operation_id'       => ['uuid', 36, false],
            'journal_sequence'   => ['bigint', null, false],
        ], $shape->columns);
        self::assertSame([
            '_review_index' => [['review_by'], false],
            '_batch_index'  => [['import_batch_id'], false],
        ], $shape->indexes);
        self::assertSame(['hold_id'], $shape->primary);
    }

    /**
     * The lifecycle lock shape is what its migration gives: the one row's id as
     * the key, the token and the time of the last lock, and no other index.
     *
     * @return void
     */
    public function testTheLockShapeIsWhatTheMigrationGives(): void
    {
        $shape = TableShape::lock();

        self::assertSame([
            'id'        => ['smallint', null, false],
            'token'     => ['string', 64, true],
            'locked_at' => ['datetime', 6, true],
        ], $shape->columns);
        self::assertSame([], $shape->indexes);
        self::assertSame(['id'], $shape->primary);
    }

    /**
     * The import batches shape is what its migration gives: the batch's id as
     * the key, its source and format, its importer, its file, its hold, its
     * status and counts, its conflicts and its times, found by status and by
     * when each was last written.
     *
     * @return void
     */
    public function testTheImportBatchesShapeIsWhatTheMigrationGives(): void
    {
        $shape = TableShape::importBatches();

        self::assertSame([
            'id'                  => ['uuid', 36, false],
            'source_id'           => ['string', 64, false],
            'source_region'       => ['string', 32, true],
            'input_format'        => ['string', 32, false],
            'importer_type'       => ['string', 191, false],
            'importer_id'         => ['string', 191, false],
            'reason'              => ['string', 64, false],
            'external_reference'  => ['string', 191, true],
            'file_sha256'         => ['string', 64, false],
            'externally_verified' => ['boolean', null, false],
            'hold_id'             => ['uuid', 36, true],
            'status'              => ['string', 16, false],
            'lines_read'          => ['integer', null, false],
            'imported'            => ['integer', null, false],
            'duplicates'          => ['integer', null, false],
            'conflicts'           => ['integer', null, false],
            'rejected'            => ['integer', null, false],
            'conflict_ids'        => ['text', null, true],
            'started_at'          => ['datetime', 6, false],
            'updated_at'          => ['datetime', 6, false],
            'finished_at'         => ['datetime', 6, true],
        ], $shape->columns);
        self::assertSame(['_status_index' => [['status', 'updated_at'], false]], $shape->indexes);
        self::assertSame(['id'], $shape->primary);
    }

    /**
     * Each key table's shape is what its migration gives: the subject keys
     * keyed by the key's id, with its unit, its generation, its state, its
     * wrapped key, its erasure and its signature, one key per unit and
     * generation and its keys found by owner and by erasure; the owner erasures
     * keyed by the journal row's id, with the owner, the transition,
     * the floor and the journal's sequence, found by owner in journal order;
     * and the key uses keyed by the key and the entry, found by the entry.
     *
     * @return void
     */
    public function testEveryKeyTableHasItsShape(): void
    {
        $keys     = TableShape::subjectKeys();
        $markers  = TableShape::ownerErasures();
        $keyUses  = TableShape::keyUses();
        $required = static fn (TableShape $shape): array => array_keys(array_filter($shape->columns, static fn (array $column): bool => !$column[2]));

        self::assertSame([
            'id'          => ['uuid', 36, false],
            'owner_type'  => ['string', 191, false],
            'owner_id'    => ['string', 191, false],
            'tenant_type' => ['string', 191, true],
            'tenant_id'   => ['string', 191, true],
            'category'    => ['string', 64, false],
            'unit'        => ['string', 64, false],
            'generation'  => ['integer', null, false],
            'state'       => ['string', 16, false],
            'wrapped_key' => ['text', null, true],
            'wrap_key_id' => ['string', 191, true],
            'created_at'  => ['datetime', 6, false],
            'erasure_id'  => ['uuid', 36, true],
            'key_id'      => ['string', 32, false],
            'hmac'        => ['string', 64, false],
        ], $keys->columns);
        self::assertSame([
            '_unit_unique'   => [['unit', 'generation'], true],
            '_owner_index'   => [['owner_type', 'owner_id'], false],
            '_erasure_index' => [['erasure_id'], false],
        ], $keys->indexes);
        self::assertSame(['id'], $keys->primary);

        self::assertSame([
            'id'               => ['uuid', 36, false],
            'owner_type'       => ['string', 191, false],
            'owner_id'         => ['string', 191, false],
            'transition'       => ['string', 16, false],
            'generation_floor' => ['integer', null, false],
            'journal_sequence' => ['bigint', null, false],
            'created_at'       => ['datetime', 6, false],
        ], $markers->columns);
        self::assertSame(['_owner_index' => [['owner_type', 'owner_id', 'journal_sequence'], false]], $markers->indexes);
        self::assertSame(['id'], $markers->primary);

        self::assertSame(['key_id' => ['uuid', 36, false], 'entry_id' => ['uuid', 36, false]], $keyUses->columns);
        self::assertSame(['_entry_index' => [['entry_id'], false]], $keyUses->indexes);
        self::assertSame(['key_id', 'entry_id'], $keyUses->primary);

        self::assertSame(array_keys($markers->columns), $required($markers));
        self::assertSame(array_keys($keyUses->columns), $required($keyUses));
    }

    /**
     * No column of a key table is named a word any supported engine reserves,
     * so every statement names them bare: the marker's transition and floor are
     * `transition` and `generation_floor`, never `action` or `floor`.
     *
     * @return void
     */
    public function testNoKeyTableColumnIsAReservedWord(): void
    {
        $reserved = ['action', 'floor', 'order', 'user', 'collation', 'key', 'range', 'generated', 'use', 'usage'];

        foreach ([TableShape::subjectKeys(), TableShape::ownerErasures(), TableShape::keyUses()] as $shape) {
            self::assertSame([], array_values(array_intersect(array_keys($shape->columns), $reserved)), $shape->label);
        }
    }

    /**
     * At the longest table name the setting accepts, every index a lifecycle or
     * key shape names fits PostgreSQL's 63 characters, and a key use's primary
     * key, which its migration names after the table too.
     *
     * @return void
     */
    public function testEveryLifecycleIndexFitsAtTheLongestTableName(): void
    {
        self::assertLessThanOrEqual(63, 47 + strlen('_primary'));

        $shapes = [
            TableShape::journal(),
            TableShape::holds(),
            TableShape::lock(),
            TableShape::importBatches(),
            TableShape::subjectKeys(),
            TableShape::ownerErasures(),
            TableShape::keyUses(),
        ];

        foreach ($shapes as $shape) {
            foreach (array_keys($shape->indexes) as $suffix) {
                self::assertLessThanOrEqual(63, 47 + strlen($suffix), $suffix);
            }
        }
    }

    /**
     * Rows of `[the shape, its label, how a column it does not hold is
     * described]`.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Console\TableShape, 1: string, 2: string}>
     */
    public static function provideShapes(): iterable
    {
        yield from [
            'the entries'            => [TableShape::entries(), 'entries', 'Column `notes` is not one the package writes, so no entry\'s HMAC covers it.'],
            'the artifacts'          => [TableShape::artifacts(), 'artifacts', 'Column `notes` is not one the package writes.'],
            'the outbox'             => [TableShape::outbox(), 'outbox', 'Column `notes` is not one the package writes.'],
            'the deliveries'         => [TableShape::deliveries(), 'deliveries', 'Column `notes` is not one the package writes.'],
            'the checkpoints'        => [TableShape::checkpoints(), 'checkpoints', 'Column `notes` is not one the package writes, so no seal covers it.'],
            'the checkpoint members' => [TableShape::members(), 'checkpoint members', 'Column `notes` is not one the package writes, so no seal covers it.'],
            'the integrity state'    => [TableShape::state(), 'integrity state', 'Column `notes` is not one the package writes.'],
            'the lifecycle journal'  => [TableShape::journal(), 'lifecycle journal', 'Column `notes` is not one the package writes, so no journal row\'s HMAC covers it.'],
            'the holds'              => [TableShape::holds(), 'holds', 'Column `notes` is not one the package writes.'],
            'the lifecycle lock'     => [TableShape::lock(), 'lifecycle lock', 'Column `notes` is not one the package writes.'],
            'the import batches'     => [TableShape::importBatches(), 'import batches', 'Column `notes` is not one the package writes.'],
            'the subject keys'       => [TableShape::subjectKeys(), 'subject keys', 'Column `notes` is not one the package writes.'],
            'the owner erasures'     => [TableShape::ownerErasures(), 'owner erasures', 'Column `notes` is not one the package writes.'],
            'the key uses'           => [TableShape::keyUses(), 'key uses', 'Column `notes` is not one the package writes.'],
        ];
    }

    /**
     * Each shape names its table, and describes a column the package does not
     * write in its own words: an entry and a journal row are covered by an
     * HMAC, a seal and its members by the seal, and nothing else, an artifact's
     * own columns included, by either.
     *
     * @param  \SineMacula\Laravel\AuditLog\Console\TableShape  $shape
     * @param  string  $label
     * @param  string  $unknown
     * @return void
     */
    #[DataProvider('provideShapes')]
    public function testEachShapeNamesItsTable(TableShape $shape, string $label, string $unknown): void
    {
        self::assertSame($label, $shape->label);
        self::assertSame($unknown, sprintf($shape->unknownColumn, 'notes'));
    }

    /**
     * The shapes can only be built by their named constructors.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        self::assertTrue((new \ReflectionMethod(TableShape::class, '__construct'))->isPrivate());
    }
}
