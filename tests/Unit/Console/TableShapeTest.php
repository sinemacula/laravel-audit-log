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
 * checkpoints', the checkpoint members' and the integrity state's are what
 * theirs give, and each names its table and describes a column the package does
 * not write in its own words.
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
        self::assertSame(['_due_index' => [['failed_at', 'available_at'], false]], $shape->indexes);
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
     * key, its place in the chain, its members' digest, its times, its
     * signature, the four anchor columns, one seal per sequence and the index
     * the anchorer reads the seals not yet anchored by.
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
            'signature'          => ['string', 64, false],
            'anchor'             => ['string', 64, true],
            'anchor_receipt'     => ['json', null, true],
            'anchored_at'        => ['datetime', 6, true],
            'anchor_error_class' => ['string', 191, true],
        ], $shape->columns);
        self::assertSame([
            '_sequence_unique' => [['sequence'], true],
            '_anchored_index'  => [['anchored_at', 'sequence'], false],
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
        ];
    }

    /**
     * Each shape names its table, and describes a column the package does not
     * write in its own words: an entry is covered by an HMAC, a seal and its
     * members by the seal, and nothing else, an artifact's own columns
     * included, by either.
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
