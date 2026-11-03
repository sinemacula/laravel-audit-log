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
 * and index by index, the outbox's and the deliveries' are what theirs give,
 * and each names its table and describes a column the package does not write in
 * its own words.
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
            '_actor_index'     => [['actor_type', 'actor_id', 'occurred_at'], false],
            '_subject_index'   => [['subject_type', 'subject_id', 'occurred_at'], false],
            '_principal_index' => [['principal_type', 'principal_id', 'occurred_at'], false],
            '_tenant_index'    => [['tenant_type', 'tenant_id', 'occurred_at'], false],
            '_event_index'     => [['event', 'occurred_at'], false],
            '_category_index'  => [['category', 'occurred_at'], false],
            '_correlate_index' => [['correlation_id'], false],
            '_occurred_index'  => [['occurred_at'], false],
            '_source_unique'   => [['source_id', 'source_record_id'], true],
        ], $shape->indexes);
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
     * Rows of `[the shape, its label, how a column it does not hold is
     * described]`.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Console\TableShape, 1: string, 2: string}>
     */
    public static function provideShapes(): iterable
    {
        yield from [
            'the entries'    => [TableShape::entries(), 'entries', 'Column `notes` is not one the package writes, so no entry\'s HMAC covers it.'],
            'the outbox'     => [TableShape::outbox(), 'outbox', 'Column `notes` is not one the package writes.'],
            'the deliveries' => [TableShape::deliveries(), 'deliveries', 'Column `notes` is not one the package writes.'],
        ];
    }

    /**
     * Each shape names its table, and describes a column the package does not
     * write in its own words: only an entry is covered by an HMAC.
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
