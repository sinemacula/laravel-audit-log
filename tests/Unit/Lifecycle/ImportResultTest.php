<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportRejection;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportStatus;
use SineMacula\Laravel\AuditLog\Lifecycle\Hold;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldScope;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportLine;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportPlan;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportResult;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportTally;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * Unit tests for an import's result: made from its tally, committed unless it
 * is a dry run, its record noted afterwards on a copy, the hold placed with its
 * start, and its map.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ImportResult::class)]
final class ImportResultTest extends TestCase
{
    /** @var string The operation every result is of. */
    private const string OPERATION = '01932b4e-9000-7000-8000-0000000000a1';

    /** @var string The batch every committed result names. */
    private const string BATCH = '01932b4e-a000-7000-8000-0000000000b1';

    /** @var string The hold placed with the batch's start. */
    private const string HOLD = '01932b4e-d000-7000-8000-000000000001';

    /**
     * An import's result carries its tally's counts, its batch, status and
     * hold, is committed, and is not yet recorded.
     *
     * @return void
     */
    public function testAnImportsResultCarriesItsTally(): void
    {
        $hold   = self::hold();
        $result = ImportResult::of(self::OPERATION, false, self::BATCH, ImportStatus::PARTIAL, $hold, self::tally());

        self::assertSame(self::OPERATION, $result->operationId);
        self::assertTrue($result->committed);
        self::assertFalse($result->recorded);
        self::assertFalse($result->dryRun);
        self::assertSame(self::BATCH, $result->batchId);
        self::assertSame(ImportStatus::PARTIAL, $result->status);
        self::assertSame(self::HOLD, $result->holdId);
        self::assertSame($hold, $result->hold);
        self::assertSame([3, 1, 0, 1, 1], [$result->linesRead, $result->imported, $result->duplicates, $result->conflicts, $result->rejected]);
        self::assertSame(['malformed_json' => 1], $result->rejections);
        self::assertSame(['rec-2'], $result->conflictIds);
        self::assertSame(1, $result->pastRetention);
        self::assertSame(2, $result->dropped);
    }

    /**
     * A dry run's result commits nothing and names no batch, status or hold.
     *
     * @return void
     */
    public function testADryRunCommitsNothing(): void
    {
        $result = ImportResult::of(self::OPERATION, true, null, null, null, self::tally());

        self::assertFalse($result->committed);
        self::assertTrue($result->dryRun);
        self::assertNull($result->batchId);
        self::assertNull($result->status);
        self::assertNull($result->holdId);
        self::assertNull($result->hold);
    }

    /**
     * A copy notes whether the record was written, and leaves everything else
     * as it was.
     *
     * @return void
     */
    public function testWithRecordedNotesTheRecord(): void
    {
        $result   = ImportResult::of(self::OPERATION, false, self::BATCH, ImportStatus::COMPLETE, self::hold(), self::tally());
        $recorded = $result->withRecorded(true);

        self::assertFalse($result->recorded);
        self::assertTrue($recorded->recorded);
        self::assertSame([...$result->toArray(), 'recorded' => true], $recorded->toArray());
        self::assertFalse($recorded->withRecorded(false)->recorded);
    }

    /**
     * The map names every field under its snake-case key, the status by its
     * value and the hold by its id.
     *
     * @return void
     */
    public function testToArray(): void
    {
        self::assertSame([
            'operation_id'   => self::OPERATION,
            'committed'      => true,
            'recorded'       => false,
            'dry_run'        => false,
            'batch_id'       => self::BATCH,
            'status'         => 'partial',
            'hold_id'        => self::HOLD,
            'lines_read'     => 3,
            'imported'       => 1,
            'duplicates'     => 0,
            'conflicts'      => 1,
            'rejected'       => 1,
            'rejections'     => ['malformed_json' => 1],
            'conflict_ids'   => ['rec-2'],
            'past_retention' => 1,
            'dropped'        => 2,
        ], ImportResult::of(self::OPERATION, false, self::BATCH, ImportStatus::PARTIAL, self::hold(), self::tally())->toArray());
    }

    /**
     * A close's result names the batch's hold by its id alone.
     *
     * @return void
     */
    public function testACloseNamesItsHoldByIdAlone(): void
    {
        $result = new ImportResult(self::OPERATION, true, false, false, self::BATCH, ImportStatus::INTERRUPTED, self::HOLD, null, 4, 2, 1, 0, 1, [], [], 0, 0);

        self::assertSame(self::HOLD, $result->toArray()['hold_id']);
        self::assertNull($result->hold);
        self::assertSame('interrupted', $result->toArray()['status']);
    }

    /**
     * A tally of three lines: one imported, one conflicting and one rejected,
     * one past retention and two values dropped.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ImportTally
     */
    private static function tally(): ImportTally
    {
        $tally = new ImportTally;

        $tally->countRead();
        $tally->countRead();
        $tally->countRead();
        $tally->countRejected(ImportRejection::MALFORMED_JSON);
        $tally->countDropped(2);
        $tally->countPastRetention();
        $tally->countPlan(new ImportPlan([self::line()], [1 => str_repeat('a', 64)], 0, [2 => 'rec-2']));

        return $tally;
    }

    /**
     * The first line of the file, imported.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ImportLine
     */
    private static function line(): ImportLine
    {
        return new ImportLine(
            1,
            'crm-eu',
            null,
            'rec-1',
            'invoice.approved',
            '2026-10-01T09:00:00.000000Z',
            Outcome::SUCCESS,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
        );
    }

    /**
     * The hold placed with the batch's start.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\Hold
     */
    private static function hold(): Hold
    {
        return new Hold(
            self::HOLD,
            HoldScope::all()->importBatch(self::BATCH),
            HoldBasis::OTHER,
            null,
            '2026-11-02T09:00:00.123456Z',
            Reference::of('App\Models\User', '7'),
            'case.review',
            null,
            self::OPERATION,
            2,
        );
    }
}
