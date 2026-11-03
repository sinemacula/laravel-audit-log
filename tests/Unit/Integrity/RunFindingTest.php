<?php

declare(strict_types = 1);

namespace Tests\Unit\Integrity;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Integrity\Enums\IntegrityStatus;
use SineMacula\Laravel\AuditLog\Integrity\RunFinding;

/**
 * Unit tests for a finding of a verification run as a whole: its line of
 * output, the status it gives, which is its finding's own, and its defaults.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RunFinding::class)]
final class RunFindingTest extends TestCase
{
    /** @var string An entry's id. */
    private const string ENTRY_ID = '01932b4e-8a40-7000-8000-000000000001';

    /**
     * The line names the check, its status, how many times it was found and the
     * first id, in that order of keys, and nothing else.
     *
     * @return void
     */
    public function testTheLineIsPinned(): void
    {
        $finding = new RunFinding(Finding::OVERDUE_UNSEALED, self::ENTRY_ID, 3);

        self::assertSame([
            'type'         => 'finding',
            'finding'      => 'overdue_unsealed',
            'integrity'    => 'incomplete',
            'count'        => 3,
            'first_bad_id' => self::ENTRY_ID,
        ], $finding->toArray());
    }

    /**
     * The status is the finding's own, for every finding a run can make.
     *
     * @return void
     */
    public function testTheStatusIsTheFindings(): void
    {
        foreach (Finding::cases() as $case) {
            self::assertSame($case->status(), (new RunFinding($case))->status(), $case->value);
        }

        self::assertSame(IntegrityStatus::TAMPERED, (new RunFinding(Finding::MISSING_TAIL))->status());
        self::assertSame(IntegrityStatus::INCOMPLETE, (new RunFinding(Finding::OVERDUE_UNSEALED))->status());
    }

    /**
     * A finding given no id and no count is found once, at no id.
     *
     * @return void
     */
    public function testDefaultsToOnceAtNoId(): void
    {
        $finding = new RunFinding(Finding::SEQUENCE_GAP);

        self::assertNull($finding->firstBadId);
        self::assertSame(1, $finding->count);
        self::assertNull($finding->toArray()['first_bad_id']);
    }
}
