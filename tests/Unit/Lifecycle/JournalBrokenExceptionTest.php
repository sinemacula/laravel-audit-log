<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException;

/**
 * Unit tests for the exception a lifecycle operation throws on a bad journal.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JournalBrokenException::class)]
final class JournalBrokenExceptionTest extends TestCase
{
    /** @var string A journal row's id. */
    private const string ROW = '01932b4e-e000-7000-8000-000000000001';

    /**
     * The message names the finding and says nothing destructive runs.
     *
     * @return void
     */
    public function testTheMessageNamesTheFinding(): void
    {
        self::assertSame(
            'The lifecycle journal fails verification (`journal_gap`); nothing destructive runs until it is investigated.',
            JournalBrokenException::at(Finding::JOURNAL_GAP, self::ROW)->getMessage(),
        );
    }

    /**
     * The finding and the row id are carried, the row `null` when none.
     *
     * @return void
     */
    public function testCarriesTheFindingAndTheRow(): void
    {
        $exception = JournalBrokenException::at(Finding::JOURNAL_SIGNATURE, self::ROW);

        self::assertSame(Finding::JOURNAL_SIGNATURE, $exception->finding);
        self::assertSame(self::ROW, $exception->rowId);
        self::assertNull(JournalBrokenException::at(Finding::JOURNAL_COMMITMENT, null)->rowId);
    }

    /**
     * It carries no previous exception and no code, and is a runtime exception.
     *
     * @return void
     */
    public function testCarriesNoPreviousException(): void
    {
        $exception = JournalBrokenException::at(Finding::JOURNAL_MALFORMED, null);

        self::assertNull($exception->getPrevious());
        self::assertSame(0, $exception->getCode());
        self::assertInstanceOf(\RuntimeException::class, $exception);
    }
}
