<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\RewrapStatus;
use SineMacula\Laravel\AuditLog\Lifecycle\RewrapResult;

/**
 * Unit tests for what a rewrap returns.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RewrapResult::class)]
final class RewrapResultTest extends TestCase
{
    /** @var string The run's operation. */
    private const string OPERATION = '01932b4e-9000-7000-8000-0000000000a1';

    /**
     * A run that skipped nothing is complete, committed unless dry, unrecorded.
     *
     * @return void
     */
    public function testARunThatSkippedNothingIsComplete(): void
    {
        $result = new RewrapResult(self::OPERATION, false, true, 'k2', 4, 3, 0, [], 2);

        self::assertSame(self::OPERATION, $result->operationId);
        self::assertFalse($result->dryRun);
        self::assertTrue($result->rotate);
        self::assertSame('k2', $result->wrapKeyId);
        self::assertSame([4, 3, 0, 2], [$result->rewrapped, $result->rotated, $result->skipped, $result->batches]);
        self::assertSame(RewrapStatus::COMPLETE, $result->status);
        self::assertSame([], $result->skippedKeyIds);
        self::assertTrue($result->committed);
        self::assertFalse($result->recorded);
    }

    /**
     * A run that skipped a key is partial, and a dry run commits nothing.
     *
     * @return void
     */
    public function testARunThatSkippedAKeyIsPartial(): void
    {
        $result = new RewrapResult(self::OPERATION, true, false, 'k2', 0, 0, 1, [self::id(1)], 1);

        self::assertSame(RewrapStatus::PARTIAL, $result->status);
        self::assertSame([self::id(1)], $result->skippedKeyIds);
        self::assertFalse($result->committed);
    }

    /**
     * At most 100 skipped keys are named, sorted; the count keeps them all.
     *
     * @return void
     */
    public function testTheSkippedKeysAreSortedAndBounded(): void
    {
        $ids    = array_map(self::id(...), range(150, 1));
        $result = new RewrapResult(self::OPERATION, false, false, 'k2', 0, 0, 150, $ids, 2);

        self::assertSame(100, RewrapResult::MAX_SKIPPED_IDS);
        self::assertSame(array_map(self::id(...), range(1, 100)), $result->skippedKeyIds);
        self::assertSame(150, $result->skipped);
    }

    /**
     * Whether it was recorded is set on a copy, every other field kept.
     *
     * @return void
     */
    public function testWithRecordedKeepsEveryOtherField(): void
    {
        $result   = new RewrapResult(self::OPERATION, false, true, 'k2', 4, 3, 1, [self::id(7)], 2);
        $recorded = $result->withRecorded(true);

        self::assertTrue($recorded->recorded);
        self::assertFalse($result->recorded);
        self::assertSame([...$result->toArray(), 'recorded' => true], $recorded->toArray());
        self::assertFalse($recorded->withRecorded(false)->recorded);
    }

    /**
     * The array form names each field under its snake-case key, in order.
     *
     * @return void
     */
    public function testTheArrayForm(): void
    {
        self::assertSame([
            'operation_id'    => self::OPERATION,
            'committed'       => true,
            'recorded'        => true,
            'dry_run'         => false,
            'status'          => 'partial',
            'rotate'          => true,
            'wrap_key_id'     => 'k2',
            'keys_rewrapped'  => 4,
            'keys_rotated'    => 3,
            'keys_skipped'    => 1,
            'skipped_key_ids' => [self::id(7)],
            'batches'         => 2,
        ], (new RewrapResult(self::OPERATION, false, true, 'k2', 4, 3, 1, [self::id(7)], 2, true))->toArray());
    }

    /**
     * A key id ending in the number, so ids sort as their numbers do.
     *
     * @param  int  $number
     * @return string
     */
    private static function id(int $number): string
    {
        return sprintf('01932b4e-c000-7000-8000-%012d', $number);
    }
}
