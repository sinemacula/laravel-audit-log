<?php

declare(strict_types = 1);

namespace Tests\Unit\Privacy;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Privacy\OmissionLog;

/**
 * Unit tests for the omission log: what it counts, the paths it remembers and
 * how it bounds them, and that the list does not depend on the order of adding.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OmissionLog::class)]
final class OmissionLogTest extends TestCase
{
    /**
     * A log nothing was added to gives `null`, so a record with no removal
     * carries no diagnostic.
     *
     * @return void
     */
    public function testNothingOmittedIsNull(): void
    {
        self::assertNull((new OmissionLog)->toArray());
    }

    /**
     * Every branch counts, including one with the same path as another: the
     * count is of removed branches, not of paths.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testCountsEveryBranch(): void
    {
        $log = new OmissionLog;

        $log->add('items.*.sku');
        $log->add('items.*.sku');
        $log->add('items.*.sku');

        self::assertSame(['count' => 3, 'paths' => ['items.*.sku']], $log->toArray());
    }

    /**
     * Paths are kept once each and sorted by byte, so `Z` comes before `a` and
     * a shorter prefix before what extends it.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testPathsAreUniqueAndSortedBytewise(): void
    {
        $log = new OmissionLog;

        foreach (['b', 'a', 'Z', 'a', 'ab', '$ip', '_audit.note', '*', 'é'] as $path) {
            $log->add($path);
        }

        self::assertSame(['count' => 9, 'paths' => ['$ip', '*', 'Z', '_audit.note', 'a', 'ab', 'b', 'é']], $log->toArray());
    }

    /**
     * The list is the same whichever order the paths arrive in, including when
     * more arrive than are kept.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheListDoesNotDependOnTheOrderOfAdding(): void
    {
        $paths = self::paths(40);

        $forwards = new OmissionLog;
        $reversed = new OmissionLog;

        foreach ($paths as $path) {
            $forwards->add($path);
        }

        foreach (array_reverse($paths) as $path) {
            $reversed->add($path);
        }

        self::assertSame($forwards->toArray(), $reversed->toArray());
    }

    /**
     * Past the limit the first 32 in sorted order are kept, and every branch is
     * still counted.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testKeepsTheFirst32Sorted(): void
    {
        $paths = self::paths(33);
        $log   = new OmissionLog;

        foreach (array_reverse($paths) as $path) {
            $log->add($path);
        }

        self::assertSame(['count' => 33, 'paths' => array_slice($paths, 0, 32)], $log->toArray());
    }

    /**
     * A log of exactly 32 paths gives them all.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testExactly32PathsAreAllKept(): void
    {
        $paths = self::paths(32);
        $log   = new OmissionLog;

        foreach ($paths as $path) {
            $log->add($path);
        }

        self::assertSame(['count' => 32, 'paths' => $paths], $log->toArray());
    }

    /**
     * A path of exactly the limit is remembered as it is.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAPathOf128BytesIsKept(): void
    {
        $path = str_repeat('a', OmissionLog::MAX_PATH_BYTES);
        $log  = new OmissionLog;

        $log->add($path);

        self::assertSame(['count' => 1, 'paths' => [$path]], $log->toArray());
    }

    /**
     * A path one byte over the limit is remembered as `*`, and is still
     * counted.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAPathOf129BytesBecomesAStar(): void
    {
        $log = new OmissionLog;

        $log->add(str_repeat('a', OmissionLog::MAX_PATH_BYTES + 1));

        self::assertSame(['count' => 1, 'paths' => ['*']], $log->toArray());
    }

    /**
     * Length is measured as the path is stored: 65 `"` are 65 bytes, but 130
     * encoded, and 64 of them are exactly the limit.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testLengthIsMeasuredEncoded(): void
    {
        $over = new OmissionLog;
        $at   = new OmissionLog;

        $over->add(str_repeat('"', 65));
        $at->add(str_repeat('"', 64));

        self::assertSame(['count' => 1, 'paths' => ['*']], $over->toArray());
        self::assertSame(['count' => 1, 'paths' => [str_repeat('"', 64)]], $at->toArray());
    }

    /**
     * Length is measured under the fixed flags, which leave a slash and a
     * multi-byte character as they are: 128 slashes fit, and 65 two-byte
     * characters do not, though they are 65 characters.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testLengthIsMeasuredWithTheFixedFlags(): void
    {
        $slashes = new OmissionLog;
        $accents = new OmissionLog;

        $slashes->add(str_repeat('/', OmissionLog::MAX_PATH_BYTES));
        $accents->add(str_repeat('é', 65));

        self::assertSame(['count' => 1, 'paths' => [str_repeat('/', OmissionLog::MAX_PATH_BYTES)]], $slashes->toArray());
        self::assertSame(['count' => 1, 'paths' => ['*']], $accents->toArray());
    }

    /**
     * A numeric path, which PHP makes an integer key, comes back a string, and
     * sorts among the others as a string.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testANumericPathStaysAString(): void
    {
        $log = new OmissionLog;

        $log->add('10');
        $log->add('9');
        $log->add('0');

        self::assertSame(['count' => 3, 'paths' => ['0', '10', '9']], $log->toArray());
    }

    /**
     * Counting without a path adds to the count and to no list, and a log with
     * only such a count still reports it.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testAddCountCountsWithoutAPath(): void
    {
        $log = new OmissionLog;

        $log->addCount(5);

        self::assertSame(['count' => 5, 'paths' => []], $log->toArray());

        $log->add('ssn');

        self::assertSame(['count' => 6, 'paths' => ['ssn']], $log->toArray());
    }

    /**
     * Counting nothing changes nothing, so a caller with no collisions past
     * those carried can pass its difference as it is.
     *
     * @return void
     */
    public function testAddingACountOfZeroIsNothing(): void
    {
        $log = new OmissionLog;

        $log->addCount(0);

        self::assertNull($log->toArray());
    }

    /**
     * A negative count is a programming error, refused rather than letting the
     * count fall, and leaves the log as it was.
     *
     * @return void
     */
    public function testRefusesANegativeCount(): void
    {
        $log = new OmissionLog;

        try {
            $log->addCount(-1);
            self::fail('Expected the count to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('An omission count cannot be negative.', $exception->getMessage());
        }

        self::assertNull($log->toArray());
    }

    /**
     * The count stops at the largest integer rather than overflowing into a
     * float, which the typed count would refuse and so fail the write.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheCountStopsAtTheLargestInteger(): void
    {
        $log = new OmissionLog;

        $log->addCount(PHP_INT_MAX);
        $log->add('ssn');
        $log->addCount(PHP_INT_MAX);

        self::assertSame(['count' => PHP_INT_MAX, 'paths' => ['ssn']], $log->toArray());
    }

    /**
     * A path that is not valid UTF-8 cannot be measured, and fails without
     * saying what it held; the masker cannot produce one, since a rule's path
     * is clean text.
     *
     * @return void
     */
    public function testAPathThatCannotBeEncodedFailsAndIsNotCounted(): void
    {
        $log = new OmissionLog;

        try {
            $log->add("s3cr3t\xFF");
            self::fail('Expected the path to be refused.');
        } catch (\JsonException $exception) {
            self::assertStringNotContainsString('s3cr3t', $exception->getMessage());
        }

        self::assertNull($log->toArray());
    }

    /**
     * Distinct paths in sorted order: `path00`, `path01` and so on.
     *
     * @param  int  $count
     * @return list<string>
     */
    private static function paths(int $count): array
    {
        return array_map(static fn (int $index): string => sprintf('path%02d', $index), range(0, $count - 1));
    }
}
