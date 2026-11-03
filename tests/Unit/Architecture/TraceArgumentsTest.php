<?php

declare(strict_types = 1);

namespace Tests\Unit\Architecture;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

/**
 * The test run keeps arguments in stack traces. The tests that prove no payload
 * reaches a trace read each frame's arguments, so with arguments dropped, as
 * production's setting drops them, they would find none and pass without
 * proving anything.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class TraceArgumentsTest extends TestCase
{
    /**
     * A thrown exception's trace holds the arguments of the frames it passed
     * through.
     *
     * @return void
     */
    public function testTracesKeepTheirArguments(): void
    {
        self::assertSame('0', ini_get('zend.exception_ignore_args'));

        try {
            self::raiseWith('kept');
        } catch (\RuntimeException $exception) {
            self::assertSame('kept', $exception->getTrace()[0]['args'][0] ?? null);
        }
    }

    /**
     * Throw from a frame whose argument the trace should keep.
     *
     * @param  string  $value
     * @return never
     *
     * @throws \RuntimeException
     */
    private static function raiseWith(string $value): never
    {
        throw new \RuntimeException($value === '' ? 'empty' : 'thrown');
    }
}
