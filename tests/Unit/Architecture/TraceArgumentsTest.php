<?php

declare(strict_types = 1);

namespace Tests\Unit\Architecture;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

/**
 * The test run keeps stack trace arguments, without which the tests that no
 * payload reaches a trace would pass vacuously.
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
