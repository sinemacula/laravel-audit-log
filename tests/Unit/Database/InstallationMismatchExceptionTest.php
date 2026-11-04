<?php

declare(strict_types = 1);

namespace Tests\Unit\Database;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Database\InstallationMismatchException;

/**
 * Unit tests for the refusal of connections that do not reach one installation:
 * each named constructor's message, which is a full sentence naming no id and
 * no connection, and the runtime exception it is.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(InstallationMismatchException::class)]
final class InstallationMismatchExceptionTest extends TestCase
{
    /**
     * Rows of `[exception, message]`: each named constructor, with the message
     * it carries.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Database\InstallationMismatchException, 1: string}>
     */
    public static function provideRefusals(): iterable
    {
        yield from [
            'absent'     => [InstallationMismatchException::absent(), 'The maintenance connection reaches no installation id; it must reach the storage connection\'s database.'],
            'mismatched' => [InstallationMismatchException::mismatched(), 'The storage and maintenance connections reach different installations.'],
        ];
    }

    /**
     * Each message is one sentence ending in a full stop, says what is wrong,
     * and names no id, no UUID and no connection: an operator reads it beside
     * logs another may see.
     *
     * @param  \SineMacula\Laravel\AuditLog\Database\InstallationMismatchException  $exception
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideRefusals')]
    public function testEachMessageIsASentenceNamingNoValue(InstallationMismatchException $exception, string $message): void
    {
        self::assertSame($message, $exception->getMessage());
        self::assertStringEndsWith('.', $message);
        self::assertMatchesRegularExpression('/\A[A-Z]/', $message);
        self::assertDoesNotMatchRegularExpression('/[0-9a-f]{8}-[0-9a-f]{4}|\[|`/', $message);
        self::assertInstanceOf(\RuntimeException::class, $exception);
        self::assertSame(0, $exception->getCode());
        self::assertNull($exception->getPrevious());
    }
}
