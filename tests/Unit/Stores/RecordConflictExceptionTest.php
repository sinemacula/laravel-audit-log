<?php

declare(strict_types = 1);

namespace Tests\Unit\Stores;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Stores\RecordConflictException;

/**
 * Unit tests for the record conflict exception: the messages naming the id of
 * an entry with different content, of one that fails verification and of a bulk
 * record stored with another artifact or without its own, the id it keeps for a
 * caller, and the class it specialises.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecordConflictException::class)]
final class RecordConflictExceptionTest extends TestCase
{
    /** @var string The id the record and the existing entry share. */
    private const string ID = '01932b4e-8a40-7000-8000-000000000001';

    /**
     * The exception for different content names the id in its message and keeps
     * it.
     *
     * @return void
     */
    public function testDifferentContentNamesTheIdAndKeepsIt(): void
    {
        $exception = RecordConflictException::differentContent(self::ID);

        self::assertSame('An audit entry with id 01932b4e-8a40-7000-8000-000000000001 already exists with different captured content.', $exception->getMessage());
        self::assertSame(self::ID, $exception->id);
        self::assertSame(0, $exception->getCode());
        self::assertNull($exception->getPrevious());
    }

    /**
     * The exception for a row that fails verification names the id in its
     * message and keeps it.
     *
     * @return void
     */
    public function testAnUnverifiedRowNamesTheIdAndKeepsIt(): void
    {
        $exception = RecordConflictException::unverified(self::ID);

        self::assertSame('An audit entry with id 01932b4e-8a40-7000-8000-000000000001 already exists, and its stored row fails verification.', $exception->getMessage());
        self::assertSame(self::ID, $exception->id);
        self::assertSame(0, $exception->getCode());
        self::assertNull($exception->getPrevious());
    }

    /**
     * The exception for a bulk record stored with another artifact, or without
     * its own, names only the id in its message, never anything of either
     * artifact, and keeps it.
     *
     * @return void
     */
    public function testADifferentArtifactNamesOnlyTheId(): void
    {
        $exception = RecordConflictException::differentArtifact(self::ID);

        self::assertSame('The record 01932b4e-8a40-7000-8000-000000000001 is stored with another artifact, or without its own.', $exception->getMessage());
        self::assertSame(self::ID, $exception->id);
        self::assertSame(0, $exception->getCode());
        self::assertNull($exception->getPrevious());
        self::assertInstanceOf(\RuntimeException::class, $exception);
    }

    /**
     * The constructor keeps the message and the id it is given.
     *
     * @return void
     */
    public function testKeepsTheMessageAndTheIdGiven(): void
    {
        $exception = new RecordConflictException('What is wrong.', 'entry-1');

        self::assertSame('What is wrong.', $exception->getMessage());
        self::assertSame('entry-1', $exception->id);
    }

    /**
     * The exception is a final runtime exception, never an invalid argument:
     * the record is well formed, and the stored entry is what disagrees.
     *
     * @return void
     */
    public function testIsARuntimeException(): void
    {
        $exception = RecordConflictException::differentContent(self::ID);

        self::assertInstanceOf(\RuntimeException::class, $exception);
        self::assertNotInstanceOf(\InvalidArgumentException::class, $exception);
        self::assertTrue((new \ReflectionClass(RecordConflictException::class))->isFinal());
    }
}
