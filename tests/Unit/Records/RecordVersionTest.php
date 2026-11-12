<?php

declare(strict_types = 1);

namespace Tests\Unit\Records;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Records\RecordVersion;

/**
 * Unit tests for the record envelope version: the version a captured record
 * carries, the versions this release reads, and the refusal of any other.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecordVersion::class)]
final class RecordVersionTest extends TestCase
{
    /**
     * The current version is 1, it is the only version this release reads, and
     * reading it back returns it.
     *
     * @return void
     */
    public function testTheCurrentVersionIsOneAndSupported(): void
    {
        self::assertSame(1, RecordVersion::CURRENT);
        self::assertSame([1], RecordVersion::SUPPORTED);
        self::assertSame(1, RecordVersion::check(1));
    }

    /**
     * Rows of `[version]`: versions this release does not read, older, newer
     * and out of range.
     *
     * @return iterable<string, array{0: int}>
     */
    public static function provideUnknownVersions(): iterable
    {
        yield from [
            'zero'             => [0],
            'the next version' => [2],
            'negative'         => [-1],
            'largest smallint' => [32767],
            'largest integer'  => [PHP_INT_MAX],
        ];
    }

    /**
     * A stored record of a version this release does not read is refused,
     * naming the version, rather than read as if it were the current one.
     *
     * @param  int  $version
     * @return void
     */
    #[DataProvider('provideUnknownVersions')]
    public function testAnUnknownVersionIsRefused(int $version): void
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage(sprintf('Record version %d is not supported by this release.', $version));

        RecordVersion::check($version);
    }

    /**
     * The constructor is private; reflection invokes it for coverage.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(RecordVersion::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(RecordVersion::class, $instance);
    }
}
