<?php

declare(strict_types = 1);

namespace Tests\Feature\Console;

use Illuminate\Config\Repository as ConfigRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Console\ReadChecks;
use Tests\TestCase;

/**
 * Feature tests for the read checks of `audit-log:check`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ReadChecks::class)]
final class ReadChecksTest extends TestCase
{
    /** @var array<string, int|string> A value each reader refuses, by setting, in reader order. */
    private const array BAD_SETTINGS = [
        'audit-log.read.max_per_page' => 0,
        'audit-log.export.chunk'      => '1e3',
    ];

    /**
     * The constructor is private; invoking it by reflection covers the line.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(ReadChecks::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(ReadChecks::class, $instance);
    }

    /**
     * One reader per read and export setting, in order, each refusing its own.
     *
     * @return void
     */
    public function testEveryReadReaderIsListed(): void
    {
        $config = app(ConfigRepository::class);

        $readers = ReadChecks::readers($config);

        self::assertCount(count(self::BAD_SETTINGS), $readers);
        self::assertSame(100, $readers[0]());
        self::assertSame(1000, $readers[1]());

        $config->set(self::BAD_SETTINGS);

        $named = [];

        foreach (ReadChecks::readers($config) as $reader) {
            try {
                $reader();
                self::fail('Expected every reader to refuse its malformed setting.');
            } catch (\InvalidArgumentException $exception) {
                $named[] = self::keyNamedBy($exception->getMessage());
            }
        }

        self::assertSame(array_keys(self::BAD_SETTINGS), $named);
    }

    /**
     * Each reader refuses only its own setting.
     *
     * @return void
     */
    public function testEachReaderRefusesOnlyItsOwnSetting(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('audit-log.read.max_per_page', 501);

        [$page, $chunk] = ReadChecks::readers($config);

        self::assertSame(1000, $chunk());

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('`audit-log.read.max_per_page` must be an integer from 1 to 500.');

        $page();
    }

    /**
     * The readers read the configuration afresh on every call.
     *
     * @return void
     */
    public function testTheReadersReadTheSettingsOnEveryCall(): void
    {
        $config  = app(ConfigRepository::class);
        $readers = ReadChecks::readers($config);

        $config->set('audit-log.read.max_per_page', '20');
        $config->set('audit-log.export.chunk', 10000);

        self::assertSame(20, $readers[0]());
        self::assertSame(10000, $readers[1]());
    }

    /**
     * The setting a refusal names, from the backticked key it opens with.
     *
     * @param  string  $message
     * @return string
     */
    private static function keyNamedBy(string $message): string
    {
        self::assertSame(1, preg_match('/\A`([a-z0-9_.-]+)` /', $message, $matches), "The refusal [{$message}] does not open with the key it names.");

        return $matches[1];
    }
}
