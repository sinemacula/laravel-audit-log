<?php

declare(strict_types = 1);

namespace Tests\Feature\Console;

use Illuminate\Config\Repository as ConfigRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Console\ReadChecks;
use Tests\TestCase;

/**
 * Feature tests for the read checks of `audit-log:check`: a reader for each
 * read and export setting, in order, each refusing its own malformed setting
 * and reading the configuration it is given on every call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ReadChecks::class)]
final class ReadChecksTest extends TestCase
{
    /** @var array<string, int|string> A value each reader refuses, by the setting it reads, in the order the readers are listed. */
    private const array BAD_SETTINGS = [
        'audit-log.read.max_per_page' => 0,
        'audit-log.export.chunk'      => '1e3',
    ];

    /**
     * `ReadChecks` is a utility container, not to be instantiated: its
     * constructor is private. Reflection invokes it so the line is covered
     * while still documenting the access modifier.
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
     * There is one reader for each read and export setting, in order: with the
     * shipped settings each reads its default, and with every one malformed the
     * reader at each place refuses the setting at that place, naming it, so a
     * reader dropped, repeated or moved fails here.
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
     * Each reader refuses only its own setting: with one setting malformed the
     * other still reads, so a reader that reads the wrong key fails here.
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
     * The readers read the configuration they are given on every call, so a
     * setting changed after they are built is the one they read.
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
