<?php

declare(strict_types = 1);

namespace Tests\Unit\Config;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Config\ExplicitKeys;

/**
 * Unit tests for reading `audit-log.require_explicit_keys`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExplicitKeys::class)]
final class ExplicitKeysTest extends TestCase
{
    /**
     * Explicit keys are not required unless the setting says so.
     *
     * @return void
     */
    public function testOffByDefault(): void
    {
        self::assertFalse(ExplicitKeys::required(new Repository));
    }

    /**
     * Both booleans are read as given.
     *
     * @return void
     */
    public function testReadsABoolean(): void
    {
        self::assertTrue(ExplicitKeys::required(new Repository(['audit-log' => ['require_explicit_keys' => true]])));
        self::assertFalse(ExplicitKeys::required(new Repository(['audit-log' => ['require_explicit_keys' => false]])));
    }

    /**
     * Values that are not a real boolean.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideMalformedValues(): iterable
    {
        yield 'a word' => ['yes'];
        yield 'a digit' => ['1'];
        yield 'a number' => [1];
        yield 'null' => [null];
    }

    /**
     * Anything but a real boolean is refused, naming the setting.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('provideMalformedValues')]
    public function testRefusesAnythingButABoolean(mixed $value): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('`audit-log.require_explicit_keys` must be true or false.');

        ExplicitKeys::required(new Repository(['audit-log' => ['require_explicit_keys' => $value]]));
    }

    /**
     * The refusal of an empty key names the key and the setting.
     *
     * @return void
     */
    public function testTheRefusalNamesTheKey(): void
    {
        self::assertSame(
            '`audit-log.redaction.key` must be set while `audit-log.require_explicit_keys` is on.',
            ExplicitKeys::missing('audit-log.redaction.key'),
        );
    }
}
