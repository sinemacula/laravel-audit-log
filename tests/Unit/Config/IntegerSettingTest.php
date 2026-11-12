<?php

declare(strict_types = 1);

namespace Tests\Unit\Config;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Config\IntegerSetting;

/**
 * Unit tests for the integer setting reader every settings class shares.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IntegerSetting::class)]
final class IntegerSettingTest extends TestCase
{
    /** @var string The key the tests read. */
    private const string KEY = 'audit-log.example.ttl_seconds';

    /**
     * A setting that is not configured takes the default, which the caller
     * chooses.
     *
     * @return void
     */
    public function testTheDefaultAppliesWhenTheKeyIsNotSet(): void
    {
        self::assertSame(600, IntegerSetting::read(new Repository, self::KEY, 600, 60, 3600));
    }

    /**
     * Rows of `[value, least, greatest, what the reader returns]`: integers and
     * the digit strings `env()` returns, at each end of the range and between.
     *
     * @return iterable<string, array{0: int|string, 1: int, 2: int, 3: int}>
     */
    public static function provideAcceptedValues(): iterable
    {
        yield from [
            'least integer'        => [60, 60, 3600, 60],
            'greatest integer'     => [3600, 60, 3600, 3600],
            'least as a string'    => ['60', 60, 3600, 60],
            'greatest as a string' => ['3600', 60, 3600, 3600],
            'between, as a string' => ['900', 60, 3600, 900],
            'zero as a string'     => ['0', 0, 10, 0],
            'nine digits'          => ['999999999', 0, 999999999, 999999999],
            'a nine-digit integer' => [999999999, 0, 999999999, 999999999],
            'ten digits in range'  => ['1000000000', 0, PHP_INT_MAX, 1000000000],
        ];
    }

    /**
     * Each accepted value is read as the integer it names.
     *
     * @param  int|string  $value
     * @param  int  $least
     * @param  int  $most
     * @param  int  $expected
     * @return void
     */
    #[DataProvider('provideAcceptedValues')]
    public function testReadsIntegersAndTheirDigitStrings(int|string $value, int $least, int $most, int $expected): void
    {
        $config = new Repository([]);

        $config->set(self::KEY, $value);

        self::assertSame($expected, IntegerSetting::read($config, self::KEY, 600, $least, $most));
    }

    /**
     * Rows of malformed or out-of-range values.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideRefusedValues(): iterable
    {
        yield from [
            'below the least'         => [59],
            'above the greatest'      => [3601],
            'below, as a string'      => ['59'],
            'above, as a string'      => ['3601'],
            'padded'                  => ['0600'],
            'signed'                  => ['+600'],
            'negative string'         => ['-600'],
            'with a trailing newline' => ["600\n"],
            'with leading space'      => [' 600'],
            'an exponent'             => ['6e2'],
            'a decimal string'        => ['600.0'],
            'ten digits'              => ['1000000000'],
            'a float'                 => [600.0],
            'null'                    => [null],
            'a boolean'               => [true],
            'an empty string'         => [''],
            'a list'                  => [[600]],
        ];
    }

    /**
     * Anything else fails closed, naming the key and the range.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('provideRefusedValues')]
    public function testRefusesAnythingElse(mixed $value): void
    {
        $config = new Repository([]);

        $config->set(self::KEY, $value);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('audit-log.example.ttl_seconds must be an integer from 60 to 3600.');

        IntegerSetting::read($config, self::KEY, 600, 60, 3600);
    }

    /**
     * A value already read is judged as a configured one is: within its range
     * it is returned, and one past either end fails naming the key.
     *
     * @return void
     */
    public function testFromJudgesAValueAlreadyRead(): void
    {
        self::assertSame(60, IntegerSetting::from(self::KEY, '60', 60, 3600));
        self::assertSame(3600, IntegerSetting::from(self::KEY, 3600, 60, 3600));

        foreach ([59, '3601', null] as $value) {

            try {
                IntegerSetting::from(self::KEY, $value, 60, 3600);
                self::fail('Expected the value to be refused.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('audit-log.example.ttl_seconds must be an integer from 60 to 3600.', $exception->getMessage());
            }
        }
    }

    /**
     * Rows of `[value, the integer it names or null]`: the one form every
     * numeric setting accepts.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: mixed, 1: ?int}>
     */
    public static function provideParsedValues(): iterable
    {
        yield from [
            'an integer'               => [42, 42],
            'zero'                     => [0, 0],
            'a negative integer'       => [-5, -5],
            'the greatest integer'     => [PHP_INT_MAX, PHP_INT_MAX],
            'a digit string'           => ['42', 42],
            'zero as a string'         => ['0', 0],
            'a negative string'        => ['-5', -5],
            'the greatest as a string' => [(string) PHP_INT_MAX, PHP_INT_MAX],
            'the least as a string'    => [(string) PHP_INT_MIN, PHP_INT_MIN],
            'past the greatest'        => ['9223372036854775808', null],
            'past the least'           => ['-9223372036854775809', null],
            'negative zero'            => ['-0', null],
            'a plus sign'              => ['+42', null],
            'padded'                   => ['042', null],
            'leading space'            => [' 42', null],
            'trailing newline'         => ["42\n", null],
            'an exponent'              => ['4e1', null],
            'hexadecimal'              => ['0x2A', null],
            'a decimal string'         => ['42.0', null],
            'a word'                   => ['forty-two', null],
            'an empty string'          => ['', null],
            'a float'                  => [42.0, null],
            'null'                     => [null, null],
            'true'                     => [true, null],
            'a list'                   => [[42], null],
            'a stringable'             => [new class implements \Stringable {
                /**
                 * The digits.
                 *
                 * @return string
                 */
                #[\Override]
                public function __toString(): string
                {
                    return '42';
                }
            }, null],
        ];
    }

    /**
     * Only an integer or its exact decimal form parses, so a string past the
     * integer range that a cast would saturate does not.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @param  ?int  $expected
     * @return void
     */
    #[DataProvider('provideParsedValues')]
    public function testParseReadsOnlyIntegersAndTheirExactDecimalForm(mixed $value, ?int $expected): void
    {
        self::assertSame($expected, IntegerSetting::parse($value));
    }

    /**
     * The constructor is private; reflection invokes it to cover the line.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(IntegerSetting::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(IntegerSetting::class, $instance);
    }
}
