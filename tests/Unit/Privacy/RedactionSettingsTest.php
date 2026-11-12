<?php

declare(strict_types = 1);

namespace Tests\Unit\Privacy;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Privacy\Enums\IdentifierMode;
use SineMacula\Laravel\AuditLog\Privacy\Enums\IpMode;
use SineMacula\Laravel\AuditLog\Privacy\RedactionSettings;

/**
 * Unit tests for the redaction settings: defaults, accepted values, exact
 * failure messages, the root key, readers, and what none shows.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RedactionSettings::class)]
final class RedactionSettingsTest extends TestCase
{
    /** @var string The refusal of malformed key names. */
    private const string KEYS = '`audit-log.redaction.keys` must be a list of key names, each of at least one token.';

    /** @var string The refusal of a malformed explicit key. */
    private const string KEY = '`audit-log.redaction.key` must be at least 32 bytes, or `base64:` followed by the encoding of at least 32 bytes.';

    /** @var string The refusal of a missing application key. */
    private const string APP_KEY_MISSING = '`app.key` must be set to derive the redaction key when `audit-log.redaction.key` is empty.';

    /** @var string The refusal of a malformed application key. */
    private const string APP_KEY_MALFORMED = '`app.key` must be at least 32 bytes, or `base64:` followed by the encoding of at least 32 bytes, to derive the redaction key.';

    /** @var string The refusal of an unknown identifier mode. */
    private const string IDENTIFIERS = '`audit-log.redaction.identifiers` must be `hash` or `drop`.';

    /** @var string The refusal of an unknown IP mode. */
    private const string IP = '`audit-log.redaction.ip` must be `full`, `truncate`, `hash`, `drop` or `encrypt`.';

    /** @var string The refusal of a properties budget out of range. */
    private const string MAX_BYTES = '`audit-log.redaction.max_bytes` must be an integer from 8192 to 16777216.';

    /** @var string The refusal of a context budget out of range. */
    private const string MAX_CONTEXT_BYTES = '`audit-log.redaction.max_context_bytes` must be an integer from 1024 to 16777216.';

    /** @var string A secret given as its own 32 bytes. */
    private const string RAW_SECRET = 'redaction-root-secret-of-32-byte';

    /** @var string A secret given as `base64:` of 32 bytes of 0xAB. */
    private const string BASE64_SECRET = 'base64:q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s=';

    /**
     * With nothing set, or none of the package's configuration at all, every
     * setting takes its default.
     *
     * @return void
     */
    public function testTheDefaultsApplyWhenNothingIsSet(): void
    {
        foreach ([new RedactionSettings(new Repository), self::settings([])] as $settings) {
            self::assertSame([], $settings->keys());
            self::assertNull($settings->explicitKey());
            self::assertSame(IdentifierMode::HASH, $settings->identifierMode());
            self::assertSame(IpMode::FULL, $settings->ipMode());
            self::assertSame(16384, $settings->maxBytes());
            self::assertSame(4096, $settings->maxContextBytes());
        }
    }

    /**
     * Each read goes back to the configuration, so a change is seen by the next
     * read and the settings hold nothing between calls.
     *
     * @return void
     */
    public function testEachSettingIsReadOnEveryCall(): void
    {
        $config   = new Repository(['app' => ['key' => self::RAW_SECRET]]);
        $settings = new RedactionSettings($config);

        self::assertSame([[], null, self::RAW_SECRET, IdentifierMode::HASH, IpMode::FULL, 16384, 4096], self::values($settings));

        $explicit = str_repeat('b', 32);

        $config->set('audit-log.redaction', [
            'keys'              => ['ssn'],
            'key'               => $explicit,
            'identifiers'       => 'drop',
            'ip'                => 'hash',
            'max_bytes'         => 9000,
            'max_context_bytes' => 2000,
        ]);

        self::assertSame([[['ssn']], $explicit, $explicit, IdentifierMode::DROP, IpMode::HASH, 9000, 2000], self::values($settings));
    }

    /**
     * Each configured name comes back as its tokens, in the order given.
     *
     * @return void
     */
    public function testKeysAreTokenised(): void
    {
        self::assertSame(
            [['ssn'], ['ssn', 'number'], ['tax', 'id'], ['national', 'id']],
            self::settings(['keys' => ['SSN', 'ssnNumber', 'tax-id', 'national_id']])->keys(),
        );
    }

    /**
     * An empty list is no names, not a malformed list.
     *
     * @return void
     */
    public function testAnEmptyListOfKeysIsNone(): void
    {
        self::assertSame([], self::settings(['keys' => []])->keys());
    }

    /**
     * Rows of `[value]`: anything but a list of names that each have a token.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideMalformedKeys(): iterable
    {
        yield from [
            'a string'             => ['ssn'],
            'a map'                => [['first' => 'ssn']],
            'a list with a gap'    => [[1 => 'ssn']],
            'null'                 => [null],
            'a non-string entry'   => [['ssn', 5]],
            'a null entry'         => [[null]],
            'an empty entry'       => [['']],
            'a separator entry'    => [['ssn', '___']],
            'an invalid UTF-8 key' => [["ssn\xFF"]],
        ];
    }

    /**
     * Each malformed list fails closed with the one message.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('provideMalformedKeys')]
    public function testRefusesMalformedKeys(mixed $value): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::KEYS);

        self::settings(['keys' => $value])->keys();
    }

    /**
     * Every identifier mode is read by its stored value.
     *
     * @return void
     */
    public function testAcceptsEveryIdentifierMode(): void
    {
        foreach (IdentifierMode::cases() as $mode) {
            self::assertSame($mode, self::settings(['identifiers' => $mode->value])->identifierMode());
        }
    }

    /**
     * Rows of `[value]`: what names no mode of either kind, or is no string.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideUnknownModes(): iterable
    {
        yield from [
            'an unknown name'  => ['maybe'],
            'an integer'       => [1],
            'null'             => [null],
            'true'             => [true],
            'empty'            => [''],
            'upper case'       => ['HASH'],
            'padded'           => [' hash'],
            'a list'           => [['hash']],
            'the enum, itself' => [IdentifierMode::HASH],
        ];
    }

    /**
     * Each value that names no identifier mode fails closed with its message.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('provideUnknownModes')]
    public function testRefusesAnUnknownIdentifierMode(mixed $value): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::IDENTIFIERS);

        self::settings(['identifiers' => $value])->identifierMode();
    }

    /**
     * A mode of the other setting is no mode of this one.
     *
     * @return void
     */
    public function testAnIpOnlyModeIsNoIdentifierMode(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::IDENTIFIERS);

        self::settings(['identifiers' => 'full'])->identifierMode();
    }

    /**
     * Every IP mode is read by its stored value.
     *
     * @return void
     */
    public function testAcceptsEveryIpMode(): void
    {
        foreach (IpMode::cases() as $mode) {
            self::assertSame($mode, self::settings(['ip' => $mode->value])->ipMode());
        }
    }

    /**
     * Each value that names no IP mode fails closed with its message.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('provideUnknownModes')]
    public function testRefusesAnUnknownIpMode(mixed $value): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::IP);

        self::settings(['ip' => $value])->ipMode();
    }

    /**
     * Each budget takes its least and greatest value, as an integer and as the
     * digit string `env()` returns.
     *
     * @return void
     */
    public function testTheByteBudgetsAcceptTheirLimits(): void
    {
        foreach ([[8192, 8192], ['8192', 8192], [16777216, 16777216], ['16777216', 16777216]] as [$value, $expected]) {
            self::assertSame($expected, self::settings(['max_bytes' => $value])->maxBytes());
        }

        foreach ([[1024, 1024], ['1024', 1024], [16777216, 16777216], ['16777216', 16777216]] as [$value, $expected]) {
            self::assertSame($expected, self::settings(['max_context_bytes' => $value])->maxContextBytes());
        }
    }

    /**
     * One byte under its minimum is malformed, for each budget.
     *
     * @return void
     */
    public function testRefusesAByteBudgetBelowItsMinimum(): void
    {
        self::assertRefused(self::MAX_BYTES, static fn () => self::settings(['max_bytes' => 8191])->maxBytes());
        self::assertRefused(self::MAX_CONTEXT_BYTES, static fn () => self::settings(['max_context_bytes' => 1023])->maxContextBytes());
    }

    /**
     * One byte over the ceiling is malformed, for each budget.
     *
     * @return void
     */
    public function testRefusesAByteBudgetAboveItsMaximum(): void
    {
        self::assertRefused(self::MAX_BYTES, static fn () => self::settings(['max_bytes' => 16777217])->maxBytes());
        self::assertRefused(self::MAX_CONTEXT_BYTES, static fn () => self::settings(['max_context_bytes' => 16777217])->maxContextBytes());
    }

    /**
     * Rows of `[value]`: what is no integer or canonical digit string.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideMalformedBudgets(): iterable
    {
        yield from [
            'trailing letters' => ['8192x'],
            'padded'           => [' 8192'],
            'a float'          => [1.5],
            'a whole float'    => [8192.0],
            'null'             => [null],
            'a list'           => [[]],
            'true'             => [true],
            'empty'            => [''],
            'negative'         => [-8192],
        ];
    }

    /**
     * Each malformed budget fails closed with its own message, for each budget.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('provideMalformedBudgets')]
    public function testRefusesAMalformedByteBudget(mixed $value): void
    {
        self::assertRefused(self::MAX_BYTES, static fn () => self::settings(['max_bytes' => $value])->maxBytes());
        self::assertRefused(self::MAX_CONTEXT_BYTES, static fn () => self::settings(['max_context_bytes' => $value])->maxContextBytes());
    }

    /**
     * The explicit key is its own bytes, or the decoding of its `base64:` form.
     *
     * @return void
     */
    public function testTheExplicitKeyIsDecoded(): void
    {
        self::assertSame(self::RAW_SECRET, self::settings(['key' => self::RAW_SECRET])->explicitKey());
        self::assertSame(str_repeat("\xAB", 32), self::settings(['key' => self::BASE64_SECRET])->explicitKey());
    }

    /**
     * An empty value, which an empty environment line gives, and a `null`,
     * which an unset one gives, read as no explicit key.
     *
     * @return void
     */
    public function testAnEmptyExplicitKeyReadsAsNone(): void
    {
        self::assertNull(self::settings(['key' => ''])->explicitKey());
        self::assertNull(self::settings(['key' => null])->explicitKey());
        self::assertSame(self::RAW_SECRET, self::settings(['key' => ''], ['key' => self::RAW_SECRET])->rootKey());
    }

    /**
     * Rows of `[value]`: explicit keys that are too short, do not decode or are
     * not strings.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideMalformedExplicitKeys(): iterable
    {
        yield from [
            '31 raw bytes'          => [str_repeat('a', 31)],
            'base64 of 31 bytes'    => ['base64:' . base64_encode(str_repeat('a', 31))],
            'base64 that is broken' => ['base64:' . str_repeat('*', 40)],
            'a bare prefix'         => ['base64:'],
            'an integer'            => [5],
            'false'                 => [false],
            'a list'                => [[self::RAW_SECRET]],
            'an empty list'         => [[]],
        ];
    }

    /**
     * A malformed explicit key fails closed.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('provideMalformedExplicitKeys')]
    public function testAMalformedExplicitKeyFailsClosed(mixed $value): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::KEY);

        self::settings(['key' => $value])->explicitKey();
    }

    /**
     * A malformed explicit key is refused by the root key too, however good the
     * application key beside it.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('provideMalformedExplicitKeys')]
    public function testAMalformedExplicitKeyNeverFallsBackToTheApplicationKey(mixed $value): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::KEY);

        self::settings(['key' => $value], ['key' => self::RAW_SECRET])->rootKey();
    }

    /**
     * A valid explicit key wins, and the application key is not read, so a
     * malformed one beside it does not matter.
     *
     * @return void
     */
    public function testTheExplicitKeyIsTheRootKey(): void
    {
        self::assertSame(self::RAW_SECRET, self::settings(['key' => self::RAW_SECRET], ['key' => str_repeat('b', 32)])->rootKey());
        self::assertSame(self::RAW_SECRET, self::settings(['key' => self::RAW_SECRET], ['key' => 'short'])->rootKey());
        self::assertSame(self::RAW_SECRET, self::settings(['key' => self::RAW_SECRET])->rootKey());
    }

    /**
     * With no explicit key, the root key is the application key's own bytes.
     *
     * @return void
     */
    public function testTheRootKeyFallsBackToTheApplicationKey(): void
    {
        self::assertSame(self::RAW_SECRET, self::settings([], ['key' => self::RAW_SECRET])->rootKey());
    }

    /**
     * An application key as Laravel writes it is decoded.
     *
     * @return void
     */
    public function testAnApplicationKeyInBase64IsDecoded(): void
    {
        self::assertSame(str_repeat("\xAB", 32), self::settings([], ['key' => self::BASE64_SECRET])->rootKey());
    }

    /**
     * Rows of `[application configuration]`: no application key to speak of.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: array<string, mixed>}>
     */
    public static function provideMissingApplicationKeys(): iterable
    {
        yield from [
            'not set'  => [[]],
            'null'     => [['key' => null]],
            'empty'    => [['key' => '']],
            'a number' => [['key' => 5]],
        ];
    }

    /**
     * With neither key, the root key is refused and names the two settings.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $app
     * @return void
     */
    #[DataProvider('provideMissingApplicationKeys')]
    public function testAMissingApplicationKeyIsRefused(array $app): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::APP_KEY_MISSING);

        self::settings([], $app)->rootKey();
    }

    /**
     * An application key that is too short or does not decode is refused with
     * its own message.
     *
     * @return void
     */
    public function testAMalformedApplicationKeyIsRefused(): void
    {
        self::assertRefused(self::APP_KEY_MALFORMED, static fn () => self::settings([], ['key' => str_repeat('a', 31)])->rootKey());
        self::assertRefused(self::APP_KEY_MALFORMED, static fn () => self::settings([], ['key' => 'base64:' . str_repeat('*', 40)])->rootKey());
        self::assertRefused(self::APP_KEY_MALFORMED, static fn () => self::settings([], ['key' => 'base64:' . base64_encode(str_repeat('a', 31))])->rootKey());
    }

    /**
     * Rows of `[redaction configuration, application configuration]`: a
     * sentinel in every leaf, and in the application key.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: array<string, mixed>}>
     */
    public static function provideSentinels(): iterable
    {
        yield from [
            'keys as a string'      => [['keys' => 'S3NTINEL'], []],
            'keys with a bad entry' => [['keys' => ['S3NTINEL', 5]], []],
            'key'                   => [['key' => 'S3NTINEL'], []],
            'key in base64'         => [['key' => 'base64:S3NTINEL*'], []],
            'identifiers'           => [['identifiers' => 'S3NTINEL'], []],
            'ip'                    => [['ip' => 'S3NTINEL'], []],
            'max_bytes'             => [['max_bytes' => 'S3NTINEL'], []],
            'max_context_bytes'     => [['max_context_bytes' => 'S3NTINEL'], []],
            'app.key'               => [[], ['key' => 'S3NTINEL']],
            'app.key in base64'     => [[], ['key' => 'base64:S3NTINEL*']],
        ];
    }

    /**
     * No refusal shows the value it refused, in its message or in the arguments
     * of the settings' own frames of its stack trace, whichever setting it was.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $redaction
     * @param  array<string, mixed>  $app
     * @return void
     */
    #[DataProvider('provideSentinels')]
    public function testNoMessageHoldsTheValue(array $redaction, array $app): void
    {
        $previous = ini_set('zend.exception_ignore_args', '0');
        $settings = self::settings($redaction, $app);

        try {
            $settings->validate();
            $settings->rootKey();
            self::fail('Expected the value to be refused.');
        } catch (\InvalidArgumentException $exception) {
            $frames = array_filter($exception->getTrace(), static fn (array $frame): bool => ($frame['class'] ?? null) === RedactionSettings::class);

            self::assertNotSame([], $frames);
            self::assertStringNotContainsString('S3NTINEL', $exception->getMessage());
            self::assertStringNotContainsString('S3NTINEL', print_r($frames, true));
        } finally {
            ini_set('zend.exception_ignore_args', $previous === false ? '0' : $previous);
        }
    }

    /**
     * Rows of `[setting, value, message]`: one malformed leaf at a time, each
     * of those `validate()` reads.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: string, 1: mixed, 2: string}>
     */
    public static function provideMalformedLeaves(): iterable
    {
        yield from [
            'keys'              => ['keys', 'ssn', self::KEYS],
            'key'               => ['key', 'short', self::KEY],
            'identifiers'       => ['identifiers', 'maybe', self::IDENTIFIERS],
            'ip'                => ['ip', 'maybe', self::IP],
            'max_bytes'         => ['max_bytes', 8191, self::MAX_BYTES],
            'max_context_bytes' => ['max_context_bytes', 1023, self::MAX_CONTEXT_BYTES],
        ];
    }

    /**
     * `validate()` reads every setting: each malformed one fails it, alone,
     * with its own message.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $setting
     * @param  mixed  $value
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMalformedLeaves')]
    public function testValidateReadsEverySetting(string $setting, mixed $value, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        self::settings([$setting => $value])->validate();
    }

    /**
     * With every setting malformed, `validate()` fails on the first in its
     * order, then the next once that one is put right.
     *
     * @return void
     */
    public function testTheFirstMalformedSettingWins(): void
    {
        $redaction = [];

        foreach (self::provideMalformedLeaves() as [$setting, $value]) {
            $redaction[$setting] = $value;
        }

        foreach (self::provideMalformedLeaves() as [$setting, , $message]) {
            self::assertRefused($message, static fn () => self::settings($redaction)->validate());

            unset($redaction[$setting]);
        }

        self::settings($redaction)->validate();

        $this->addToAssertionCount(1);
    }

    /**
     * `validate()` needs no application key: one that is missing or malformed
     * is judged only once a hash is needed.
     *
     * @return void
     */
    public function testValidateDoesNotNeedTheApplicationKey(): void
    {
        self::settings([])->validate();
        self::settings([], ['key' => 'short'])->validate();

        self::assertRefused(self::APP_KEY_MISSING, static fn () => self::settings([])->rootKey());
    }

    /**
     * Every setting, read once: the key names, the explicit key, the root key,
     * the two modes and the two budgets.
     *
     * @param  \SineMacula\Laravel\AuditLog\Privacy\RedactionSettings  $settings
     * @return list<\BackedEnum|int|list<non-empty-list<string>>|string|null>
     */
    private static function values(RedactionSettings $settings): array
    {
        return [
            $settings->keys(),
            $settings->explicitKey(),
            $settings->rootKey(),
            $settings->identifierMode(),
            $settings->ipMode(),
            $settings->maxBytes(),
            $settings->maxContextBytes(),
        ];
    }

    /**
     * Assert the call fails closed with exactly the message.
     *
     * @param  string  $message
     * @param  \Closure(): (array<int, array<int, string>>|int|string|void|null)  $call
     * @return void
     */
    private static function assertRefused(string $message, \Closure $call): void
    {
        try {
            $call();
            self::fail(sprintf('Expected the call to be refused with: %s', $message));
        } catch (\InvalidArgumentException $exception) {
            self::assertSame($message, $exception->getMessage());
        }
    }

    /**
     * Settings over a plain repository holding the redaction settings and the
     * application settings.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $redaction
     * @param  array<string, mixed>  $app
     * @return \SineMacula\Laravel\AuditLog\Privacy\RedactionSettings
     */
    private static function settings(array $redaction, array $app = []): RedactionSettings
    {
        return new RedactionSettings(new Repository(['audit-log' => ['redaction' => $redaction], 'app' => $app]));
    }
}
