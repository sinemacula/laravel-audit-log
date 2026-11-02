<?php

declare(strict_types = 1);

namespace Tests\Unit\Runtime;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Runtime\ContextSettings;

/**
 * Unit tests for the context settings: the default each missing key takes, the
 * list of guards, the two trust flags and the header name they read, everything
 * they fail closed on, and the values no message ever shows.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ContextSettings::class)]
final class ContextSettingsTest extends TestCase
{
    /** @var string The refusal of anything but `null` or a list of guard names. */
    private const string MALFORMED_GUARDS = '`audit-log.actor.guards` must be null, or a list of guard names of 1 to 64 characters.';

    /** @var string The refusal of a malformed header name. */
    private const string MALFORMED_HEADER = '`audit-log.context.request_id_header` must be a header name of 1 to 64 characters.';

    /** @var string The refusal of anything but a boolean for the request id's flag. */
    private const string MALFORMED_REQUEST_ID_FLAG = '`audit-log.context.trust_request_id` must be true or false.';

    /** @var string The refusal of anything but a boolean for the `traceparent`'s flag. */
    private const string MALFORMED_TRACEPARENT_FLAG = '`audit-log.context.trust_traceparent` must be true or false.';

    /**
     * With no setting, or a `null` one, no list of guards is configured: the
     * actor is read from the default guard.
     *
     * @return void
     */
    public function testGuardsDefaultToNone(): void
    {
        self::assertNull((new ContextSettings(new Repository))->guards());
        self::assertNull(self::settings([])->guards());
        self::assertNull(self::settings(['actor' => ['guards' => null]])->guards());
    }

    /**
     * Rows of `[guards]`: one guard, several in the order they are checked, and
     * the bounds of a name, in single-byte and in multi-byte characters.
     *
     * @return iterable<string, array{0: non-empty-list<string>}>
     */
    public static function provideGuardLists(): iterable
    {
        yield from [
            'one guard'                => [['web']],
            'in the order given'       => [['web', 'api', 'admin']],
            'one character'            => [['w']],
            '64 characters'            => [[str_repeat('w', 64)]],
            '64 multi-byte characters' => [[str_repeat('é', 64)]],
        ];
    }

    /**
     * A list of guard names is kept whole and in order.
     *
     * @param  non-empty-list<string>  $guards
     * @return void
     */
    #[DataProvider('provideGuardLists')]
    public function testReadsAListOfGuards(array $guards): void
    {
        self::assertSame($guards, self::settings(['actor' => ['guards' => $guards]])->guards());
    }

    /**
     * Rows of `[guards]`: an empty list, a map, a list with a gap, other types,
     * including falsy ones that must not read as none, and lists holding a bad
     * name, first or later.
     *
     * @return iterable<string, array{0: array<int|string, int|string|null>|bool|int|string}>
     */
    public static function provideMalformedGuardLists(): iterable
    {
        yield from [
            'an empty list'           => [[]],
            'a map'                   => [['default' => 'web']],
            'a list with a gap'       => [[1 => 'web']],
            'a string'                => ['web'],
            'an empty string'         => [''],
            'an integer'              => [42],
            'zero'                    => [0],
            'true'                    => [true],
            'false'                   => [false],
            'holding an integer'      => [[42]],
            'holding null'            => [[null]],
            'a bad name after a good' => [['web', 42]],
            'holding an empty name'   => [['']],
            'holding 65 characters'   => [[str_repeat('w', 65)]],
            'holding 65 multi-byte'   => [[str_repeat('é', 65)]],
            'holding a control'       => [["we\x01b"]],
            'holding a line feed'     => [["web\n"]],
            'holding invalid UTF-8'   => [["web\xFF"]],
        ];
    }

    /**
     * Each malformed list fails closed, rather than reading as the default
     * guard or skipping the bad name, either of which could name another actor.
     *
     * @param  array<int|string, int|string|null>|bool|int|string  $guards
     * @return void
     */
    #[DataProvider('provideMalformedGuardLists')]
    public function testRefusesEachMalformedGuardList(array|bool|int|string $guards): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::MALFORMED_GUARDS);

        self::settings(['actor' => ['guards' => $guards]])->guards();
    }

    /**
     * With no setting neither inbound header is trusted.
     *
     * @return void
     */
    public function testTrustDefaultsToOff(): void
    {
        foreach ([new ContextSettings(new Repository), self::settings([]), self::settings(['context' => []])] as $settings) {
            self::assertFalse($settings->trustsRequestId());
            self::assertFalse($settings->trustsTraceparent());
        }
    }

    /**
     * Each flag reads its own key, on and off, whatever the other holds.
     *
     * @return void
     */
    public function testReadsEachTrustFlag(): void
    {
        $requestId = self::settings(['context' => ['trust_request_id' => true, 'trust_traceparent' => false]]);

        self::assertTrue($requestId->trustsRequestId());
        self::assertFalse($requestId->trustsTraceparent());

        $traceparent = self::settings(['context' => ['trust_request_id' => false, 'trust_traceparent' => true]]);

        self::assertFalse($traceparent->trustsRequestId());
        self::assertTrue($traceparent->trustsTraceparent());
    }

    /**
     * Rows of `[flag's key, its value, the expected message]`: for each flag,
     * truthy and falsy values of every other type, and a `null` set explicitly,
     * which is not a missing key.
     *
     * @return iterable<string, array{0: 'trust_request_id'|'trust_traceparent', 1: array<never, never>|int|string|null, 2: string}>
     */
    public static function provideNonBooleanFlags(): iterable
    {
        $messages = ['trust_request_id' => self::MALFORMED_REQUEST_ID_FLAG, 'trust_traceparent' => self::MALFORMED_TRACEPARENT_FLAG];
        $values   = [
            'the string 1'     => '1',
            'the string 0'     => '0',
            'the integer 1'    => 1,
            'the integer 0'    => 0,
            'yes'              => 'yes',
            'the string true'  => 'true',
            'an empty string'  => '',
            'an empty array'   => [],
            'an explicit null' => null,
        ];

        foreach ($messages as $key => $message) {
            foreach ($values as $label => $value) {
                yield $key . ', ' . $label => [$key, $value, $message];
            }
        }
    }

    /**
     * Only a real boolean passes for either flag, so a truthy string never
     * turns trust on.
     *
     * @param  'trust_request_id'|'trust_traceparent'  $key
     * @param  array<never, never>|int|string|null  $value
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideNonBooleanFlags')]
    public function testRefusesAnythingButABooleanForEachFlag(string $key, array|int|string|null $value, string $message): void
    {
        $settings = self::settings(['context' => [$key => $value]]);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        $key === 'trust_request_id' ? $settings->trustsRequestId() : $settings->trustsTraceparent();
    }

    /**
     * With no setting the request id comes under `X-Request-Id`.
     *
     * @return void
     */
    public function testTheHeaderDefaultsToXRequestId(): void
    {
        self::assertSame('X-Request-Id', (new ContextSettings(new Repository))->requestIdHeader());
        self::assertSame('X-Request-Id', self::settings(['context' => []])->requestIdHeader());
    }

    /**
     * Rows of `[header]`: an ordinary name, the bounds of the length, and every
     * character an RFC 9110 token may hold.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideHeaders(): iterable
    {
        yield from [
            'an ordinary name' => ['X-Correlation-Id'],
            'one character'    => ['X'],
            '64 characters'    => [str_repeat('x', 64)],
            'every symbol'     => ['!#$%&\'*+-.^_`|~'],
            'every digit'      => ['0123456789'],
            'lower case'       => ['abcdefghijklmnopqrstuvwxyz'],
            'upper case'       => ['ABCDEFGHIJKLMNOPQRSTUVWXYZ'],
        ];
    }

    /**
     * A configured header name is kept as given.
     *
     * @param  string  $header
     * @return void
     */
    #[DataProvider('provideHeaders')]
    public function testReadsAConfiguredHeader(string $header): void
    {
        self::assertSame($header, self::settings(['context' => ['request_id_header' => $header]])->requestIdHeader());
    }

    /**
     * Rows of `[header]`: what is no token of 1 to 64 characters, and what is
     * no string. A `null` set explicitly is not a missing key.
     *
     * @return iterable<string, array{0: array<never, never>|bool|int|string|null}>
     */
    public static function provideMalformedHeaders(): iterable
    {
        yield from [
            'empty'              => [''],
            'space'              => ['X Request Id'],
            'colon'              => ['X-Request-Id:'],
            '65 characters'      => [str_repeat('x', 65)],
            'an integer'         => [42],
            'CR LF'              => ["X-Request-Id\r\n"],
            'a trailing newline' => ["X-Request-Id\n"],
            'a leading newline'  => ["\nX-Request-Id"],
            'a parenthesis'      => ['X(Request)'],
            'non-ASCII'          => ['X-Requêst-Id'],
            'an explicit null'   => [null],
            'true'               => [true],
            'an array'           => [[]],
        ];
    }

    /**
     * Each malformed header name fails closed, so a request never reads a
     * header the setting did not properly name.
     *
     * @param  array<never, never>|bool|int|string|null  $header
     * @return void
     */
    #[DataProvider('provideMalformedHeaders')]
    public function testRefusesEachMalformedHeaderName(array|bool|int|string|null $header): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::MALFORMED_HEADER);

        self::settings(['context' => ['request_id_header' => $header]])->requestIdHeader();
    }

    /**
     * Rows of `[configuration, the expected message]`: one malformed setting
     * each, with every other left well formed.
     *
     * @return iterable<string, array{0: array<string, array<string, array<never, never>|string>>, 1: string}>
     */
    public static function provideEverySetting(): iterable
    {
        yield from [
            'the guards'           => [['actor' => ['guards' => []]], self::MALFORMED_GUARDS],
            'the request id flag'  => [['context' => ['trust_request_id' => 'yes']], self::MALFORMED_REQUEST_ID_FLAG],
            'the header name'      => [['context' => ['request_id_header' => 'X Request Id']], self::MALFORMED_HEADER],
            'the traceparent flag' => [['context' => ['trust_traceparent' => 'yes']], self::MALFORMED_TRACEPARENT_FLAG],
        ];
    }

    /**
     * `validate()` reads every setting, failing on whichever is malformed.
     *
     * @param  array<string, array<string, array<never, never>|string>>  $config
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideEverySetting')]
    public function testValidateReadsEverySetting(array $config, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        self::settings($config)->validate();
    }

    /**
     * `validate()` passes on every default, and on every setting well formed.
     *
     * @return void
     */
    public function testValidatePassesOnWellFormedSettings(): void
    {
        self::settings([])->validate();
        self::settings([
            'actor'   => ['guards' => ['web', 'api']],
            'context' => ['trust_request_id' => true, 'request_id_header' => 'X-Correlation-Id', 'trust_traceparent' => true],
        ])->validate();

        $this->addToAssertionCount(2);
    }

    /**
     * Rows of `[configuration]`: a value a message could repeat, under each
     * setting.
     *
     * @return iterable<string, array{0: array<string, array<string, list<string>|string>>}>
     */
    public static function provideRefusedValues(): iterable
    {
        yield from [
            'a guard'        => [['actor' => ['guards' => ['leaked' . str_repeat('x', 100)]]]],
            'a guard string' => [['actor' => ['guards' => 'leaked']]],
            'the header'     => [['context' => ['request_id_header' => 'leaked value']]],
            'a flag'         => [['context' => ['trust_request_id' => 'leaked']]],
            'other flag'     => [['context' => ['trust_traceparent' => 'leaked']]],
        ];
    }

    /**
     * No refusal repeats the value it refuses, so a setting mistyped with
     * something sensitive never reaches a log.
     *
     * @param  array<string, array<string, list<string>|string>>  $config
     * @return void
     */
    #[DataProvider('provideRefusedValues')]
    public function testNoMessageHoldsTheValue(array $config): void
    {
        try {
            self::settings($config)->validate();
            self::fail('Expected the value to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertStringNotContainsString('leaked', $exception->getMessage());
        }
    }

    /**
     * The settings over the given `audit-log` configuration.
     *
     * @param  array<string, array<string, array<int|string, int|string|null>|bool|int|string|null>>  $config
     * @return \SineMacula\Laravel\AuditLog\Runtime\ContextSettings
     */
    private static function settings(array $config): ContextSettings
    {
        return new ContextSettings(new Repository(['audit-log' => $config]));
    }
}
