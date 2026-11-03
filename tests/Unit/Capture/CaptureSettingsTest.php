<?php

declare(strict_types = 1);

namespace Tests\Unit\Capture;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Capture\CaptureSettings;

/**
 * Unit tests for the capture settings: the default each missing key takes, the
 * guards the core capture skips, the one credential key, the Gate flag and the
 * abilities it selects, the reason codes, the two bulk bounds, everything they
 * fail closed on, and the values no message ever shows.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CaptureSettings::class)]
final class CaptureSettingsTest extends TestCase
{
    /** @var string The refusal of anything but a list of guard names, or the wildcard alone. */
    private const string MALFORMED_EXCEPT_GUARDS = '`audit-log.capture.laravel.except_guards` must be a list of guard names of 1 to 64 characters, or `[\'*\']`.';

    /** @var string The refusal of a credential key outside its grammar. */
    private const string MALFORMED_IDENTIFIER_KEY = '`audit-log.capture.laravel.identifier_key` must be 1 to 64 letters, digits, underscores, dots or hyphens,'
        . ' starting with a letter, a digit or an underscore.';

    /** @var string The refusal of anything but a boolean for the Gate flag. */
    private const string MALFORMED_GATE_ENABLED = '`audit-log.capture.gate.enabled` must be true or false.';

    /** @var string The refusal of malformed only abilities. */
    private const string MALFORMED_ONLY_ABILITIES = '`audit-log.capture.gate.only_abilities` must be null, or a non-empty list of abilities of 1 to 191 bytes.';

    /** @var string The refusal of malformed excepted abilities. */
    private const string MALFORMED_EXCEPT_ABILITIES = '`audit-log.capture.gate.except_abilities` must be a list of abilities of 1 to 191 bytes.';

    /** @var string The refusal of malformed reason codes. */
    private const string MALFORMED_REASON_CODES = '`audit-log.capture.gate.reason_codes` must be a list of machine-readable codes of 1 to 64 characters:'
        . ' lower-case letters, digits, `_`, `.`, `:` or `-`, starting with a letter or a digit.';

    /** @var string What a test's bad value carries, and no message may hold. */
    private const string SENTINEL = 'sentinel-7f3a9c';

    /**
     * With no setting no guard is excepted, so every core event is recorded
     * whatever guard it names.
     *
     * @return void
     */
    public function testExceptGuardsDefaultToNone(): void
    {
        foreach ([new CaptureSettings(new Repository), self::settings([]), self::settings(['laravel' => []])] as $settings) {
            self::assertSame([], $settings->exceptGuards());
            self::assertFalse($settings->excludesGuard('web'));
            self::assertFalse($settings->excludesGuard(null));
        }

        self::assertSame([], self::settings(['laravel' => ['except_guards' => []]])->exceptGuards());
    }

    /**
     * A list of names is kept whole and in order, a name is excluded exactly
     * when the list holds it, compared exactly, and a name at either bound of
     * its length, counted in characters, is accepted.
     *
     * @return void
     */
    public function testExceptGuardsAreAListOfNames(): void
    {
        $longest  = str_repeat('é', CaptureSettings::GUARD_MAX_CHARACTERS);
        $settings = self::exceptGuards(['api', 'w', $longest]);

        self::assertSame(['api', 'w', $longest], $settings->exceptGuards());
        self::assertTrue($settings->excludesGuard('api'));
        self::assertTrue($settings->excludesGuard('w'));
        self::assertTrue($settings->excludesGuard($longest));
        self::assertFalse($settings->excludesGuard('web'));
        self::assertFalse($settings->excludesGuard('API'));
        self::assertFalse($settings->excludesGuard('api '));
        self::assertFalse($settings->excludesGuard('*'));
        self::assertFalse($settings->excludesGuard(''));
    }

    /**
     * Under `['*']` every guard is excluded, a name that only looks like the
     * wildcard included.
     *
     * @return void
     */
    public function testEveryGuardIsExcludedUnderTheWildcard(): void
    {
        $settings = self::exceptGuards([CaptureSettings::ALL_GUARDS]);

        self::assertSame('*', CaptureSettings::ALL_GUARDS);
        self::assertSame(['*'], $settings->exceptGuards());
        self::assertTrue($settings->excludesGuard('web'));
        self::assertTrue($settings->excludesGuard('api'));
        self::assertTrue($settings->excludesGuard('*'));
    }

    /**
     * An event that names no guard is excluded only under the wildcard: a list
     * of names never holds it, whatever names it holds.
     *
     * @return void
     */
    public function testAGuardlessEventIsExcludedOnlyUnderTheWildcard(): void
    {
        self::assertTrue(self::exceptGuards(['*'])->excludesGuard(null));
        self::assertFalse(self::exceptGuards(['web'])->excludesGuard(null));
        self::assertFalse(self::exceptGuards(['web', 'api'])->excludesGuard(null));
        self::assertFalse(self::exceptGuards([])->excludesGuard(null));
    }

    /**
     * Rows of `[except guards]`: a string, a map, a list with a gap, an
     * explicit `null`, a member that is not a string, an empty or over-long
     * name, one that is not clean text, and the wildcard beside a name or
     * repeated.
     *
     * @return iterable<string, array{0: array<int|string, int|string|null>|string|null}>
     */
    public static function provideMalformedExceptGuards(): iterable
    {
        yield from [
            'a string'                => ['web'],
            'the wildcard alone'      => ['*'],
            'a map'                   => [['default' => 'web']],
            'a list with a gap'       => [[1 => 'web']],
            'an explicit null'        => [null],
            'an integer member'       => [[42]],
            'a null member'           => [[null]],
            'an empty name'           => [['']],
            '65 characters'           => [[str_repeat('w', 65)]],
            '65 multi-byte'           => [[str_repeat('é', 65)]],
            'a control character'     => [["we\x01b"]],
            'a line feed'             => [["web\n"]],
            'invalid UTF-8'           => [["web\xFF"]],
            'a bad name after a good' => [['web', '']],
            'the wildcard and a name' => [['*', 'web']],
            'a name and the wildcard' => [['web', '*']],
            'the wildcard twice'      => [['*', '*']],
        ];
    }

    /**
     * Each malformed list fails closed, both when it is read and when a guard
     * is asked about, rather than skipping a bad name or recording every event.
     *
     * @param  array<int|string, int|string|null>|string|null  $guards
     * @return void
     */
    #[DataProvider('provideMalformedExceptGuards')]
    public function testRefusesMalformedExceptGuards(array|string|null $guards): void
    {
        $settings = self::exceptGuards($guards);

        self::assertRefused(self::MALFORMED_EXCEPT_GUARDS, $settings->exceptGuards(...));
        self::assertRefused(self::MALFORMED_EXCEPT_GUARDS, static fn (): bool => $settings->excludesGuard('web'));
        self::assertRefused(self::MALFORMED_EXCEPT_GUARDS, static fn (): bool => $settings->excludesGuard(null));
    }

    /**
     * With no setting the credential a failed sign-in is read for is `email`.
     *
     * @return void
     */
    public function testTheIdentifierKeyDefaultsToEmail(): void
    {
        self::assertSame('email', (new CaptureSettings(new Repository))->identifierKey());
        self::assertSame('email', self::settings(['laravel' => []])->identifierKey());
    }

    /**
     * Rows of `[identifier key]`: keys the grammar accepts, at each bound of
     * its length and with each kind of character it allows.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideIdentifierKeys(): iterable
    {
        yield from [
            'a word'                  => ['username'],
            'one character'           => ['u'],
            'a leading digit'         => ['2fa_email'],
            'a leading underscore'    => ['_login'],
            'capitals'                => ['EmailAddress'],
            'a dot'                   => ['user.email'],
            'a hyphen'                => ['e-mail'],
            '64 characters'           => [str_repeat('k', 64)],
            'every allowed character' => ['aZ09_.-'],
        ];
    }

    /**
     * A key within the grammar is read as configured.
     *
     * @param  string  $key
     * @return void
     */
    #[DataProvider('provideIdentifierKeys')]
    public function testReadsAnIdentifierKey(string $key): void
    {
        self::assertSame($key, self::settings(['laravel' => ['identifier_key' => $key]])->identifierKey());
    }

    /**
     * Rows of `[identifier key]`: empty, over-long, starting with a dot or a
     * hyphen, holding a space, a slash, a non-ASCII letter or a trailing line
     * feed, and values that are not strings.
     *
     * @return iterable<string, array{0: bool|int|list<string>|string|null}>
     */
    public static function provideMalformedIdentifierKeys(): iterable
    {
        yield from [
            'empty'             => [''],
            '65 characters'     => [str_repeat('k', 65)],
            'a leading dot'     => ['.email'],
            'a leading hyphen'  => ['-email'],
            'a space'           => ['e mail'],
            'a slash'           => ['user/email'],
            'a bracket'         => ['user[email]'],
            'a non-ASCII'       => ['émail'],
            'a trailing line'   => ["email\n"],
            'an explicit null'  => [null],
            'an integer'        => [42],
            'true'              => [true],
            'a list'            => [['email']],
            'a sentinel spaced' => [self::SENTINEL . ' x'],
        ];
    }

    /**
     * A key outside the grammar fails closed, naming the setting and never the
     * value: protects against a mutation that drops either anchor of the
     * pattern.
     *
     * @param  bool|int|list<string>|string|null  $key
     * @return void
     */
    #[DataProvider('provideMalformedIdentifierKeys')]
    public function testRefusesAMalformedIdentifierKey(array|bool|int|string|null $key): void
    {
        $settings = self::settings(['laravel' => ['identifier_key' => $key]]);

        self::assertRefused(self::MALFORMED_IDENTIFIER_KEY, $settings->identifierKey(...));
    }

    /**
     * With no setting Gate denials are not recorded, and a real boolean turns
     * the capture on and off.
     *
     * @return void
     */
    public function testGateCaptureIsOffByDefault(): void
    {
        self::assertFalse((new CaptureSettings(new Repository))->isGateEnabled());
        self::assertFalse(self::settings(['gate' => []])->isGateEnabled());
        self::assertFalse(self::settings(['gate' => ['enabled' => false]])->isGateEnabled());
        self::assertTrue(self::settings(['gate' => ['enabled' => true]])->isGateEnabled());
    }

    /**
     * Rows of `[flag]`: truthy and falsy values of every other type, and a
     * `null` set explicitly, which is not a missing key.
     *
     * @return iterable<string, array{0: array<never, never>|int|string|null}>
     */
    public static function provideNonBooleanFlags(): iterable
    {
        yield from [
            'the string true'  => ['true'],
            'the integer 1'    => [1],
            'the string 1'     => ['1'],
            'the integer 0'    => [0],
            'yes'              => ['yes'],
            'an empty string'  => [''],
            'an empty array'   => [[]],
            'an explicit null' => [null],
        ];
    }

    /**
     * Only a real boolean passes, so a truthy string never turns the capture
     * on.
     *
     * @param  array<never, never>|int|string|null  $enabled
     * @return void
     */
    #[DataProvider('provideNonBooleanFlags')]
    public function testGateCaptureNeedsARealBoolean(array|int|string|null $enabled): void
    {
        $settings = self::settings(['gate' => ['enabled' => $enabled]]);

        self::assertRefused(self::MALFORMED_GATE_ENABLED, $settings->isGateEnabled(...));
    }

    /**
     * With no setting, or `null` only abilities and no excepted ones, every
     * ability is selected.
     *
     * @return void
     */
    public function testEveryAbilityIsSelectedByDefault(): void
    {
        foreach ([new CaptureSettings(new Repository), self::settings(['gate' => ['only_abilities' => null, 'except_abilities' => []]])] as $settings) {
            self::assertNull($settings->onlyAbilities());
            self::assertSame([], $settings->exceptAbilities());
            self::assertTrue($settings->selectsAbility('update'));
            self::assertTrue($settings->selectsAbility('view-invoice'));
        }
    }

    /**
     * A list of only abilities is kept in order and selects exactly those,
     * however long, up to 191 bytes.
     *
     * @return void
     */
    public function testOnlyAbilitiesSelectsExactlyThose(): void
    {
        $longest  = str_repeat('a', CaptureSettings::ABILITY_MAX_BYTES);
        $settings = self::settings(['gate' => ['only_abilities' => ['update', 'delete', $longest]]]);

        self::assertSame(191, CaptureSettings::ABILITY_MAX_BYTES);
        self::assertSame(['update', 'delete', $longest], $settings->onlyAbilities());
        self::assertTrue($settings->selectsAbility('update'));
        self::assertTrue($settings->selectsAbility('delete'));
        self::assertTrue($settings->selectsAbility($longest));
        self::assertFalse($settings->selectsAbility('view'));
    }

    /**
     * An excepted ability is never selected, even when the only abilities name
     * it, and every other ability is selected when no only list is set.
     *
     * @return void
     */
    public function testExceptAbilitiesWinsOverOnlyAbilities(): void
    {
        $both = self::settings(['gate' => ['only_abilities' => ['update', 'delete'], 'except_abilities' => ['delete']]]);

        self::assertSame(['delete'], $both->exceptAbilities());
        self::assertTrue($both->selectsAbility('update'));
        self::assertFalse($both->selectsAbility('delete'));
        self::assertFalse($both->selectsAbility('view'));

        $except = self::settings(['gate' => ['except_abilities' => ['viewNova']]]);

        self::assertFalse($except->selectsAbility('viewNova'));
        self::assertTrue($except->selectsAbility('update'));
    }

    /**
     * Abilities are compared exactly as the Gate gives them: one that differs
     * in case or whitespace is another ability, in either list.
     *
     * @return void
     */
    public function testAbilitiesAreComparedExactly(): void
    {
        $only = self::settings(['gate' => ['only_abilities' => ['update']]]);

        self::assertFalse($only->selectsAbility('Update'));
        self::assertFalse($only->selectsAbility('update '));
        self::assertFalse($only->selectsAbility(' update'));
        self::assertFalse($only->selectsAbility('UPDATE'));

        $except = self::settings(['gate' => ['except_abilities' => ['update']]]);

        self::assertTrue($except->selectsAbility('Update'));
        self::assertTrue($except->selectsAbility('update '));
        self::assertFalse($except->selectsAbility('update'));
    }

    /**
     * Rows of `[the list's key, its value, the expected message]`: an empty
     * only list, which must be said as `null`, a 192-byte member, counted in
     * bytes, a member that is not a string, an empty or unclean member, a
     * string, a map, and an explicit `null` for the excepted list.
     *
     * @return iterable<string, array{0: 'except_abilities'|'only_abilities', 1: array<int|string, int|string|null>|string|null, 2: string}>
     */
    public static function provideMalformedAbilityLists(): iterable
    {
        $over      = str_repeat('a', 192);
        $multibyte = str_repeat('é', 96);
        $members   = [
            'a 192-byte member'           => [$over],
            'a member of 192 bytes in 96' => [$multibyte],
            'a non-string member'         => [42],
            'a null member'               => [null],
            'an empty member'             => [''],
            'a control character'         => ["up\x01date"],
            'a line feed'                 => ["update\n"],
            'invalid UTF-8'               => ["update\xFF"],
            'a bad member after a good'   => ['update', 42],
        ];

        yield 'only, an empty list' => ['only_abilities', [], self::MALFORMED_ONLY_ABILITIES];

        foreach (['only_abilities' => self::MALFORMED_ONLY_ABILITIES, 'except_abilities' => self::MALFORMED_EXCEPT_ABILITIES] as $key => $message) {

            $label = $key === 'only_abilities' ? 'only' : 'except';

            foreach ($members as $what => $list) {
                yield "{$label}, {$what}" => [$key, $list, $message];
            }

            yield "{$label}, a string" => [$key, 'update', $message];
            yield "{$label}, a map" => [$key, ['first' => 'update'], $message];
            yield "{$label}, a list with a gap" => [$key, [1 => 'update'], $message];
        }

        yield 'except, an explicit null' => ['except_abilities', null, self::MALFORMED_EXCEPT_ABILITIES];
    }

    /**
     * Each malformed ability list fails closed when it is read and when an
     * ability is asked about, rather than selecting every ability or none.
     *
     * @param  'except_abilities'|'only_abilities'  $key
     * @param  array<int|string, int|string|null>|string|null  $abilities
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMalformedAbilityLists')]
    public function testRefusesAMalformedAbilityList(string $key, array|string|null $abilities, string $message): void
    {
        $settings = self::settings(['gate' => [$key => $abilities]]);
        $read     = $key === 'only_abilities' ? $settings->onlyAbilities(...) : $settings->exceptAbilities(...);

        self::assertRefused($message, $read);
        self::assertRefused($message, static fn (): bool => $settings->selectsAbility('update'));
    }

    /**
     * With no setting no reason code is kept, and a list of machine-readable
     * codes is read whole and in order.
     *
     * @return void
     */
    public function testReasonCodesDefaultToNone(): void
    {
        self::assertSame([], (new CaptureSettings(new Repository))->reasonCodes());
        self::assertSame([], self::settings(['gate' => ['reason_codes' => []]])->reasonCodes());

        $codes = ['insufficient_role', 'plan:expired', 'a', str_repeat('c', 64)];

        self::assertSame($codes, self::settings(['gate' => ['reason_codes' => $codes]])->reasonCodes());
    }

    /**
     * Rows of `[reason codes]`: members that are not machine-readable codes,
     * members that are not strings, and lists that are not lists.
     *
     * @return iterable<string, array{0: array<int|string, int|string|null>|string|null}>
     */
    public static function provideMalformedReasonCodes(): iterable
    {
        yield from [
            'a capital'               => [['Insufficient']],
            'a space'                 => [['no role']],
            'a leading underscore'    => [['_role']],
            'empty'                   => [['']],
            '65 characters'           => [[str_repeat('c', 65)]],
            'a sentinel with a space' => [[self::SENTINEL . ' x']],
            'an integer member'       => [[403]],
            'a null member'           => [[null]],
            'a bad code after a good' => [['plan_expired', 'Bad']],
            'a string'                => ['plan_expired'],
            'a map'                   => [['first' => 'plan_expired']],
            'an explicit null'        => [null],
        ];
    }

    /**
     * A reason code that is not a machine-readable code fails closed, naming
     * the setting and never the code, so a list that could keep free text is
     * never used.
     *
     * @param  array<int|string, int|string|null>|string|null  $codes
     * @return void
     */
    #[DataProvider('provideMalformedReasonCodes')]
    public function testRefusesAReasonCodeThatIsNotAMachineCode(array|string|null $codes): void
    {
        $settings = self::settings(['gate' => ['reason_codes' => $codes]]);

        self::assertRefused(self::MALFORMED_REASON_CODES, $settings->reasonCodes(...));
    }

    /**
     * With no setting a manifest holds at most 100000 subjects and 4194304
     * bytes, and each bound is read from its own key, as an integer or the
     * digits `env()` returns, at either end of its range.
     *
     * @return void
     */
    public function testTheBulkLimitsHaveTheirDefaults(): void
    {
        $defaults = new CaptureSettings(new Repository);

        self::assertSame(100000, $defaults->bulkMaxMembers());
        self::assertSame(4194304, $defaults->bulkMaxBytes());

        $least = self::settings(['bulk' => ['max_members' => 1, 'max_bytes' => '65536']]);

        self::assertSame(1, $least->bulkMaxMembers());
        self::assertSame(65536, $least->bulkMaxBytes());

        $most = self::settings(['bulk' => ['max_members' => '1000000', 'max_bytes' => 8388608]]);

        self::assertSame(1000000, $most->bulkMaxMembers());
        self::assertSame(8388608, $most->bulkMaxBytes());
    }

    /**
     * Rows of `[the bound's key, its value, its range]`: one past either end of
     * each range, a negative, a padded or fractional string, a float, an
     * explicit `null` and a word.
     *
     * @return iterable<string, array{0: 'max_bytes'|'max_members', 1: float|int|string|null, 2: string}>
     */
    public static function provideBulkLimitBounds(): iterable
    {
        $ranges = ['max_members' => [1, 1000000], 'max_bytes' => [65536, 8388608]];

        foreach ($ranges as $key => [$least, $most]) {

            $range = "from {$least} to {$most}";

            yield "{$key}, one under its least" => [$key, $least - 1, $range];
            yield "{$key}, one over its most" => [$key, $most + 1, $range];
            yield "{$key}, as digits over" => [$key, (string) ($most + 1), $range];
            yield "{$key}, negative" => [$key, -1, $range];
            yield "{$key}, padded" => [$key, ' ' . $least, $range];
            yield "{$key}, a fraction" => [$key, $least . '.0', $range];
            yield "{$key}, a float" => [$key, (float) $least, $range];
            yield "{$key}, an explicit null" => [$key, null, $range];
            yield "{$key}, a word" => [$key, self::SENTINEL, $range];
        }
    }

    /**
     * A bound outside its range, or that is not an integer, fails closed,
     * naming the setting and the range and never the value.
     *
     * @param  'max_bytes'|'max_members'  $key
     * @param  float|int|string|null  $value
     * @param  string  $range
     * @return void
     */
    #[DataProvider('provideBulkLimitBounds')]
    public function testRefusesABulkLimitOutsideItsRange(string $key, float|int|string|null $value, string $range): void
    {
        $settings = self::settings(['bulk' => [$key => $value]]);
        $read     = $key === 'max_members' ? $settings->bulkMaxMembers(...) : $settings->bulkMaxBytes(...);

        self::assertRefused("`audit-log.capture.bulk.{$key}` must be an integer {$range}.", $read);
    }

    /**
     * Validation passes on the defaults and on good values, and reads every
     * setting, so a malformed one anywhere fails it with that setting's
     * message.
     *
     * @return void
     */
    public function testValidateReadsEverySetting(): void
    {
        (new CaptureSettings(new Repository))->validate();

        self::settings([
            'laravel' => ['except_guards' => ['*'], 'identifier_key' => 'username'],
            'gate'    => ['enabled' => true, 'only_abilities' => ['update'], 'except_abilities' => ['delete'], 'reason_codes' => ['plan_expired']],
            'bulk'    => ['max_members' => 10, 'max_bytes' => 65536],
        ])->validate();

        $bad = [
            [['laravel' => ['except_guards' => 'web']], self::MALFORMED_EXCEPT_GUARDS],
            [['laravel' => ['identifier_key' => '']], self::MALFORMED_IDENTIFIER_KEY],
            [['gate' => ['enabled' => 'true']], self::MALFORMED_GATE_ENABLED],
            [['gate' => ['only_abilities' => []]], self::MALFORMED_ONLY_ABILITIES],
            [['gate' => ['except_abilities' => 'delete']], self::MALFORMED_EXCEPT_ABILITIES],
            [['gate' => ['reason_codes' => ['Bad']]], self::MALFORMED_REASON_CODES],
            [['bulk' => ['max_members' => 0]], '`audit-log.capture.bulk.max_members` must be an integer from 1 to 1000000.'],
            [['bulk' => ['max_bytes' => 0]], '`audit-log.capture.bulk.max_bytes` must be an integer from 65536 to 8388608.'],
        ];

        foreach ($bad as [$capture, $message]) {
            self::assertRefused($message, self::settings($capture)->validate(...));
        }
    }

    /**
     * Each setting is read on every call, so a change takes effect at once and
     * a value changed to a malformed one fails at once.
     *
     * @return void
     */
    public function testTheSettingsAreReadOnEveryCall(): void
    {
        $config   = new Repository(['audit-log' => ['capture' => ['gate' => ['enabled' => false]]]]);
        $settings = new CaptureSettings($config);

        self::assertFalse($settings->isGateEnabled());

        $config->set('audit-log.capture.gate.enabled', true);

        self::assertTrue($settings->isGateEnabled());

        $config->set('audit-log.capture.laravel.except_guards', ['api']);

        self::assertTrue($settings->excludesGuard('api'));

        $config->set('audit-log.capture.laravel.except_guards', 'api');

        self::assertRefused(self::MALFORMED_EXCEPT_GUARDS, static fn (): bool => $settings->excludesGuard('api'));
    }

    /**
     * Assert the read fails closed with exactly the message, which never holds
     * the sentinel a bad value may carry.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $message
     * @param  \Closure(): mixed  $read
     * @return void
     */
    private static function assertRefused(string $message, \Closure $read): void
    {
        try {
            $read();
        } catch (\InvalidArgumentException $exception) {
            self::assertSame($message, $exception->getMessage());
            self::assertStringNotContainsString(self::SENTINEL, $exception->getMessage());

            return;
        }

        self::fail('Expected the setting to be refused.');
    }

    /**
     * The capture settings over a configuration holding the excepted guards.
     *
     * @param  array<int|string, int|string|null>|string|null  $guards
     * @return \SineMacula\Laravel\AuditLog\Capture\CaptureSettings
     */
    private static function exceptGuards(array|string|null $guards): CaptureSettings
    {
        return self::settings(['laravel' => ['except_guards' => $guards]]);
    }

    /**
     * The capture settings over a configuration holding the capture section.
     *
     * @param  array<string, array<string, array<int|string, int|string|null>|bool|float|int|string|null>>  $capture
     * @return \SineMacula\Laravel\AuditLog\Capture\CaptureSettings
     */
    private static function settings(array $capture): CaptureSettings
    {
        return new CaptureSettings(new Repository(['audit-log' => ['capture' => $capture]]));
    }
}
