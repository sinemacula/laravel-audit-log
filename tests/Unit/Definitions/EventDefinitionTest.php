<?php

declare(strict_types = 1);

namespace Tests\Unit\Definitions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Contracts\OcsfMapper;
use SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling;
use SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Definitions\FieldRule;
use SineMacula\Laravel\AuditLog\Records\EventCode;
use Tests\Fixtures\Definitions\Enums\InvoiceActivity;
use Tests\Fixtures\Export\ApprovedInvoiceMapper;
use Tests\Fixtures\Export\MisclassifyingMapper;

/**
 * Unit tests for the event definition: its defaults, the versions and
 * categories it keeps and refuses, its immutability, the rules its shorthands
 * add, the duplicate and unreachable rules it refuses in either order, the
 * order it keeps its rules in, which rule decides a field, which rule lies
 * beneath a path, the OCSF mapper it names and keeps, and equality.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EventDefinition::class)]
final class EventDefinitionTest extends TestCase
{
    /** @var string The code most tests define. */
    private const string CODE = 'invoice.approved';

    /** @var string The message a version outside its bounds fails with. */
    private const string VERSION_MESSAGE = 'An event definition\'s version must be from 1 to 32767.';

    /** @var string The message a category that is not a slug fails with. */
    private const string CATEGORY_MESSAGE = 'An event definition\'s category must be 1 to 64 lower-case letters, digits or underscores, starting with a letter.';

    /**
     * The version bounds are 1 and PostgreSQL's signed smallint, and a
     * definition that names no category is in `general`.
     *
     * @return void
     */
    public function testTheBoundsAndTheDefaultCategory(): void
    {
        self::assertSame(1, EventDefinition::MIN_VERSION);
        self::assertSame(32767, EventDefinition::MAX_VERSION);
        self::assertSame('general', EventDefinition::DEFAULT_CATEGORY);
    }

    /**
     * A registered code's definition starts at version 1, in `general`, with no
     * rules, and drops every field no rule names.
     *
     * @return void
     */
    public function testTheDefaultsOfARegisteredCode(): void
    {
        $definition = EventDefinition::for(self::CODE);

        self::assertSame(self::CODE, $definition->code);
        self::assertSame(1, $definition->version);
        self::assertSame('general', $definition->category);
        self::assertSame([], $definition->rules);
        self::assertSame(FieldHandling::DROP, $definition->unlisted);
    }

    /**
     * A string-backed enum case gives its value as the code.
     *
     * @return void
     */
    public function testTakesAStringBackedEnumCase(): void
    {
        self::assertSame('invoice.approved', EventDefinition::for(InvoiceActivity::APPROVED)->code);
    }

    /**
     * A code outside the event code grammar is refused with the code's own
     * message.
     *
     * @return void
     */
    public function testRefusesAnInvalidCode(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('An event code must be lower-case dotted segments, such as `invoice.approved`:');

        EventDefinition::for('invoice');
    }

    /**
     * A caller cannot define a code under the prefix reserved for the package's
     * own codes.
     *
     * @return void
     */
    public function testRefusesTheReservedPrefix(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The `audit_log.` prefix is reserved for the package\'s own event codes.');

        EventDefinition::for('audit_log.pruned');
    }

    /**
     * Rows of `[version]`: versions within the bounds, the least and greatest
     * included.
     *
     * @return iterable<string, array{0: int}>
     */
    public static function provideVersions(): iterable
    {
        yield from [
            'the least'    => [1],
            'the second'   => [2],
            'the greatest' => [32767],
        ];
    }

    /**
     * A version within the bounds is kept.
     *
     * @param  int  $version
     * @return void
     */
    #[DataProvider('provideVersions')]
    public function testKeepsAVersionWithinItsBounds(int $version): void
    {
        self::assertSame($version, EventDefinition::for(self::CODE)->version($version)->version);
    }

    /**
     * Rows of `[version]`: versions just outside the bounds, and further.
     *
     * @return iterable<string, array{0: int}>
     */
    public static function provideRefusedVersions(): iterable
    {
        yield from [
            'zero'                 => [0],
            'negative'             => [-1],
            'one past the column'  => [32768],
            'the largest integer'  => [PHP_INT_MAX],
            'the smallest integer' => [PHP_INT_MIN],
        ];
    }

    /**
     * A version outside the bounds is refused, naming them.
     *
     * @param  int  $version
     * @return void
     */
    #[DataProvider('provideRefusedVersions')]
    public function testRefusesAVersionOutsideItsBounds(int $version): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::VERSION_MESSAGE);

        EventDefinition::for(self::CODE)->version($version);
    }

    /**
     * Rows of `[category]`: slugs, the shortest and longest included.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideCategories(): iterable
    {
        yield from [
            'the default'           => ['general'],
            'a word'                => ['finance'],
            'one letter'            => ['a'],
            'an underscore'         => ['pci_dss'],
            'digits'                => ['tier2'],
            'a trailing underscore' => ['finance_'],
            '64 characters'         => ['a' . str_repeat('b', 63)],
        ];
    }

    /**
     * A slug is kept as the category.
     *
     * @param  string  $category
     * @return void
     */
    #[DataProvider('provideCategories')]
    public function testKeepsACategorySlug(string $category): void
    {
        self::assertSame($category, EventDefinition::for(self::CODE)->category($category)->category);
    }

    /**
     * Rows of `[category]`: categories that are not slugs.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideRefusedCategories(): iterable
    {
        yield from [
            'empty'                => [''],
            'upper case'           => ['Finance'],
            'a leading digit'      => ['1finance'],
            'a leading underscore' => ['_finance'],
            'a hyphen'             => ['fin-ance'],
            'a space'              => ['fin ance'],
            '65 characters'        => ['a' . str_repeat('b', 64)],
            'a trailing newline'   => ["finance\n"],
            'a leading newline'    => ["\nfinance"],
            'a non-ASCII letter'   => ['finançe'],
            'a dot'                => ['fin.ance'],
        ];
    }

    /**
     * A category that is not a slug is refused, describing the slug.
     *
     * @param  string  $category
     * @return void
     */
    #[DataProvider('provideRefusedCategories')]
    public function testRefusesACategoryThatIsNotASlug(string $category): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::CATEGORY_MESSAGE);

        EventDefinition::for(self::CODE)->category($category);
    }

    /**
     * Rows of `[fluent call]`: a call of each fluent method.
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\AuditLog\Definitions\EventDefinition): \SineMacula\Laravel\AuditLog\Definitions\EventDefinition}>
     */
    public static function provideFluentCalls(): iterable
    {
        yield from [
            'version'             => [static fn (EventDefinition $definition): EventDefinition => $definition->version(2)],
            'category'            => [static fn (EventDefinition $definition): EventDefinition => $definition->category('finance')],
            'retain'              => [static fn (EventDefinition $definition): EventDefinition => $definition->retain('amount')],
            'retain with no path' => [static fn (EventDefinition $definition): EventDefinition => $definition->retain()],
            'redact'              => [static fn (EventDefinition $definition): EventDefinition => $definition->redact('amount')],
            'pseudonymise'        => [static fn (EventDefinition $definition): EventDefinition => $definition->pseudonymise('email')],
            'encrypt'             => [static fn (EventDefinition $definition): EventDefinition => $definition->encrypt('card_holder', KeyOwner::SUBJECT)],
            'drop'                => [static fn (EventDefinition $definition): EventDefinition => $definition->drop('notes')],
            'rule'                => [static fn (EventDefinition $definition): EventDefinition => $definition->rule('amount', FieldHandling::RETAIN)],
            'unlisted'            => [static fn (EventDefinition $definition): EventDefinition => $definition->unlisted(FieldHandling::RETAIN)],
        ];
    }

    /**
     * Each fluent method returns a new definition and leaves the one it was
     * called on as it was.
     *
     * @param  \Closure(\SineMacula\Laravel\AuditLog\Definitions\EventDefinition): \SineMacula\Laravel\AuditLog\Definitions\EventDefinition  $call
     * @return void
     */
    #[DataProvider('provideFluentCalls')]
    public function testEachFluentMethodReturnsANewInstanceAndLeavesTheOriginal(\Closure $call): void
    {
        $original = EventDefinition::for(self::CODE);

        self::assertNotSame($original, $call($original));
        self::assertTrue($original->equals(EventDefinition::for(self::CODE)));
    }

    /**
     * Each shorthand adds a rule of its handling for each path it is given, and
     * `encrypt()` keeps the owner it names.
     *
     * @return void
     */
    public function testTheShorthandsAddTheirHandling(): void
    {
        $definition = EventDefinition::for(self::CODE)
            ->retain('a', 'b')
            ->redact('c')
            ->pseudonymise('d')
            ->drop('e')
            ->encrypt('f', KeyOwner::ACTOR)
            ->encrypt('g', 'b');

        $handlings = array_map(static fn (FieldRule $rule): FieldHandling => $rule->handling, $definition->rules);

        self::assertSame([
            'a' => FieldHandling::RETAIN,
            'b' => FieldHandling::RETAIN,
            'c' => FieldHandling::REDACT,
            'd' => FieldHandling::PSEUDONYMISE,
            'e' => FieldHandling::DROP,
            'f' => FieldHandling::ENCRYPT,
            'g' => FieldHandling::ENCRYPT,
        ], $handlings);
        self::assertSame(KeyOwner::ACTOR, $definition->rules['f']->owner);
        self::assertSame('b', $definition->rules['g']->owner);
        self::assertNull($definition->rules['a']->owner);
    }

    /**
     * `encrypt()` without an owner reaches the field rule's refusal.
     *
     * @return void
     */
    public function testEncryptRequiresAnOwner(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('An encrypted field must name its owner: `KeyOwner::ACTOR`, `KeyOwner::SUBJECT` or the path of a property holding a reference.');

        EventDefinition::for(self::CODE)->encrypt('card_holder');
    }

    /**
     * A malformed path given to a shorthand is refused with the grammar's
     * message.
     *
     * @return void
     */
    public function testAMalformedPathIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A field path must be dot-separated keys, each non-empty, with `*` alone matching one key or list index.');

        EventDefinition::for(self::CODE)->retain('amount', 'a..b');
    }

    /**
     * Rules are kept by path in path order, whatever order they are added in.
     *
     * @return void
     */
    public function testRulesAreKeptInPathOrder(): void
    {
        $definition = EventDefinition::for(self::CODE)->retain('b')->retain('a');

        self::assertSame(['a', 'b'], array_keys($definition->rules));
        self::assertSame('a', $definition->rules['a']->path);
        self::assertSame('b', $definition->rules['b']->path);
    }

    /**
     * Paths are ordered as strings, never as numbers, so a definition of digit
     * keys keeps `10` before `9`; the rules still decide those keys. Protects
     * against a mutation that drops the string ordering flag.
     *
     * @return void
     */
    public function testPathsAreOrderedAsStrings(): void
    {
        $definition = EventDefinition::for(self::CODE)->redact('9')->retain('10');

        self::assertSame(['10', '9'], array_values(array_map(static fn (FieldRule $rule): string => $rule->path, $definition->rules)));
        self::assertSame(FieldHandling::REDACT, $definition->handlingFor([9]));
        self::assertSame(FieldHandling::RETAIN, $definition->handlingFor([10]));
    }

    /**
     * The same version, category, unlisted handling and rules, given in any
     * order, make equal definitions, and no fluent method loses what another
     * set.
     *
     * @return void
     */
    public function testDefinitionsBuiltInAnyOrderAreEqual(): void
    {
        $one = EventDefinition::for(self::CODE)
            ->version(2)
            ->category('finance')
            ->retain('b')
            ->unlisted(FieldHandling::RETAIN)
            ->encrypt('a', KeyOwner::SUBJECT);

        $another = EventDefinition::for(self::CODE)
            ->unlisted(FieldHandling::RETAIN)
            ->encrypt('a', KeyOwner::SUBJECT)
            ->category('finance')
            ->retain('b')
            ->version(2);

        self::assertTrue($one->equals($another));
        self::assertTrue($another->equals($one));
        self::assertSame(['a', 'b'], array_keys($another->rules));
        self::assertSame(2, $another->version);
        self::assertSame('finance', $another->category);
        self::assertSame(FieldHandling::RETAIN, $another->unlisted);
        self::assertSame(KeyOwner::SUBJECT, $another->rules['a']->owner);
    }

    /**
     * Repeating an identical rule changes nothing: the definition still has one
     * rule for the path, and is equal to the one before.
     *
     * @return void
     */
    public function testAnIdenticalRuleRepeatedIsKeptOnce(): void
    {
        $once  = EventDefinition::for(self::CODE)->version(3)->encrypt('card_holder', KeyOwner::SUBJECT);
        $twice = $once->encrypt('card_holder', KeyOwner::SUBJECT);

        self::assertNotSame($once, $twice);
        self::assertTrue($twice->equals($once));
        self::assertCount(1, $twice->rules);
        self::assertSame(3, $twice->version);
    }

    /**
     * A second, different rule for a path that has one is refused, naming the
     * path, whether its handling or its owner differs.
     *
     * @return void
     */
    public function testASecondRuleForAPathIsRefused(): void
    {
        $calls = [
            'another handling' => static fn (): EventDefinition => EventDefinition::for(self::CODE)->retain('a')->redact('a'),
            'another owner'    => static fn (): EventDefinition => EventDefinition::for(self::CODE)->encrypt('a', KeyOwner::ACTOR)->encrypt('a', KeyOwner::SUBJECT),
        ];

        foreach ($calls as $label => $call) {
            try {
                $call();

                self::fail(sprintf('Expected a second rule with %s to be refused.', $label));
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('The path `a` already has a rule.', $exception->getMessage(), $label);
            }
        }
    }

    /**
     * Rows of `[first path, its handling, second path, its handling, the
     * descendant, the ancestor]`: pairs where a rule that decides its whole
     * branch may cover the other, in each order.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: string, 1: \SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling, 2: string, 3: \SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling, 4: string, 5: string}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideUnreachableRules(): iterable
    {
        yield from [
            'beneath a dropped map'                => ['a', FieldHandling::DROP, 'a.b', FieldHandling::RETAIN, 'a.b', 'a'],
            'beneath a redacted map'               => ['a', FieldHandling::REDACT, 'a.b', FieldHandling::DROP, 'a.b', 'a'],
            'beneath a pseudonymised map'          => ['a', FieldHandling::PSEUDONYMISE, 'a.b', FieldHandling::RETAIN, 'a.b', 'a'],
            'beneath an encrypted map'             => ['a', FieldHandling::ENCRYPT, 'a.b', FieldHandling::RETAIN, 'a.b', 'a'],
            'beneath a dropped wildcard'           => ['a.*', FieldHandling::DROP, 'a.b.c', FieldHandling::RETAIN, 'a.b.c', 'a.*'],
            'a wildcard that may be beneath'       => ['a', FieldHandling::DROP, '*.b', FieldHandling::RETAIN, '*.b', 'a'],
            'two levels beneath'                   => ['a', FieldHandling::DROP, 'a.b.c', FieldHandling::RETAIN, 'a.b.c', 'a'],
            'a dropped map after its child'        => ['a.b', FieldHandling::RETAIN, 'a', FieldHandling::DROP, 'a.b', 'a'],
            'a redacted map after its child'       => ['a.b', FieldHandling::DROP, 'a', FieldHandling::REDACT, 'a.b', 'a'],
            'a pseudonymised map after its child'  => ['a.b', FieldHandling::RETAIN, 'a', FieldHandling::PSEUDONYMISE, 'a.b', 'a'],
            'an encrypted map after its child'     => ['a.b', FieldHandling::RETAIN, 'a', FieldHandling::ENCRYPT, 'a.b', 'a'],
            'a dropped wildcard after its child'   => ['a.b.c', FieldHandling::RETAIN, 'a.*', FieldHandling::DROP, 'a.b.c', 'a.*'],
            'a dropped map after a wildcard child' => ['*.b', FieldHandling::RETAIN, 'a', FieldHandling::DROP, '*.b', 'a'],
        ];
    }

    /**
     * A rule that a rule deciding its whole branch may cover could never apply,
     * and is refused whichever is added first, naming the descendant and then
     * the ancestor.
     *
     * @param  string  $firstPath
     * @param  \SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling  $firstHandling
     * @param  string  $secondPath
     * @param  \SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling  $secondHandling
     * @param  string  $descendant
     * @param  string  $ancestor
     * @return void
     */
    #[DataProvider('provideUnreachableRules')]
    public function testRefusesAnUnreachableRule(
        string $firstPath,
        FieldHandling $firstHandling,
        string $secondPath,
        FieldHandling $secondHandling,
        string $descendant,
        string $ancestor,
    ): void {
        $definition = EventDefinition::for(self::CODE)->rule($firstPath, $firstHandling, self::ownerFor($firstHandling));

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(sprintf('The rule for `%s` is unreachable beneath the rule for `%s`.', $descendant, $ancestor));

        $definition->rule($secondPath, $secondHandling, self::ownerFor($secondHandling));
    }

    /**
     * A rule beneath a retained map is reachable, since `retain` does not
     * decide the whole branch, in either order.
     *
     * @return void
     */
    public function testARuleBeneathARetainedPathIsReachable(): void
    {
        $one     = EventDefinition::for(self::CODE)->retain('a')->redact('a.b');
        $another = EventDefinition::for(self::CODE)->redact('a.b')->retain('a');

        self::assertTrue($one->equals($another));
        self::assertSame(FieldHandling::REDACT, $one->handlingFor(['a', 'b']));
        self::assertSame(FieldHandling::RETAIN, $one->handlingFor(['a', 'c']));
    }

    /**
     * Rules of the same length never cover one another, even when both decide
     * their branches and may match the same field.
     *
     * @return void
     */
    public function testRulesThatOnlyShareALengthAreReachable(): void
    {
        $definition = EventDefinition::for(self::CODE)->redact('a.*')->retain('*.b');

        self::assertCount(2, $definition->rules);
        self::assertSame(FieldHandling::REDACT, $definition->handlingFor(['a', 'b']));
    }

    /**
     * Rules in other branches never cover one another, whatever their handling.
     *
     * @return void
     */
    public function testRulesInOtherBranchesAreReachable(): void
    {
        $definition = EventDefinition::for(self::CODE)->drop('a')->drop('b.a')->redact('c.*.a');

        self::assertCount(3, $definition->rules);
    }

    /**
     * A registered code's definition may opt out of dropping unlisted fields
     * and retain them instead, explicitly.
     *
     * @return void
     */
    public function testUnlistedFieldsMayBeRetainedExplicitly(): void
    {
        $definition = EventDefinition::for(self::CODE)->unlisted(FieldHandling::RETAIN);

        self::assertSame(FieldHandling::RETAIN, $definition->unlisted);
        self::assertSame(FieldHandling::RETAIN, $definition->handlingFor(['anything']));
        self::assertSame(FieldHandling::REDACT, $definition->unlisted(FieldHandling::REDACT)->unlisted);
    }

    /**
     * Unlisted fields cannot be encrypted, since an encrypted field must name
     * its owner.
     *
     * @return void
     */
    public function testUnlistedFieldsCannotBeEncrypted(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Unlisted fields cannot be encrypted, because an encrypted field names its owner.');

        EventDefinition::for(self::CODE)->unlisted(FieldHandling::ENCRYPT);
    }

    /**
     * The default an unregistered code takes is version 1, in `general`, with
     * no rules, and retains every field.
     *
     * @return void
     */
    public function testThePermissiveDefaultRetainsUnlistedFields(): void
    {
        $definition = EventDefinition::permissive(EventCode::of('x.y'));

        self::assertSame('x.y', $definition->code);
        self::assertSame(1, $definition->version);
        self::assertSame('general', $definition->category);
        self::assertSame([], $definition->rules);
        self::assertSame(FieldHandling::RETAIN, $definition->unlisted);
        self::assertSame(FieldHandling::RETAIN, $definition->handlingFor(['anything', 0]));
    }

    /**
     * Rows of `[concrete path, the winning rule's path]`: the precedence table,
     * over one definition, with `null` where no rule decides the field.
     *
     * @return iterable<string, array{0: list<int|string>, 1: ?string}>
     */
    public static function providePrecedence(): iterable
    {
        yield from [
            'more segments'                     => [['card', 'number'], 'card.number'],
            'a rule covers its branch'          => [['card', 'holder'], 'card'],
            'exact'                             => [['card'], 'card'],
            'equal length, exact beats *'       => [['user', 'email'], 'user.email'],
            'the only match'                    => [['admin', 'email'], '*.email'],
            'a terminal rule covers its branch' => [['card', 'number', 'last4'], 'card.number'],
            'a literal digit matches an index'  => [['lines', 0], 'lines.0'],
            'and covers its branch'             => [['lines', 0, 'sku'], 'lines.0'],
            '* matches an index'                => [['lines', 1], 'lines.*'],
            'and * covers its branch'           => [['lines', 1, 'sku'], 'lines.*'],
            'compared left to right'            => [['lines', 'email'], 'lines.*'],
            'exact beats * beneath a drop'      => [['meta', 'keep'], 'meta.keep'],
            'a wildcard'                        => [['meta', 'other'], 'meta.*'],
            'a key with a dot is not two keys'  => [['card.number'], null],
            'a key with a dot is reachable'     => [['admin.team', 'email'], '*.email'],
            'unlisted'                          => [['other'], null],
            'no rule matches any prefix'        => [['items', 0], null],
            'the empty path'                    => [[], null],
        ];
    }

    /**
     * Of the rules matching a prefix of the concrete path, the most specific
     * decides it: more segments first, then, at equal length, compared left to
     * right, a literal over `*`. A field no rule decides is handled as unlisted
     * fields are.
     *
     * @param  list<int|string>  $path
     * @param  ?string  $winner
     * @return void
     */
    #[DataProvider('providePrecedence')]
    public function testTheMostSpecificRuleWins(array $path, ?string $winner): void
    {
        $definition = EventDefinition::for(self::CODE)
            ->retain('card')
            ->redact('card.number')
            ->pseudonymise('*.email')
            ->retain('user.email')
            ->retain('lines.*')
            ->redact('lines.0')
            ->drop('meta.*')
            ->retain('meta.keep');

        $rule = $definition->ruleFor($path);

        self::assertSame($winner, $rule?->path);
        self::assertSame($rule === null ? FieldHandling::DROP : $rule->handling, $definition->handlingFor($path));
    }

    /**
     * Rules added in the opposite order decide every field the same way, so the
     * winner never depends on which rule came first: a longer rule beats a
     * shorter one, and a literal beats `*` at equal length.
     *
     * @return void
     */
    public function testTheWinnerDoesNotDependOnTheOrderOfTheRules(): void
    {
        $forward = EventDefinition::for(self::CODE)->retain('a')->retain('*.b')->retain('a.b')->drop('a.*.c');
        $reverse = EventDefinition::for(self::CODE)->drop('a.*.c')->retain('a.b')->retain('*.b')->retain('a');

        $winners = [
            [['a'], 'a'],
            [['a', 'b'], 'a.b'],
            [['a', 'x'], 'a'],
            [['x', 'b'], '*.b'],
            [['a', 'b', 'c'], 'a.*.c'],
            [['a', 'x', 'c'], 'a.*.c'],
        ];

        foreach ($winners as [$path, $winner]) {
            self::assertSame($winner, $forward->ruleFor($path)?->path, implode('.', $path));
            self::assertSame($winner, $reverse->ruleFor($path)?->path, implode('.', $path));
        }
    }

    /**
     * One rule makes a registered code drop every other field, at any depth;
     * retaining unlisted fields keeps them, and a field a rule names always
     * takes its rule's handling.
     *
     * @return void
     */
    public function testOneRuleDropsEveryOtherField(): void
    {
        $definition = EventDefinition::for('invoice.approved')->retain('amount');

        self::assertSame(FieldHandling::RETAIN, $definition->handlingFor(['amount']));
        self::assertSame(FieldHandling::DROP, $definition->handlingFor(['currency']));
        self::assertSame(FieldHandling::DROP, $definition->handlingFor(['notes', 0]));

        $retaining = $definition->unlisted(FieldHandling::RETAIN);

        self::assertSame(FieldHandling::RETAIN, $retaining->handlingFor(['amount']));
        self::assertSame(FieldHandling::RETAIN, $retaining->handlingFor(['currency']));
        self::assertSame(FieldHandling::RETAIN, $retaining->handlingFor(['notes', 0]));

        $redacting = EventDefinition::for('invoice.approved')->redact('amount')->unlisted(FieldHandling::RETAIN);

        self::assertSame(FieldHandling::REDACT, $redacting->handlingFor(['amount']));
    }

    /**
     * Rows of `[concrete path, the rule found beneath it]`: over one
     * definition, a literal, a wildcard in the pattern, a list index, a rule
     * more than one level down, and paths with nothing beneath them.
     *
     * @return iterable<string, array{0: list<int|string>, 1: ?string}>
     */
    public static function provideDescendantRules(): iterable
    {
        yield from [
            'a literal'                     => [['customer'], 'customer.email'],
            'a literal, more levels down'   => [['deep'], 'deep.er.still'],
            'and one level above it'        => [['deep', 'er'], 'deep.er.still'],
            'a wildcard in the pattern'     => [['items', 7], 'items.*.sku'],
            'and a dynamic key through it'  => [['items', 'bob@example.com'], 'items.*.sku'],
            'a list index'                  => [['lines'], 'lines.0.sku'],
            'and the index itself'          => [['lines', 0], 'lines.0.sku'],
            'a numeric key'                 => [[5], '5.total'],
            'an index another rule names'   => [['lines', 1], null],
            'a padded index is another key' => [['lines', '00'], null],
            'a key with a dot is not two'   => [['customer.email'], null],
            'none'                          => [['other'], null],
        ];
    }

    /**
     * The rule beneath a path is one with more segments whose leading segments
     * match it, comparing a list index by its decimal string.
     *
     * @param  list<int|string>  $path
     * @param  ?string  $expected
     * @return void
     */
    #[DataProvider('provideDescendantRules')]
    public function testRuleBeneathFindsADescendantRule(array $path, ?string $expected): void
    {
        $definition = EventDefinition::for(self::CODE)
            ->retain('customer.email')
            ->drop('deep.er.still')
            ->redact('items.*.sku')
            ->drop('lines.0.sku')
            ->retain('5.total');

        self::assertSame($expected, $definition->ruleBeneath($path)?->path);
    }

    /**
     * A rule at the path or above it decides the path, so it is not beneath it.
     *
     * @return void
     */
    public function testRuleBeneathIgnoresARuleAtOrAboveThePath(): void
    {
        $definition = EventDefinition::for(self::CODE)->retain('customer')->retain('order.total');

        self::assertNull($definition->ruleBeneath(['customer']), 'A rule at the path is not beneath it.');
        self::assertNull($definition->ruleBeneath(['customer', 'name']), 'A rule above the path is not beneath it.');
        self::assertNull($definition->ruleBeneath(['order', 'total']), 'A rule at the path is not beneath it.');
        self::assertNull($definition->ruleBeneath(['order', 'total', 'net']), 'A rule above the path is not beneath it.');
    }

    /**
     * Of several rules beneath a path the first in path order is taken, however
     * they were added, so the answer does not depend on the order of building.
     *
     * @return void
     */
    public function testRuleBeneathTakesTheFirstInPathOrder(): void
    {
        $forward = EventDefinition::for(self::CODE)->retain('a.c')->retain('a.b')->retain('*.d');
        $reverse = EventDefinition::for(self::CODE)->retain('*.d')->retain('a.b')->retain('a.c');

        self::assertSame('*.d', $forward->ruleBeneath(['a'])?->path);
        self::assertSame('*.d', $reverse->ruleBeneath(['a'])?->path);

        $literal = EventDefinition::for(self::CODE)->retain('a.c')->retain('a.b');

        self::assertSame('a.b', $literal->ruleBeneath(['a'])?->path);
    }

    /**
     * The rule beneath a path says nothing about the path's own handling: a
     * branch holding a rule-governed field is still handled as unlisted fields
     * are until the walker reaches that field.
     *
     * @return void
     */
    public function testARuleBeneathDoesNotDecideThePath(): void
    {
        $definition = EventDefinition::for(self::CODE)->retain('customer.email');

        self::assertNull($definition->ruleFor(['customer']));
        self::assertSame(FieldHandling::DROP, $definition->handlingFor(['customer']));
        self::assertSame('customer.email', $definition->ruleBeneath(['customer'])?->path);
    }

    /**
     * A definition names no OCSF mapper until `ocsf()` names one, and then
     * keeps its class name, never an instance; the permissive default names
     * none.
     *
     * @return void
     */
    public function testOcsfNamesAMapper(): void
    {
        $definition = EventDefinition::for(self::CODE);

        self::assertNull($definition->ocsfMapper);
        self::assertNull(EventDefinition::permissive(EventCode::of(self::CODE))->ocsfMapper);
        self::assertSame(ApprovedInvoiceMapper::class, $definition->ocsf(ApprovedInvoiceMapper::class)->ocsfMapper);
    }

    /**
     * Naming a mapper returns a new definition, equal to the original in every
     * other part, and leaves the original without one.
     *
     * @return void
     */
    public function testOcsfLeavesTheOriginalAsItWas(): void
    {
        $original = EventDefinition::for(self::CODE)->version(2)->category('finance')->retain('amount');
        $mapped   = $original->ocsf(ApprovedInvoiceMapper::class);

        self::assertNotSame($original, $mapped);
        self::assertNull($original->ocsfMapper);
        self::assertTrue($original->equals(EventDefinition::for(self::CODE)->version(2)->category('finance')->retain('amount')));
        self::assertSame([$original->code, $original->version, $original->category], [$mapped->code, $mapped->version, $mapped->category]);
        self::assertSame([$original->rules, $original->unlisted], [$mapped->rules, $mapped->unlisted]);
    }

    /**
     * Rows of `[fluent call]`: a call of each fluent method but `ocsf()`.
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\AuditLog\Definitions\EventDefinition): \SineMacula\Laravel\AuditLog\Definitions\EventDefinition}>
     */
    public static function provideMapperKeepingCalls(): iterable
    {
        yield from [
            'version'      => [static fn (EventDefinition $definition): EventDefinition => $definition->version(2)],
            'category'     => [static fn (EventDefinition $definition): EventDefinition => $definition->category('finance')],
            'retain'       => [static fn (EventDefinition $definition): EventDefinition => $definition->retain('amount')],
            'redact'       => [static fn (EventDefinition $definition): EventDefinition => $definition->redact('amount')],
            'pseudonymise' => [static fn (EventDefinition $definition): EventDefinition => $definition->pseudonymise('email')],
            'encrypt'      => [static fn (EventDefinition $definition): EventDefinition => $definition->encrypt('card_holder', KeyOwner::SUBJECT)],
            'drop'         => [static fn (EventDefinition $definition): EventDefinition => $definition->drop('notes')],
            'rule'         => [static fn (EventDefinition $definition): EventDefinition => $definition->rule('amount', FieldHandling::RETAIN)],
            'unlisted'     => [static fn (EventDefinition $definition): EventDefinition => $definition->unlisted(FieldHandling::RETAIN)],
        ];
    }

    /**
     * Every other fluent method keeps the mapper the definition names, so the
     * order a definition is built in does not lose it.
     *
     * @param  \Closure(\SineMacula\Laravel\AuditLog\Definitions\EventDefinition): \SineMacula\Laravel\AuditLog\Definitions\EventDefinition  $call
     * @return void
     */
    #[DataProvider('provideMapperKeepingCalls')]
    public function testEveryFluentMethodKeepsTheMapper(\Closure $call): void
    {
        $definition = EventDefinition::for(self::CODE)->ocsf(ApprovedInvoiceMapper::class);

        self::assertSame(ApprovedInvoiceMapper::class, $call($definition)->ocsfMapper);
    }

    /**
     * Rows of `[class name]`: names that are not of a class implementing the
     * mapper contract.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideNonMappers(): iterable
    {
        yield from [
            'no class'                => ['Tests\Fixtures\Export\NoSuchMapper'],
            'a class that is not one' => [\stdClass::class],
            'the contract itself'     => [OcsfMapper::class],
            'an empty name'           => [''],
        ];
    }

    /**
     * A name that is not of a class implementing `OcsfMapper` is refused,
     * naming it.
     *
     * @param  string  $mapper
     * @return void
     */
    #[DataProvider('provideNonMappers')]
    public function testRefusesAnOcsfMapperThatIsNoMapper(string $mapper): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(sprintf('`%s` is not a class implementing `OcsfMapper`.', $mapper));

        // @phpstan-ignore argument.type (the refusal is what is under test)
        EventDefinition::for(self::CODE)->ocsf($mapper);
    }

    /**
     * Two definitions alike but for the mapper they name are different
     * definitions, so registering a code twice with different mappers
     * conflicts.
     *
     * @return void
     */
    public function testADifferentMapperIsADifferentDefinition(): void
    {
        $definition = EventDefinition::for(self::CODE);

        self::assertFalse($definition->ocsf(ApprovedInvoiceMapper::class)->equals($definition->ocsf(MisclassifyingMapper::class)));
        self::assertTrue($definition->ocsf(ApprovedInvoiceMapper::class)->equals($definition->ocsf(ApprovedInvoiceMapper::class)));
    }

    /**
     * Rows of `[one definition, another, whether they are equal]`.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Definitions\EventDefinition, 1: \SineMacula\Laravel\AuditLog\Definitions\EventDefinition, 2: bool}>
     */
    public static function provideDifferences(): iterable
    {
        $base    = EventDefinition::for(self::CODE)->version(2)->category('finance')->retain('amount')->encrypt('card_holder', KeyOwner::SUBJECT);
        $rebuilt = EventDefinition::for(self::CODE)->encrypt('card_holder', KeyOwner::SUBJECT)->retain('amount')->category('finance')->version(2);
        $reowned = EventDefinition::for(self::CODE)->version(2)->category('finance')->retain('amount')->encrypt('card_holder', KeyOwner::ACTOR);

        yield from [
            'an equal build'         => [$base, $rebuilt, true],
            'another code'           => [EventDefinition::for('a.b'), EventDefinition::for('a.c'), false],
            'another version'        => [$base, $base->version(3), false],
            'another category'       => [$base, $base->category('billing'), false],
            'another unlisted'       => [$base, $base->unlisted(FieldHandling::RETAIN), false],
            'another rule set'       => [EventDefinition::for(self::CODE)->retain('a'), EventDefinition::for(self::CODE)->retain('b'), false],
            'one more rule'          => [$base, $base->retain('currency'), false],
            'another rule handling'  => [EventDefinition::for(self::CODE)->retain('a'), EventDefinition::for(self::CODE)->redact('a'), false],
            'another rule owner'     => [$base, $reowned, false],
            'the permissive default' => [EventDefinition::for('x.y'), EventDefinition::permissive(EventCode::of('x.y')), false],
            'a mapper and none'      => [$base, $base->ocsf(ApprovedInvoiceMapper::class), false],
            'the same mapper'        => [$base->ocsf(ApprovedInvoiceMapper::class), $rebuilt->ocsf(ApprovedInvoiceMapper::class), true],
        ];
    }

    /**
     * Two definitions are equal only when their code, version, category,
     * unlisted handling, OCSF mapper and every rule are, and equality is
     * symmetric.
     *
     * @param  \SineMacula\Laravel\AuditLog\Definitions\EventDefinition  $one
     * @param  \SineMacula\Laravel\AuditLog\Definitions\EventDefinition  $another
     * @param  bool  $expected
     * @return void
     */
    #[DataProvider('provideDifferences')]
    public function testEqualsComparesEveryPart(EventDefinition $one, EventDefinition $another, bool $expected): void
    {
        self::assertSame($expected, $one->equals($another));
        self::assertSame($expected, $another->equals($one));
    }

    /**
     * The owner a rule of the handling needs: the actor for an encrypted field,
     * and none for any other.
     *
     * @param  \SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling  $handling
     * @return ?\SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner
     */
    private static function ownerFor(FieldHandling $handling): ?KeyOwner
    {
        return $handling === FieldHandling::ENCRYPT ? KeyOwner::ACTOR : null;
    }
}
