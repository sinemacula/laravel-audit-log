<?php

declare(strict_types = 1);

namespace Tests\Unit\Console;

use Illuminate\Console\Command;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Console\LifecycleOptions;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis;
use Symfony\Component\Console\Input\ArrayInput;

/**
 * Unit tests for the options the lifecycle commands share: the authority they
 * assert, a reference split on its first colon, an instant given as an ISO-8601
 * time or a date, and a hold's basis, each form accepted and each refused,
 * every refusal naming the option and never the value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LifecycleOptions::class)]
final class LifecycleOptionsTest extends TestCase
{
    /** @var array<string, string> The options of an authority every test gives, unless it gives others. */
    private const array AUTHORITY = ['--by-type' => 'App\Models\User', '--by-id' => '7', '--reason' => 'case.review'];

    /** @var string The refusal of an operator that is not a reference. */
    private const string OPERATOR = 'The --by-type and --by-id options must each be 1 to 191 characters, with no control characters.';

    /** @var string The refusal of a reason that is not a reason code. */
    private const string REASON = 'The --reason option must be 1 to 64 lower-case letters, digits, `_`, `.`, `:` or `-`, starting with a letter or a digit.';

    /** @var string The refusal of an external reference that is not one. */
    private const string REFERENCE = 'The --reference option must be 1 to 191 characters, with no control characters.';

    /**
     * The authority is the operator the two options name together, the reason
     * code, and the external reference when it is given.
     *
     * @return void
     */
    public function testTheAuthorityIsReadFromItsOptions(): void
    {
        $authority = LifecycleOptions::authority(self::command([...self::AUTHORITY, '--reference' => 'app:ticket-123']));

        self::assertSame(['type' => 'App\Models\User', 'id' => '7', 'reason' => 'case.review', 'external_reference' => 'app:ticket-123'], $authority->toArray());
    }

    /**
     * The external reference is optional.
     *
     * @return void
     */
    public function testTheReferenceIsOptional(): void
    {
        self::assertNull(LifecycleOptions::authority(self::command(self::AUTHORITY))->externalReference);
    }

    /**
     * Rows of `[options, message]`: each required option missing or empty, and
     * each option malformed, with the refusal that names it.
     *
     * @return iterable<string, array{0: array<string, string>, 1: string}>
     */
    public static function provideRefusedAuthorities(): iterable
    {
        $without = static function (string $option): array {
            $options = self::AUTHORITY;

            unset($options[$option]);

            return $options;
        };

        yield from [
            'no operator type'           => [$without('--by-type'), 'The --by-type option is required.'],
            'no operator id'             => [$without('--by-id'), 'The --by-id option is required.'],
            'no reason'                  => [$without('--reason'), 'The --reason option is required.'],
            'an empty operator type'     => [['--by-type' => ''] + self::AUTHORITY, 'The --by-type option is required.'],
            'an empty reason'            => [['--reason' => ''] + self::AUTHORITY, 'The --reason option is required.'],
            'a control character'        => [['--by-id' => "7\x07"] + self::AUTHORITY, self::OPERATOR],
            'an operator id too long'    => [['--by-id' => str_repeat('7', 192)] + self::AUTHORITY, self::OPERATOR],
            'a reason that is prose'     => [['--reason' => 'Case Review'] + self::AUTHORITY, self::REASON],
            'an empty external ref'      => [['--reference' => ''] + self::AUTHORITY, self::REFERENCE],
            'an external ref too long'   => [['--reference' => str_repeat('a', 192)] + self::AUTHORITY, self::REFERENCE],
            'an external ref with a NUL' => [['--reference' => "app\0"] + self::AUTHORITY, self::REFERENCE],
        ];
    }

    /**
     * Each refused authority fails closed, naming the option and never what was
     * given.
     *
     * @param  array<string, string>  $options
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideRefusedAuthorities')]
    public function testRefusesAMissingOrMalformedAuthority(array $options, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        LifecycleOptions::authority(self::command($options));
    }

    /**
     * An external reference of exactly 191 characters is the longest kept,
     * which protects against a mutation that moves the bound by one.
     *
     * @return void
     */
    public function testTheLongestExternalReferenceIsKept(): void
    {
        $reference = str_repeat('a', 191);

        self::assertSame($reference, LifecycleOptions::authority(self::command(['--reference' => $reference] + self::AUTHORITY))->externalReference);
    }

    /**
     * A reference is split on its first colon, so an id may hold colons of its
     * own, and a type may be a class name.
     *
     * @return void
     */
    public function testAReferenceIsSplitOnItsFirstColon(): void
    {
        self::assertSame(['type' => 'organisation', 'id' => 'org_01'], LifecycleOptions::reference('tenant', 'organisation:org_01')->toArray());
        self::assertSame(['type' => 'App\Models\User', 'id' => '42:eu:7'], LifecycleOptions::reference('about', 'App\Models\User:42:eu:7')->toArray());
    }

    /**
     * Rows of `[value]`: values that name no reference.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideRefusedReferences(): iterable
    {
        yield from [
            'no colon'            => ['organisation'],
            'no type'             => [':org_01'],
            'no id'               => ['organisation:'],
            'nothing'             => [''],
            'a colon alone'       => [':'],
            'a control character' => ["organisation\x1b:org_01"],
            'an id too long'      => ['organisation:' . str_repeat('1', 192)],
        ];
    }

    /**
     * Each refused reference fails closed, naming the option.
     *
     * @param  string  $value
     * @return void
     */
    #[DataProvider('provideRefusedReferences')]
    public function testRefusesAValueThatNamesNoReference(string $value): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The --tenant option must name a reference as `type:id`, each part 1 to 191 characters with no control characters.');

        LifecycleOptions::reference('tenant', $value);
    }

    /**
     * Rows of `[value, the instant in UTC]`: each form an instant is accepted
     * in.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideInstants(): iterable
    {
        yield from [
            'a date'                 => ['2026-11-02', '2026-11-02T00:00:00.000000Z'],
            'a time in UTC'          => ['2026-11-02T09:30:15Z', '2026-11-02T09:30:15.000000Z'],
            'a time with a fraction' => ['2026-11-02T09:30:15.123456Z', '2026-11-02T09:30:15.123456Z'],
            'a short fraction'       => ['2026-11-02T09:30:15.5Z', '2026-11-02T09:30:15.500000Z'],
            'a time with an offset'  => ['2026-11-02T11:30:15+02:00', '2026-11-02T09:30:15.000000Z'],
            'a negative offset'      => ['2026-11-01T23:00:00-05:00', '2026-11-02T04:00:00.000000Z'],
            'a leap day'             => ['2028-02-29', '2028-02-29T00:00:00.000000Z'],
        ];
    }

    /**
     * Each accepted form gives its instant, in UTC.
     *
     * @param  string  $value
     * @param  string  $expected
     * @return void
     */
    #[DataProvider('provideInstants')]
    public function testAnInstantIsReadInEachForm(string $value, string $expected): void
    {
        $instant = LifecycleOptions::instant('from', $value);

        self::assertSame($expected, $instant->format('Y-m-d\TH:i:s.u\Z'));
        self::assertSame('UTC', $instant->getTimezone()->getName());
    }

    /**
     * Rows of `[value]`: values that name no instant, a date or a time that
     * does not exist among them, which is never rolled over.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideRefusedInstants(): iterable
    {
        yield from [
            'a day that does not exist'   => ['2026-02-30'],
            'not a leap year'             => ['2027-02-29'],
            'an hour that does not exist' => ['2026-11-02T25:00:00Z'],
            'a month that does not exist' => ['2026-13-02T09:00:00Z'],
            'no zone'                     => ['2026-11-02T09:00:00'],
            'a space for the T'           => ['2026-11-02 09:00:00Z'],
            'seven fractional digits'     => ['2026-11-02T09:00:00.1234567Z'],
            'no seconds'                  => ['2026-11-02T09:00Z'],
            'words'                       => ['tomorrow'],
            'nothing'                     => [''],
            'a trailing newline'          => ["2026-11-02\n"],
        ];
    }

    /**
     * Each refused instant fails closed, naming the option.
     *
     * @param  string  $value
     * @return void
     */
    #[DataProvider('provideRefusedInstants')]
    public function testRefusesAValueThatNamesNoInstant(string $value): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The --review-by option must be an ISO-8601 time with `Z` or an offset, or a `Y-m-d` date.');

        LifecycleOptions::instant('review-by', $value);
    }

    /**
     * Every basis is read by its value.
     *
     * @return void
     */
    public function testEveryBasisIsReadByItsValue(): void
    {
        foreach (HoldBasis::cases() as $basis) {
            self::assertSame($basis, LifecycleOptions::basis('basis', $basis->value), $basis->value);
        }
    }

    /**
     * A basis that is not one, or none, is refused, naming the option and every
     * basis there is.
     *
     * @return void
     */
    public function testRefusesAValueThatNamesNoBasis(): void
    {
        foreach (['LEGAL_CLAIM', 'litigation', '', null] as $value) {
            try {
                LifecycleOptions::basis('hold-basis', $value);

                self::fail('Expected the basis to be refused.');
            } catch (\InvalidArgumentException $refusal) {
                self::assertSame('The --hold-basis option must be legal_claim, regulatory, investigation or other.', $refusal->getMessage());
            }
        }
    }

    /**
     * `LifecycleOptions` is a utility container, not to be instantiated: its
     * constructor is private. Reflection invokes it so the line is covered
     * while still documenting the access modifier.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(LifecycleOptions::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(LifecycleOptions::class, $instance);
    }

    /**
     * A command of the authority's options, given the options' values.
     *
     * @param  array<string, string>  $options
     * @return \Illuminate\Console\Command
     */
    private static function command(array $options): Command
    {
        $command = new class extends Command {
            /** @var string The name and signature of the console command. */
            protected $signature = 'lifecycle-options:probe {--by-type=} {--by-id=} {--reason=} {--reference=}';
        };

        $command->setInput(new ArrayInput($options, $command->getDefinition()));

        return $command;
    }
}
