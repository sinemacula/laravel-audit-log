<?php

declare(strict_types = 1);

namespace Tests\Unit\Capture\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Capture\Enums\CapturedActivity;
use SineMacula\Laravel\AuditLog\Contracts\DefinesAuditEvents;
use SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Definitions\FieldRule;
use SineMacula\Laravel\AuditLog\Records\EventCode;

/**
 * Unit tests for the codes the package records when it captures Laravel's own
 * events: the whole ordered vocabulary, each case defining its own code, and
 * every definition in the security category on its first version, dropping what
 * it does not list and keeping only what each code needs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CapturedActivity::class)]
final class CapturedActivityTest extends TestCase
{
    /**
     * The codes are the vocabulary's, in its order, so a renamed, reordered,
     * added or removed code fails here.
     *
     * @return void
     */
    public function testTheCodesAreTheVocabularys(): void
    {
        self::assertSame([
            'SIGNED_IN'                => 'authentication.signed_in',
            'SESSION_RESTORED'         => 'authentication.session_restored',
            'SIGN_IN_FAILED'           => 'authentication.sign_in_failed',
            'SIGNED_OUT'               => 'authentication.signed_out',
            'SIGNED_OUT_OTHER_DEVICES' => 'authentication.signed_out_other_devices',
            'LOCKED_OUT'               => 'authentication.locked_out',
            'REGISTERED'               => 'account.registered',
            'EMAIL_VERIFIED'           => 'account.email_verified',
            'PASSWORD_RESET'           => 'account.password_reset',
            'PASSWORD_RESET_REQUESTED' => 'account.password_reset_requested',
            'GATE_DENIED'              => 'authorization.gate_denied',
        ], array_column(array_map(static fn (CapturedActivity $case): array => [$case->name, $case->value], CapturedActivity::cases()), 1, 0));
    }

    /**
     * Rows of `[case]`: every package code.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Capture\Enums\CapturedActivity}>
     */
    public static function provideCases(): iterable
    {
        foreach (CapturedActivity::cases() as $case) {
            yield $case->name => [$case];
        }
    }

    /**
     * Each case's definition is for its own code, which is a valid event code,
     * and the enum defines events.
     *
     * @param  \SineMacula\Laravel\AuditLog\Capture\Enums\CapturedActivity  $case
     * @return void
     */
    #[DataProvider('provideCases')]
    public function testEveryCaseDefinesItsOwnCode(CapturedActivity $case): void
    {
        self::assertInstanceOf(DefinesAuditEvents::class, $case);
        self::assertSame($case->value, $case->definition()->code);
        self::assertSame($case->value, EventCode::of($case)->value);
    }

    /**
     * Each definition is version 1 of its payload contract, in the `security`
     * category, drops every field it does not list, maps to no OCSF class of
     * its own, and is the same on every call.
     *
     * @param  \SineMacula\Laravel\AuditLog\Capture\Enums\CapturedActivity  $case
     * @return void
     */
    #[DataProvider('provideCases')]
    public function testEveryDefinitionIsSecurityVersionOneAndDropsUnlisted(CapturedActivity $case): void
    {
        $definition = $case->definition();

        self::assertSame(1, $definition->version);
        self::assertSame('security', $definition->category);
        self::assertSame(FieldHandling::DROP, $definition->unlisted);
        self::assertNull($definition->ocsfMapper);
        self::assertTrue($definition->equals($case->definition()));
    }

    /**
     * A sign-in and a restored session keep whether it was remembered, and
     * nothing else.
     *
     * @return void
     */
    public function testTheSignInsRetainOnlyRemember(): void
    {
        foreach ([CapturedActivity::SIGNED_IN, CapturedActivity::SESSION_RESTORED] as $case) {
            self::assertSame(['remember' => FieldHandling::RETAIN], self::rulesOf($case), $case->name);
        }
    }

    /**
     * A gate denial keeps the ability, its arguments and how many there were,
     * and nothing else.
     *
     * @return void
     */
    public function testTheGateDenialRetainsTheAbilityAndItsArguments(): void
    {
        self::assertSame([
            'ability'        => FieldHandling::RETAIN,
            'argument_count' => FieldHandling::RETAIN,
            'arguments'      => FieldHandling::RETAIN,
        ], self::rulesOf(CapturedActivity::GATE_DENIED));
    }

    /**
     * Every other code keeps no property at all, so a failed sign-in, a lockout
     * and a reset request keep no identifier of the person.
     *
     * @return void
     */
    public function testTheOtherCodesRetainNothing(): void
    {
        $retaining = [CapturedActivity::SIGNED_IN, CapturedActivity::SESSION_RESTORED, CapturedActivity::GATE_DENIED];
        $others    = array_values(array_filter(CapturedActivity::cases(), static fn (CapturedActivity $case): bool => !in_array($case, $retaining, true)));

        self::assertCount(8, $others);

        foreach ($others as $case) {
            self::assertSame([], self::rulesOf($case), $case->name);
        }
    }

    /**
     * The catalogue registers every package code from the enum, each as its
     * case defines it, and registering the enum again changes nothing.
     *
     * @return void
     */
    public function testTheCatalogueAcceptsTheEnum(): void
    {
        $catalogue = new EventCatalogue;

        $catalogue->define(CapturedActivity::class);
        $catalogue->define(CapturedActivity::class);

        foreach (CapturedActivity::cases() as $case) {
            $code = EventCode::of($case);

            self::assertTrue($catalogue->isRegistered($code), $case->name);
            self::assertTrue($catalogue->definitionFor($code, true)->equals($case->definition()), $case->name);
        }
    }

    /**
     * A definition of a package code that differs from the package's is refused
     * once the package has defined its codes.
     *
     * @return void
     */
    public function testADifferentDefinitionOfAPackageCodeIsRefused(): void
    {
        $catalogue = new EventCatalogue;

        $catalogue->define(CapturedActivity::class);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('The event code `authentication.sign_in_failed` is already defined differently; a code has one definition.');

        $catalogue->define(EventDefinition::for(CapturedActivity::SIGN_IN_FAILED)->category('security')->retain('email'));
    }

    /**
     * The handling of each rule of the case's definition, by path.
     *
     * @param  \SineMacula\Laravel\AuditLog\Capture\Enums\CapturedActivity  $case
     * @return array<string, \SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling>
     */
    private static function rulesOf(CapturedActivity $case): array
    {
        return array_map(static fn (FieldRule $rule): FieldHandling => $rule->handling, $case->definition()->rules);
    }
}
