<?php

declare(strict_types = 1);

namespace Tests\Unit\Definitions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Contracts\DefinesAuditEvents;
use SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Records\EventCode;
use Tests\Fixtures\Definitions\Enums\InvoiceActivity;
use Tests\Fixtures\Definitions\Enums\MisdefinedActivity;
use Tests\Fixtures\Definitions\Enums\NumberedActivity;
use Tests\Fixtures\Definitions\Enums\RevisedInvoiceActivity;
use Tests\Unit\Stubs\Enums\StubActivity;

/**
 * Unit tests for the event catalogue: the permissive default and the refusal of
 * unregistered codes, registering a definition or a whole enum, idempotent
 * repeats, conflicts in either order, the enums it refuses and in what order,
 * and freezing once the application has booted.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EventCatalogue::class)]
final class EventCatalogueTest extends TestCase
{
    /** @var string The message a conflicting definition of `invoice.approved` fails with. */
    private const string CONFLICT_MESSAGE = 'The event code `invoice.approved` is already defined differently; a code has one definition.';

    /** @var string The message a registration after booting fails with. */
    private const string FROZEN_MESSAGE = 'Event definitions are registered while the application boots, and it has already booted.';

    /**
     * A code no definition registers takes the permissive default: version 1,
     * `general`, no rules, and every field retained. Registration is not
     * required unless asked for.
     *
     * @return void
     */
    public function testAnUnregisteredCodeTakesThePermissiveDefault(): void
    {
        $code       = EventCode::of('user.suspended');
        $definition = (new EventCatalogue)->definitionFor($code);

        self::assertTrue($definition->equals(EventDefinition::permissive($code)));
        self::assertSame(FieldHandling::RETAIN, $definition->unlisted);
        self::assertFalse((new EventCatalogue)->isRegistered($code));
        self::assertTrue((new EventCatalogue)->definitionFor($code, false)->equals($definition));
    }

    /**
     * When registration is required, a code no definition registers is a
     * programming error, named in the message.
     *
     * @return void
     */
    public function testAnUnregisteredCodeIsRefusedWhenRegistrationIsRequired(): void
    {
        $catalogue = new EventCatalogue;

        $catalogue->define(InvoiceActivity::class);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The event code `user.suspended` is not registered, and unregistered codes are refused.');

        $catalogue->definitionFor(EventCode::of('user.suspended'), requireRegistered: true);
    }

    /**
     * When registration is required, a registered code is still served its
     * definition.
     *
     * @return void
     */
    public function testARegisteredCodeIsServedWhenRegistrationIsRequired(): void
    {
        $catalogue  = new EventCatalogue;
        $definition = EventDefinition::for('invoice.approved')->retain('amount');

        $catalogue->define($definition);

        self::assertSame($definition, $catalogue->definitionFor(EventCode::of('invoice.approved'), requireRegistered: true));
    }

    /**
     * Whether registration is required is asked on each call, so one catalogue,
     * resolved once at boot, answers each capture by what that capture asks: a
     * refusal leaves nothing behind, and the same code then takes the default.
     *
     * @return void
     */
    public function testRegistrationIsRequiredPerCall(): void
    {
        $catalogue = new EventCatalogue;
        $code      = EventCode::of('user.suspended');

        self::assertTrue($catalogue->definitionFor($code)->equals(EventDefinition::permissive($code)));

        try {
            $catalogue->definitionFor($code, true);
            self::fail('Expected the unregistered code to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('The event code `user.suspended` is not registered, and unregistered codes are refused.', $exception->getMessage());
        }

        self::assertTrue($catalogue->definitionFor($code)->equals(EventDefinition::permissive($code)));
        self::assertFalse($catalogue->isRegistered($code));
    }

    /**
     * Freezing the catalogue changes nothing about how a code is served, so a
     * capture after boot reads it as one during boot would.
     *
     * @return void
     */
    public function testAFrozenCatalogueStillServesEachCallAsAsked(): void
    {
        $catalogue  = new EventCatalogue;
        $definition = EventDefinition::for('invoice.approved');

        $catalogue->define($definition);
        $catalogue->freeze();

        self::assertSame($definition, $catalogue->definitionFor(EventCode::of('invoice.approved'), true));
        self::assertTrue($catalogue->definitionFor(EventCode::of('user.suspended'))->equals(EventDefinition::permissive(EventCode::of('user.suspended'))));

        $this->expectException(\InvalidArgumentException::class);

        $catalogue->definitionFor(EventCode::of('user.suspended'), true);
    }

    /**
     * A definition registered on its own is reported as registered and served
     * for its code, and no other code is registered by it.
     *
     * @return void
     */
    public function testDefinesASingleDefinition(): void
    {
        $catalogue  = new EventCatalogue;
        $definition = EventDefinition::for('invoice.approved')->category('finance');

        $catalogue->define($definition);

        self::assertTrue($catalogue->isRegistered(EventCode::of('invoice.approved')));
        self::assertSame($definition, $catalogue->definitionFor(EventCode::of('invoice.approved')));
        self::assertFalse($catalogue->isRegistered(EventCode::of('invoice.voided')));
    }

    /**
     * An enum registers every one of its cases, each under its own code and
     * equal to the case's definition.
     *
     * @return void
     */
    public function testDefinesEveryCaseOfAnEnum(): void
    {
        $catalogue = new EventCatalogue;

        $catalogue->define(InvoiceActivity::class);

        foreach (InvoiceActivity::cases() as $case) {
            $code = EventCode::of($case);

            self::assertTrue($catalogue->isRegistered($code), $case->value);
            self::assertTrue($catalogue->definitionFor($code)->equals($case->definition()), $case->value);
        }

        $approved = $catalogue->definitionFor(EventCode::of(InvoiceActivity::APPROVED));

        self::assertSame(2, $approved->version);
        self::assertSame('finance', $approved->category);
        self::assertSame(FieldHandling::DROP, $approved->unlisted);
    }

    /**
     * Registering the same enum twice, then one of its definitions again,
     * changes nothing and throws nothing: the definition first registered is
     * kept, and only the enum's two codes are registered.
     *
     * @return void
     */
    public function testAnIdenticalRegistrationRepeatedIsIdempotent(): void
    {
        $catalogue = new EventCatalogue;
        $code      = EventCode::of(InvoiceActivity::APPROVED);

        $catalogue->define(InvoiceActivity::class);

        $first = $catalogue->definitionFor($code);

        $catalogue->define(InvoiceActivity::class);
        $catalogue->define(InvoiceActivity::APPROVED->definition());

        self::assertSame($first, $catalogue->definitionFor($code));
        self::assertTrue($catalogue->isRegistered(EventCode::of(InvoiceActivity::REFUND_FAILED)));
        self::assertFalse($catalogue->isRegistered(EventCode::of(RevisedInvoiceActivity::VOIDED)));
    }

    /**
     * Rows of `[the enum registered first, the enum registered second]`.
     *
     * @return iterable<string, array{0: class-string, 1: class-string}>
     */
    public static function provideConflictingOrders(): iterable
    {
        yield from [
            'the revision second' => [InvoiceActivity::class, RevisedInvoiceActivity::class],
            'the revision first'  => [RevisedInvoiceActivity::class, InvoiceActivity::class],
        ];
    }

    /**
     * Two enums defining one code differently conflict whichever is registered
     * first, and the second is refused, naming the code.
     *
     * @param  class-string  $first
     * @param  class-string  $second
     * @return void
     */
    #[DataProvider('provideConflictingOrders')]
    public function testAConflictingDefinitionThrowsInEitherOrder(string $first, string $second): void
    {
        $catalogue = new EventCatalogue;

        $catalogue->define($first);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(self::CONFLICT_MESSAGE);

        $catalogue->define($second);
    }

    /**
     * A refused enum registers none of its cases, not even one declared before
     * the conflicting case, and the definitions already registered stay.
     *
     * @return void
     */
    public function testAConflictingEnumRegistersNoneOfItsCases(): void
    {
        $catalogue = new EventCatalogue;

        $catalogue->define(InvoiceActivity::class);

        try {
            $catalogue->define(RevisedInvoiceActivity::class);

            self::fail('Expected the conflicting enum to be refused.');
        } catch (\LogicException $exception) {
            self::assertSame(self::CONFLICT_MESSAGE, $exception->getMessage());
        }

        self::assertFalse($catalogue->isRegistered(EventCode::of(RevisedInvoiceActivity::VOIDED)));
        self::assertSame('finance', $catalogue->definitionFor(EventCode::of(InvoiceActivity::APPROVED))->category);
    }

    /**
     * A definition differing from the one registered for its code, in its
     * category alone, is refused, and the first stays.
     *
     * @return void
     */
    public function testAConflictingSingleDefinitionThrows(): void
    {
        $catalogue = new EventCatalogue;
        $first     = EventDefinition::for('a.b');

        $catalogue->define($first);

        try {
            $catalogue->define(EventDefinition::for('a.b')->category('other'));

            self::fail('Expected the conflicting definition to be refused.');
        } catch (\LogicException $exception) {
            self::assertSame('The event code `a.b` is already defined differently; a code has one definition.', $exception->getMessage());
        }

        self::assertSame($first, $catalogue->definitionFor(EventCode::of('a.b')));
    }

    /**
     * Rows of `[class name]`: a plain class, an enum without the contract, and
     * a class that does not exist.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideNonDefiningClasses(): iterable
    {
        yield from [
            'a plain class'                => [\stdClass::class],
            'an enum without the contract' => [StubActivity::class],
            'a missing class'              => ['Tests\Missing\Nothing'],
            'the contract itself'          => [DefinesAuditEvents::class],
        ];
    }

    /**
     * A class name that is not an enum implementing the contract is refused,
     * naming the class.
     *
     * @param  string  $class
     * @return void
     */
    #[DataProvider('provideNonDefiningClasses')]
    public function testRefusesAClassThatIsNotADefiningEnum(string $class): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(sprintf('`%s` is not an enum implementing `DefinesAuditEvents`.', $class));

        (new EventCatalogue)->define($class);
    }

    /**
     * An enum whose case defines a code other than its own value is refused,
     * naming the case, and registers nothing.
     *
     * @return void
     */
    public function testRefusesACaseThatDefinesAnotherCode(): void
    {
        $catalogue = new EventCatalogue;

        try {
            $catalogue->define(MisdefinedActivity::class);

            self::fail('Expected the misdefining enum to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame(sprintf('`%s::FIRST` defines another event code.', MisdefinedActivity::class), $exception->getMessage());
        }

        self::assertFalse($catalogue->isRegistered(EventCode::of('app.first')));
        self::assertFalse($catalogue->isRegistered(EventCode::of('app.second')));
    }

    /**
     * An integer-backed enum implementing the contract is refused for its
     * backing type before any case is asked for its definition, so it is not
     * reported as defining another code.
     *
     * @return void
     */
    public function testRefusesAnIntegerBackedDefiningEnum(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('An event code enum must be backed by strings.');

        (new EventCatalogue)->define(NumberedActivity::class);
    }

    /**
     * Rows of `[registration]`: a definition, and an enum class.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Definitions\EventDefinition|string}>
     */
    public static function provideRegistrations(): iterable
    {
        yield from [
            'a definition'  => [EventDefinition::for('invoice.approved')],
            'an enum class' => [InvoiceActivity::class],
        ];
    }

    /**
     * Once frozen, the catalogue refuses any registration, and registers
     * nothing.
     *
     * @param  \SineMacula\Laravel\AuditLog\Definitions\EventDefinition|string  $registration
     * @return void
     */
    #[DataProvider('provideRegistrations')]
    public function testDefiningAfterFreezingThrows(EventDefinition|string $registration): void
    {
        $catalogue = new EventCatalogue;

        $catalogue->freeze();

        try {
            $catalogue->define($registration);

            self::fail('Expected the registration after booting to be refused.');
        } catch (\LogicException $exception) {
            self::assertSame(self::FROZEN_MESSAGE, $exception->getMessage());
        }

        self::assertFalse($catalogue->isRegistered(EventCode::of('invoice.approved')));
    }

    /**
     * The frozen check comes before any check of what is registered, so a
     * malformed registration after booting is refused as late, not as
     * malformed.
     *
     * @return void
     */
    public function testTheFrozenCheckComesFirst(): void
    {
        $catalogue = new EventCatalogue;

        $catalogue->freeze();

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(self::FROZEN_MESSAGE);

        $catalogue->define(\stdClass::class);
    }

    /**
     * A catalogue is not frozen until it is, and freezing it again changes
     * nothing.
     *
     * @return void
     */
    public function testFreezingIsIdempotentAndReported(): void
    {
        $catalogue = new EventCatalogue;

        self::assertFalse($catalogue->isFrozen());

        $catalogue->freeze();
        $catalogue->freeze();

        self::assertTrue($catalogue->isFrozen());
    }

    /**
     * Definitions registered before freezing are still served after it, and so
     * is the permissive default.
     *
     * @return void
     */
    public function testDefinitionsAreServedAfterFreezing(): void
    {
        $catalogue = new EventCatalogue;

        $catalogue->define(InvoiceActivity::class);
        $catalogue->freeze();

        $code = EventCode::of(InvoiceActivity::REFUND_FAILED);

        self::assertTrue($catalogue->isRegistered($code));
        self::assertTrue($catalogue->definitionFor($code)->equals(InvoiceActivity::REFUND_FAILED->definition()));
        self::assertSame(FieldHandling::RETAIN, $catalogue->definitionFor(EventCode::of('user.suspended'))->unlisted);
    }
}
