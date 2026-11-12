<?php

declare(strict_types = 1);

namespace Tests\Unit\Contributors;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Contracts\ContextContributor;
use SineMacula\Laravel\AuditLog\Contributors\ActorContributor;
use SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry;
use SineMacula\Laravel\AuditLog\Contributors\OriginContributor;
use SineMacula\Laravel\AuditLog\Contributors\RequestContributor;
use Tests\Fixtures\Contributors\ActorFillingContributor;
use Tests\Fixtures\Contributors\QueryingContributor;
use Tests\Fixtures\Contributors\TenantContributor;

/**
 * Unit tests for the contributors every capture runs: the defaults first, each
 * registered one after them once and in order, and the freeze.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ContributorRegistry::class)]
final class ContributorRegistryTest extends TestCase
{
    /** @var list<class-string> The defaults, in the order they run. */
    private const array DEFAULTS = [OriginContributor::class, RequestContributor::class, ActorContributor::class];

    /** @var string The message a frozen list refuses with. */
    private const string FROZEN = 'Contributors are registered while the application boots, and it has already booted.';

    /**
     * With nothing registered the list is the defaults, in order.
     *
     * @return void
     */
    public function testHoldsTheDefaultsInOrder(): void
    {
        self::assertSame(self::DEFAULTS, (new ContributorRegistry)->classes());
    }

    /**
     * Registered contributors follow the defaults, in the order given.
     *
     * @return void
     */
    public function testAddsAfterTheDefaultsInOrder(): void
    {
        $registry = new ContributorRegistry;

        $registry->add(TenantContributor::class);
        $registry->add(ActorFillingContributor::class);

        self::assertSame([...self::DEFAULTS, TenantContributor::class, ActorFillingContributor::class], $registry->classes());
    }

    /**
     * Registering a contributor again changes nothing, and it keeps its place.
     *
     * @return void
     */
    public function testAddingTwiceIsIdempotent(): void
    {
        $registry = new ContributorRegistry;

        $registry->add(TenantContributor::class);
        $registry->add(ActorFillingContributor::class);
        $registry->add(TenantContributor::class);

        self::assertSame([...self::DEFAULTS, TenantContributor::class, ActorFillingContributor::class], $registry->classes());
    }

    /**
     * Rows of `[class]`: each default.
     *
     * @return iterable<string, array{0: class-string}>
     */
    public static function provideDefaults(): iterable
    {
        foreach (self::DEFAULTS as $default) {
            yield $default => [$default];
        }
    }

    /**
     * Registering a default changes nothing, so it does not run twice.
     *
     * @param  class-string  $default
     * @return void
     */
    #[DataProvider('provideDefaults')]
    public function testAddingADefaultChangesNothing(string $default): void
    {
        $registry = new ContributorRegistry;

        $registry->add($default);

        self::assertSame(self::DEFAULTS, $registry->classes());
    }

    /**
     * A class that does not implement the contract is refused, by name, and
     * registers nothing.
     *
     * @return void
     */
    public function testRefusesAClassThatIsNotAContributor(): void
    {
        $registry = new ContributorRegistry;

        try {
            $registry->add(\stdClass::class);

            self::fail('Expected the class to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('`stdClass` is not a class implementing `ContextContributor`.', $exception->getMessage());
        }

        self::assertSame(self::DEFAULTS, $registry->classes());
    }

    /**
     * Rows of `[what is given]`: names of no class that could be instantiated.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideNonClasses(): iterable
    {
        yield from [
            'no such class' => ['App\Contributors\Missing'],
            'empty'         => [''],
            'the contract'  => [ContextContributor::class],
        ];
    }

    /**
     * What is not a class is refused the same way, and the contract is an
     * interface, not a class implementing itself.
     *
     * @param  string  $class
     * @return void
     */
    #[DataProvider('provideNonClasses')]
    public function testRefusesWhatIsNotAClass(string $class): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(sprintf('`%s` is not a class implementing `ContextContributor`.', $class));

        (new ContributorRegistry)->add($class);
    }

    /**
     * A frozen list refuses a contributor and keeps what it had.
     *
     * @return void
     */
    public function testFrozenRefuses(): void
    {
        $registry = new ContributorRegistry;

        $registry->add(TenantContributor::class);
        $registry->freeze();

        try {
            $registry->add(ActorFillingContributor::class);

            self::fail('Expected the registration to be refused.');
        } catch (\LogicException $exception) {
            self::assertSame(self::FROZEN, $exception->getMessage());
        }

        self::assertSame([...self::DEFAULTS, TenantContributor::class], $registry->classes());
    }

    /**
     * Once frozen, even a class that is not a contributor gets the frozen
     * refusal: registering too late is the error to fix first.
     *
     * @return void
     */
    public function testTheFrozenCheckComesFirst(): void
    {
        $registry = new ContributorRegistry;

        $registry->freeze();

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(self::FROZEN);

        $registry->add(\stdClass::class);
    }

    /**
     * A list starts unfrozen, says when it is frozen, and freezing it again
     * changes nothing.
     *
     * @return void
     */
    public function testFreezingIsIdempotentAndReported(): void
    {
        $registry = new ContributorRegistry;

        self::assertFalse($registry->isFrozen());

        $registry->freeze();

        self::assertTrue($registry->isFrozen());

        $registry->freeze();

        self::assertTrue($registry->isFrozen());
    }

    /**
     * Registering holds a name: a contributor that could not be built without a
     * container is registered without one, so nothing is retained in a worker.
     *
     * @return void
     */
    public function testInstantiatesNothing(): void
    {
        $registry = new ContributorRegistry;

        $registry->add(QueryingContributor::class);

        self::assertSame([...self::DEFAULTS, QueryingContributor::class], $registry->classes());
    }
}
