<?php

declare(strict_types = 1);

namespace Tests\Unit\Capture;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Capture\MapperRegistry;
use SineMacula\Laravel\AuditLog\Contracts\AuditLogEvent;
use SineMacula\Laravel\AuditLog\Contracts\EventMapper;
use SineMacula\Laravel\AuditLog\Events\AuditCaptureFailed;
use Tests\Fixtures\Capture\Events\AccountEvent;
use Tests\Fixtures\Capture\Events\ExcludedPortalEvent;
use Tests\Fixtures\Capture\Events\PackageShapedEvent;
use Tests\Fixtures\Capture\Events\PortalEvent;
use Tests\Fixtures\Capture\Events\PortalSignedIn;
use Tests\Fixtures\Capture\Events\RenewedPortalSession;
use Tests\Fixtures\Capture\Events\SignedInToPortal;
use Tests\Fixtures\Capture\Mappers\NotAMapper;
use Tests\Fixtures\Capture\Mappers\NullMapper;
use Tests\Fixtures\Capture\Mappers\PortalMapper;
use Tests\Fixtures\Capture\Mappers\ThrowingMapper;

/**
 * Unit tests for the registry of event mappers: resolution order, excepted
 * subtypes, refusals, the freeze and the per-class cache.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MapperRegistry::class)]
final class MapperRegistryTest extends TestCase
{
    /** @var string The message a second, different registration is refused with. */
    private const string MAPPED_DIFFERENTLY = '`%s` is already mapped differently; an event class or interface has one mapper.';

    /** @var string The message an excepted type outside the mapping is refused with. */
    private const string EXCEPT_OUTSIDE = '`%s` is excepted from the mapping of `%s`, and is not a class or interface that extends or implements it.';

    /**
     * A mapping of an event's own class resolves it, and resolves nothing else.
     *
     * @return void
     */
    public function testAnExactClassMappingResolves(): void
    {
        $registry = new MapperRegistry;

        $registry->map(SignedInToPortal::class, PortalMapper::class);

        self::assertSame(PortalMapper::class, $registry->mapperFor(SignedInToPortal::class));
        self::assertNull($registry->mapperFor(ExcludedPortalEvent::class));
    }

    /**
     * A mapping of an interface resolves every class implementing it.
     *
     * @return void
     */
    public function testASingleInterfaceMappingResolves(): void
    {
        $registry = new MapperRegistry;

        $registry->map(PortalEvent::class, PortalMapper::class);

        self::assertSame(PortalMapper::class, $registry->mapperFor(SignedInToPortal::class));
        self::assertSame(PortalMapper::class, $registry->mapperFor(ExcludedPortalEvent::class));
        self::assertNull($registry->mapperFor(PortalSignedIn::class));
    }

    /**
     * A mapping of a class resolves its subclasses.
     *
     * @return void
     */
    public function testASingleParentMappingResolves(): void
    {
        $registry = new MapperRegistry;

        $registry->map(PortalSignedIn::class, PortalMapper::class);

        self::assertSame(PortalMapper::class, $registry->mapperFor(RenewedPortalSession::class));
        self::assertSame(PortalMapper::class, $registry->mapperFor(PortalSignedIn::class));
    }

    /**
     * An event's own class's mapping wins over any broad one, whether the broad
     * ones are interfaces or a parent class, and however many there are.
     *
     * @return void
     */
    public function testTheExactClassWinsOverABroadMapping(): void
    {
        $registry = new MapperRegistry;

        $registry->map(PortalEvent::class, PortalMapper::class);
        $registry->map(AccountEvent::class, NullMapper::class);
        $registry->map(SignedInToPortal::class, ThrowingMapper::class);
        $registry->map(PortalSignedIn::class, PortalMapper::class);
        $registry->map(RenewedPortalSession::class, NullMapper::class);

        self::assertSame(ThrowingMapper::class, $registry->mapperFor(SignedInToPortal::class));
        self::assertSame(NullMapper::class, $registry->mapperFor(RenewedPortalSession::class));
    }

    /**
     * Two broad mappings that both apply are an ambiguity naming both, sorted,
     * never a choice between them.
     *
     * @return void
     */
    public function testTwoBroadMappingsAreAnAmbiguity(): void
    {
        $registry = new MapperRegistry;

        $registry->map(PortalEvent::class, PortalMapper::class);
        $registry->map(AccountEvent::class, NullMapper::class);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(sprintf('`%s` matches several mappings: `%s`, `%s`.', SignedInToPortal::class, AccountEvent::class, PortalEvent::class));

        $registry->mapperFor(SignedInToPortal::class);
    }

    /**
     * A parent class's mapping and an interface's mapping that both apply are
     * an ambiguity too, however the two broad kinds mix.
     *
     * @return void
     */
    public function testAParentAndAnInterfaceMappingAreAnAmbiguity(): void
    {
        $registry = new MapperRegistry;
        $event    = new readonly class extends PortalSignedIn implements PortalEvent {
            /**
             * The id of the user who signed in.
             *
             * @return string
             */
            #[\Override]
            public function userId(): string
            {
                return $this->user;
            }
        };

        $registry->map(PortalSignedIn::class, PortalMapper::class);
        $registry->map(PortalEvent::class, NullMapper::class);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(sprintf('matches several mappings: `%s`, `%s`.', PortalEvent::class, PortalSignedIn::class));

        $registry->mapperFor($event::class);
    }

    /**
     * An ambiguity is kept with the class's answer, so every lookup of the
     * class is refused, never only the first.
     *
     * @return void
     */
    public function testAnAmbiguityIsRefusedOnEveryLookup(): void
    {
        $registry = new MapperRegistry;

        $registry->map(PortalEvent::class, PortalMapper::class);
        $registry->map(AccountEvent::class, NullMapper::class);

        foreach ([1, 2] as $lookup) {
            try {
                $registry->mapperFor(SignedInToPortal::class);

                self::fail(sprintf('Expected lookup %d to be refused.', $lookup));
            } catch (\LogicException $exception) {
                self::assertStringContainsString('matches several mappings', $exception->getMessage(), (string) $lookup);
            }
        }
    }

    /**
     * An excepted class, and every subclass of it, is skipped by the mapping
     * that excepts it, while its siblings stay mapped.
     *
     * @return void
     */
    public function testAnExceptedClassAndItsSubclassesAreUnmapped(): void
    {
        $registry = new MapperRegistry;

        $registry->map(PortalEvent::class, PortalMapper::class, [ExcludedPortalEvent::class]);
        $registry->map(\LogicException::class, PortalMapper::class, [\BadFunctionCallException::class]);

        self::assertNull($registry->mapperFor(ExcludedPortalEvent::class));
        self::assertSame(PortalMapper::class, $registry->mapperFor(SignedInToPortal::class));
        self::assertNull($registry->mapperFor(\BadFunctionCallException::class));
        self::assertNull($registry->mapperFor(\BadMethodCallException::class));
        self::assertSame(PortalMapper::class, $registry->mapperFor(\InvalidArgumentException::class));
    }

    /**
     * An excepted class skips only the mapping that excepts it: another broad
     * mapping still applies, alone and so without an ambiguity.
     *
     * @return void
     */
    public function testAnExceptLeavesAnotherMappingToApply(): void
    {
        $registry = new MapperRegistry;

        $registry->map(PortalEvent::class, PortalMapper::class, [SignedInToPortal::class]);
        $registry->map(AccountEvent::class, NullMapper::class);

        self::assertSame(NullMapper::class, $registry->mapperFor(SignedInToPortal::class));
    }

    /**
     * Registering the same mapper for the same class again changes nothing.
     *
     * @return void
     */
    public function testIdenticalRegistrationChangesNothing(): void
    {
        $registry = new MapperRegistry;

        $registry->map(PortalEvent::class, PortalMapper::class, [ExcludedPortalEvent::class]);
        $registry->map(PortalEvent::class, PortalMapper::class, [ExcludedPortalEvent::class]);

        self::assertSame(PortalMapper::class, $registry->mapperFor(SignedInToPortal::class));
        self::assertNull($registry->mapperFor(ExcludedPortalEvent::class));
    }

    /**
     * The excepted subtypes are a set: the same ones in another order, or one
     * named twice, are the same registration.
     *
     * @return void
     */
    public function testTheExceptOrderDoesNotMatter(): void
    {
        $registry = new MapperRegistry;

        $registry->map(\LogicException::class, PortalMapper::class, [\DomainException::class, \LengthException::class]);
        $registry->map(\LogicException::class, PortalMapper::class, [\LengthException::class, \DomainException::class]);
        $registry->map(\LogicException::class, PortalMapper::class, [\LengthException::class, \DomainException::class, \LengthException::class]);

        self::assertNull($registry->mapperFor(\DomainException::class));
        self::assertNull($registry->mapperFor(\LengthException::class));
    }

    /**
     * A class or interface named in another case is the same mapping, as PHP
     * names it: it resolves the class, and registering it again is identical.
     *
     * @return void
     */
    public function testANameInAnotherCaseIsTheSameMapping(): void
    {
        $registry = new MapperRegistry;

        $registry->map(strtolower(PortalSignedIn::class), strtoupper(PortalMapper::class), [strtolower(RenewedPortalSession::class)]);
        $registry->map(PortalSignedIn::class, PortalMapper::class, [RenewedPortalSession::class]);

        self::assertSame(PortalMapper::class, $registry->mapperFor(PortalSignedIn::class));
        self::assertNull($registry->mapperFor(RenewedPortalSession::class));
    }

    /**
     * A second, different mapper for a class is refused, naming the class.
     *
     * @return void
     */
    public function testASecondMapperForAClassIsRefused(): void
    {
        $registry = new MapperRegistry;

        $registry->map(PortalEvent::class, PortalMapper::class);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(sprintf(self::MAPPED_DIFFERENTLY, PortalEvent::class));

        $registry->map(PortalEvent::class, NullMapper::class);
    }

    /**
     * The same mapper with other excepted subtypes, fewer or more, is a
     * different registration and is refused.
     *
     * @return void
     */
    public function testADifferentExceptListIsRefused(): void
    {
        $registry = new MapperRegistry;

        $registry->map(PortalEvent::class, PortalMapper::class, [ExcludedPortalEvent::class]);

        foreach ([[], [ExcludedPortalEvent::class, SignedInToPortal::class]] as $except) {
            try {
                $registry->map(PortalEvent::class, PortalMapper::class, $except);

                self::fail('Expected a different except list to be refused.');
            } catch (\LogicException $exception) {
                self::assertSame(sprintf(self::MAPPED_DIFFERENTLY, PortalEvent::class), $exception->getMessage());
            }
        }

        self::assertNull($registry->mapperFor(ExcludedPortalEvent::class));
    }

    /**
     * The package's event marker itself is never mapped.
     *
     * @return void
     */
    public function testMappingThePackageMarkerIsRefused(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('The package\'s own events are never mapped.');

        (new MapperRegistry)->map(AuditLogEvent::class, PortalMapper::class);
    }

    /**
     * Rows of `[class]`: classes implementing the package's event marker, its
     * own and one shaped like it.
     *
     * @return iterable<string, array{0: class-string}>
     */
    public static function provideMarkedClasses(): iterable
    {
        yield from [
            'a package event'                  => [AuditCaptureFailed::class],
            'an event implementing the marker' => [PackageShapedEvent::class],
        ];
    }

    /**
     * A class implementing the package's event marker is never mapped, and
     * nothing is registered.
     *
     * @param  class-string  $class
     * @return void
     */
    #[DataProvider('provideMarkedClasses')]
    public function testMappingAClassImplementingTheMarkerIsRefused(string $class): void
    {
        $registry = new MapperRegistry;

        try {
            $registry->map($class, PortalMapper::class);

            self::fail('Expected a marked class to be refused.');
        } catch (\LogicException $exception) {
            self::assertSame('The package\'s own events are never mapped.', $exception->getMessage());
        }

        self::assertFalse($registry->hasMappings());
    }

    /**
     * Rows of `[mapper]`: names that are not a class the container can make
     * implementing `EventMapper`.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideNonMappers(): iterable
    {
        yield from [
            'a class that is not a mapper' => [NotAMapper::class],
            'the contract itself'          => [EventMapper::class],
            'no class at all'              => ['Tests\Fixtures\Capture\Mappers\MissingMapper'],
        ];
    }

    /**
     * A mapper that is not a class implementing `EventMapper` the container can
     * make is refused, naming it, and nothing is registered.
     *
     * @param  string  $mapper
     * @return void
     */
    #[DataProvider('provideNonMappers')]
    public function testAMapperThatIsNotAnEventMapperIsRefused(string $mapper): void
    {
        $registry = new MapperRegistry;

        try {
            $registry->map(PortalEvent::class, $mapper);

            self::fail('Expected the mapper to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame(sprintf('`%s` is not a class implementing `EventMapper`.', $mapper), $exception->getMessage());
        }

        self::assertFalse($registry->hasMappings());
    }

    /**
     * A name that is neither a class nor an interface is refused, naming it.
     *
     * @return void
     */
    public function testAnUnknownClassIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('`Tests\Fixtures\Capture\Events\MissingEvent` is not a class or an interface.');

        (new MapperRegistry)->map('Tests\Fixtures\Capture\Events\MissingEvent', PortalMapper::class);
    }

    /**
     * Rows of `[mapped, excepted]`: an excepted type that does not exist, is
     * the mapping itself, or is not a subtype of it.
     *
     * @return iterable<string, array{0: class-string, 1: string}>
     */
    public static function provideExceptsOutsideTheMapping(): iterable
    {
        yield from [
            'an unknown class'               => [PortalEvent::class, 'Tests\Fixtures\Capture\Events\MissingEvent'],
            'the mapping itself'             => [PortalEvent::class, PortalEvent::class],
            'an unrelated interface'         => [PortalEvent::class, AccountEvent::class],
            'an unrelated class'             => [PortalEvent::class, PortalSignedIn::class],
            'a parent of the mapping'        => [RenewedPortalSession::class, PortalSignedIn::class],
            'a class of a sibling interface' => [AccountEvent::class, ExcludedPortalEvent::class],
        ];
    }

    /**
     * An excepted type that is not a proper subtype of the mapped type is
     * refused, naming both, and nothing is registered.
     *
     * @param  class-string  $mapped
     * @param  string  $excepted
     * @return void
     */
    #[DataProvider('provideExceptsOutsideTheMapping')]
    public function testAnExceptOutsideTheMappingIsRefused(string $mapped, string $excepted): void
    {
        $registry = new MapperRegistry;

        try {
            $registry->map($mapped, PortalMapper::class, [$excepted]);

            self::fail('Expected the except to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame(sprintf(self::EXCEPT_OUTSIDE, $excepted, $mapped), $exception->getMessage());
        }

        self::assertFalse($registry->hasMappings());
    }

    /**
     * A frozen registry refuses every registration, an identical one included,
     * and still resolves; freezing again changes nothing.
     *
     * @return void
     */
    public function testRegistrationAfterFreezeIsRefused(): void
    {
        $registry = new MapperRegistry;

        $registry->map(PortalEvent::class, PortalMapper::class);

        self::assertFalse($registry->isFrozen());

        $registry->freeze();
        $registry->freeze();

        self::assertTrue($registry->isFrozen());
        self::assertSame(PortalMapper::class, $registry->mapperFor(SignedInToPortal::class));

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Event mappers are registered while the application boots, and it has already booted.');

        $registry->map(PortalEvent::class, PortalMapper::class);
    }

    /**
     * Resolution is cached per class, misses included, and a later registration
     * clears the cache.
     *
     * @SuppressWarnings("php:S3011")
     *
     * @return void
     */
    public function testResolutionIsCachedPerClass(): void
    {
        $registry = new MapperRegistry;
        $resolved = new \ReflectionProperty(MapperRegistry::class, 'resolved');

        $registry->map(PortalEvent::class, PortalMapper::class);

        $registry->mapperFor(SignedInToPortal::class);
        $registry->mapperFor(SignedInToPortal::class);
        $registry->mapperFor(PortalSignedIn::class);

        self::assertSame([SignedInToPortal::class => [PortalEvent::class], PortalSignedIn::class => []], $resolved->getValue($registry));

        $registry->map(PortalSignedIn::class, NullMapper::class);

        self::assertSame([], $resolved->getValue($registry));
        self::assertSame(NullMapper::class, $registry->mapperFor(PortalSignedIn::class));
    }

    /**
     * A registry has mappings once one is registered, and a refused
     * registration adds none.
     *
     * @return void
     */
    public function testHasMappings(): void
    {
        $registry = new MapperRegistry;

        self::assertFalse($registry->hasMappings());

        try {
            $registry->map(AuditLogEvent::class, PortalMapper::class);
        } catch (\LogicException) {
            // The refusal is what this test provokes
        }

        self::assertFalse($registry->hasMappings());

        $registry->map(PortalEvent::class, PortalMapper::class);

        self::assertTrue($registry->hasMappings());
    }

    /**
     * With nothing registered, every class is unmapped.
     *
     * @return void
     */
    public function testAnUnmappedClassIsNull(): void
    {
        $registry = new MapperRegistry;

        self::assertNull($registry->mapperFor(SignedInToPortal::class));

        $registry->map(PortalSignedIn::class, PortalMapper::class);

        self::assertNull($registry->mapperFor(SignedInToPortal::class));
    }
}
