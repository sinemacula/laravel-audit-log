<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Container\Container;
use Illuminate\Foundation\Application;
use Illuminate\Support\ServiceProvider;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\AuditLogServiceProvider;
use SineMacula\Laravel\AuditLog\Contracts\AuditAccessPolicy;
use SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;
use SineMacula\Laravel\AuditLog\Contracts\HeldActorReader;
use SineMacula\Laravel\AuditLog\Contracts\PruneLedger;
use SineMacula\Laravel\AuditLog\Contracts\RetentionPolicy;
use SineMacula\Laravel\AuditLog\Lifecycle\ConfiguredRetentionPolicy;
use SineMacula\Laravel\AuditLog\Lifecycle\JournalPruneLedger;
use SineMacula\Laravel\AuditLog\Privacy\NoFieldEncrypter;
use SineMacula\Laravel\AuditLog\Privacy\SubjectKeyEncrypter;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Support\SystemClock;
use SineMacula\Laravel\AuditLog\Support\UuidV7;
use Tests\Fixtures\Support\FrozenClock;

/**
 * Feature tests for the package's bindings as defaults others can replace.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuditLogServiceProvider::class)]
final class ProviderBindingOrderTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * The rows hold a default of each kind the provider binds, the access
     * policy among them, and no held actor reader, an optional seam.
     *
     * @return void
     */
    public function testTheRowsHoldEachKindOfDefaultAndNoHeldActorReader(): void
    {
        $abstracts = array_keys(iterator_to_array(self::provideBoundAbstracts()));

        foreach ([AuditAccessPolicy::class, Clock::class, FieldEncrypter::class, CheckpointAnchor::class, Recorder::class, UuidV7::class] as $abstract) {
            self::assertContains($abstract, $abstracts);
        }

        self::assertNotContains(HeldActorReader::class, $abstracts);
    }

    /**
     * Rows of `[abstract]`: every abstract the package's provider binds, read
     * from the bindings it makes on a bare application.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideBoundAbstracts(): iterable
    {
        // A new application makes itself the global container; put back the one
        // the rest of the run uses
        $global = Container::getInstance();

        try {
            $container = self::container();
            $before    = array_keys($container->getBindings());

            (new AuditLogServiceProvider($container))->register();

            $abstracts = array_diff(array_keys($container->getBindings()), $before);
        } finally {
            Container::setInstance($global);
        }

        foreach ($abstracts as $abstract) {
            yield $abstract => [$abstract];
        }
    }

    /**
     * A binding made before the package's provider registers is kept.
     *
     * @param  string  $abstract
     * @return void
     */
    #[DataProvider('provideBoundAbstracts')]
    public function testABindingMadeBeforeThePackageRegistersIsKept(string $abstract): void
    {
        $container = self::container();
        $sibling   = new \stdClass;

        self::siblingBinding($container, $abstract, $sibling)->register();
        (new AuditLogServiceProvider($container))->register();

        self::assertSame($sibling, $container->make($abstract));
    }

    /**
     * A binding made after the provider registers replaces the default.
     *
     * @param  string  $abstract
     * @return void
     */
    #[DataProvider('provideBoundAbstracts')]
    public function testABindingMadeAfterThePackageRegistersReplacesTheDefault(string $abstract): void
    {
        $container = self::container();
        $sibling   = new \stdClass;

        (new AuditLogServiceProvider($container))->register();
        self::siblingBinding($container, $abstract, $sibling)->register();

        self::assertSame($sibling, $container->make($abstract));
    }

    /**
     * A clock bound after the default has resolved still replaces it.
     *
     * @return void
     */
    public function testALaterBindingReplacesADefaultThatHasResolved(): void
    {
        $app = $this->app;

        assert($app !== null);

        self::assertInstanceOf(SystemClock::class, $app->make(Clock::class));

        $app->singleton(Clock::class, static fn (): FrozenClock => FrozenClock::at('2026-11-01 12:00:00'));

        self::assertInstanceOf(FrozenClock::class, $app->make(Clock::class));
    }

    /**
     * The policy and ledger are shared defaults that yield to earlier ones.
     *
     * @return void
     */
    public function testAPolicyAndALedgerBoundEarlierAreKept(): void
    {
        $app = $this->app;

        assert($app !== null);

        self::assertInstanceOf(ConfiguredRetentionPolicy::class, $app->make(RetentionPolicy::class));
        self::assertInstanceOf(JournalPruneLedger::class, $app->make(PruneLedger::class));
        self::assertSame($app->make(RetentionPolicy::class), $app->make(RetentionPolicy::class));
        self::assertSame($app->make(PruneLedger::class), $app->make(PruneLedger::class));

        $policy    = \Mockery::mock(RetentionPolicy::class);
        $ledger    = \Mockery::mock(PruneLedger::class);
        $container = self::container();

        self::siblingBinding($container, RetentionPolicy::class, $policy)->register();
        self::siblingBinding($container, PruneLedger::class, $ledger)->register();
        (new AuditLogServiceProvider($container))->register();

        self::assertSame($policy, $container->make(RetentionPolicy::class));
        self::assertSame($ledger, $container->make(PruneLedger::class));
    }

    /**
     * The encrypter is an unshared default that yields to one bound earlier.
     *
     * @return void
     */
    public function testAnEncrypterBoundEarlierIsKeptEvenUnshared(): void
    {
        $app = $this->app;

        assert($app !== null);

        self::assertInstanceOf(SubjectKeyEncrypter::class, $app->make(FieldEncrypter::class));
        self::assertNotSame($app->make(FieldEncrypter::class), $app->make(FieldEncrypter::class));

        $container = self::container();

        $container->bind(FieldEncrypter::class, NoFieldEncrypter::class);
        (new AuditLogServiceProvider($container))->register();

        self::assertInstanceOf(NoFieldEncrypter::class, $container->make(FieldEncrypter::class));
    }

    /**
     * Register the package service provider against the Testbench application.
     *
     * @param  mixed  $app
     * @return array<int, class-string<\Illuminate\Support\ServiceProvider>>
     */
    #[\Override]
    protected function getPackageProviders(mixed $app): array
    {
        return [AuditLogServiceProvider::class];
    }

    /**
     * An application with only its base bindings and a config repository.
     *
     * @return \Illuminate\Foundation\Application
     */
    private static function container(): Application
    {
        $container = new Application;
        $container->instance('config', new ConfigRepository);

        return $container;
    }

    /**
     * Another package's provider, binding the abstract to the object.
     *
     * @param  \Illuminate\Foundation\Application  $container
     * @param  string  $abstract
     * @param  object  $object
     * @return \Illuminate\Support\ServiceProvider
     */
    private static function siblingBinding(Application $container, string $abstract, object $object): ServiceProvider
    {
        return new class ($container, $abstract, $object) extends ServiceProvider {
            /**
             * Constructor.
             *
             * @param  \Illuminate\Foundation\Application  $app
             * @param  string  $abstract
             * @param  object  $object
             */
            public function __construct(

                // Handed to the parent constructor.
                Application $app,

                /** Abstract the provider binds. */
                private readonly string $abstract,

                /** Object the abstract resolves to. */
                private readonly object $object,
            ) {
                parent::__construct($app);
            }

            /**
             * Bind the abstract to the object.
             *
             * @return void
             */
            #[\Override]
            public function register(): void
            {
                $object = $this->object;

                $this->app->singleton($this->abstract, static fn (): object => $object);
            }
        };
    }
}
