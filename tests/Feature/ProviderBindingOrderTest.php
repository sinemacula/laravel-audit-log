<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\ServiceProvider;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\AuditLogServiceProvider;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;
use SineMacula\Laravel\AuditLog\Contracts\FieldReader;
use SineMacula\Laravel\AuditLog\Contracts\KeyWrapper;
use SineMacula\Laravel\AuditLog\Contracts\PruneLedger;
use SineMacula\Laravel\AuditLog\Contracts\RetentionPolicy;
use SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Integrity\IntegritySettings;
use SineMacula\Laravel\AuditLog\Integrity\KeyRing;
use SineMacula\Laravel\AuditLog\Lifecycle\ConfiguredRetentionPolicy;
use SineMacula\Laravel\AuditLog\Lifecycle\JournalPruneLedger;
use SineMacula\Laravel\AuditLog\Privacy\NoFieldEncrypter;
use SineMacula\Laravel\AuditLog\Privacy\SubjectKeyEncrypter;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Runtime\ExecutionFrames;
use SineMacula\Laravel\AuditLog\Runtime\ReportLatch;
use SineMacula\Laravel\AuditLog\Runtime\RequestIdentity;
use SineMacula\Laravel\AuditLog\Runtime\WriteGuard;
use SineMacula\Laravel\AuditLog\Support\SystemClock;
use Tests\Fixtures\Support\FrozenClock;

/**
 * Feature tests for the order the package's service provider and another
 * package's provider register in: every binding the package makes is a default,
 * kept out of the way of one made before it and replaced by one made after, on
 * an application that holds only its base bindings and the two providers'.
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
     * Rows of `[abstract]`: every abstract the package's provider binds.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideBoundAbstracts(): iterable
    {
        $abstracts = [
            Clock::class,
            AuditStore::class,
            FieldEncrypter::class,
            FieldReader::class,
            KeyWrapper::class,
            RetentionPolicy::class,
            PruneLedger::class,
            CheckpointAnchor::class,
            KeyRing::class,
            IntegritySettings::class,
            Recorder::class,
            EventCatalogue::class,
            ContributorRegistry::class,
            ExecutionFrames::class,
            RequestIdentity::class,
            ReportLatch::class,
            WriteGuard::class,
        ];

        foreach ($abstracts as $abstract) {
            yield $abstract => [$abstract];
        }
    }

    /**
     * A binding another package made before the package's provider registers is
     * kept: the package's default does not replace it.
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
     * A binding another package makes after the package's provider registers
     * replaces the default, as any later binding does.
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
     * A clock bound with `singleton()` after the default has resolved still
     * replaces it, as the container drops the resolved instance.
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
     * With nothing bound before it, the package's provider binds the configured
     * retention policy and the journal's prune ledger, each once per
     * application; an application's own policy and ledger, bound before it, are
     * what the container resolves instead.
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
     * With nothing bound before it, the package's provider binds its own field
     * encrypter, made afresh on every resolution; an application that chooses
     * never to encrypt binds `NoFieldEncrypter` before it, and that is what the
     * container resolves instead, as a plain binding too.
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
     * An application holding nothing but its base bindings and a configuration
     * repository, which the package's provider merges its configuration into.
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

                // Application the provider binds into.
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
