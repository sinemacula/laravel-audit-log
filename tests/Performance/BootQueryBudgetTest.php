<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\AuditLogServiceProvider;
use SineMacula\Laravel\AuditLog\Capture\CaptureCoordinator;
use SineMacula\Laravel\AuditLog\Capture\CapturedEvents;
use SineMacula\Laravel\AuditLog\Capture\CaptureSettings;
use SineMacula\Laravel\AuditLog\Capture\Enums\CapturedActivity;
use SineMacula\Laravel\AuditLog\Capture\MapperRegistry;
use SineMacula\Laravel\AuditLog\Capture\ModelWatcher;
use SineMacula\Laravel\AuditLog\Contracts\AuditAccessPolicy;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;
use SineMacula\Laravel\AuditLog\Contracts\FieldReader;
use SineMacula\Laravel\AuditLog\Contracts\KeyWrapper;
use SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Delivery\RecordDelivery;
use SineMacula\Laravel\AuditLog\Integrity\KeyRing;
use SineMacula\Laravel\AuditLog\Keys\KeyCreator;
use SineMacula\Laravel\AuditLog\Keys\KeyStore;
use SineMacula\Laravel\AuditLog\Lifecycle\AuditLifecycle;
use SineMacula\Laravel\AuditLog\Querying\AuditTrail;
use SineMacula\Laravel\AuditLog\Querying\Describer;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\RecordPipeline;
use SineMacula\Laravel\AuditLog\Records\EventCode;
use SineMacula\Laravel\AuditLog\Records\RecordFinaliser;
use SineMacula\Laravel\AuditLog\Runtime\ExecutionFrames;
use SineMacula\Laravel\AuditLog\Runtime\RequestIdentity;
use Tests\Fixtures\Capture\Events\PortalSignedIn;
use Tests\Fixtures\Capture\Mappers\PortalMapper;
use Tests\Fixtures\Capture\Models\PlainLine;
use Tests\TestCase;

/**
 * Query budget for booting the package: registering, booting and resolving its
 * services issues no query and opens no connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuditLogServiceProvider::class)]
final class BootQueryBudgetTest extends TestCase
{
    /**
     * A request that records nothing issues no queries.
     *
     * @return void
     */
    public function testARequestThatRecordsNothingIssuesNoQueries(): void
    {
        Route::get('/ping', static fn (): string => 'pong');

        DB::enableQueryLog();

        $this->get('/ping')->assertOk()->assertSee('pong');

        self::assertSame([], DB::getQueryLog());
    }

    /**
     * Resolving the store and its collaborators opens no connection: the store
     * connects only when it stores a record.
     *
     * @return void
     */
    public function testResolvingTheStoreAndItsCollaboratorsIssuesNoQueries(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('database.connections.audit_unopened', $config->array('database.connections.' . self::CONNECTION));
        $config->set('audit-log.storage.connection', 'audit_unopened');

        DB::enableQueryLog();

        foreach ([AuditStore::class, Clock::class, KeyRing::class, RecordFinaliser::class] as $abstract) {
            self::assertIsObject(app($abstract));
        }

        self::assertSame([], DB::getQueryLog());
        self::assertArrayNotHasKey('audit_unopened', DB::getConnections());
    }

    /**
     * Resolving the recorder and its collaborators issues no statement and
     * opens no connection.
     *
     * @return void
     */
    public function testResolvingTheRecorderAndItsCollaboratorsIssuesNoQueries(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('database.connections.audit_unopened', $config->array('database.connections.' . self::CONNECTION));
        $config->set('audit-log.storage.connection', 'audit_unopened');

        DB::enableQueryLog();

        foreach ([Recorder::class, EventCatalogue::class, ContributorRegistry::class, ExecutionFrames::class, RequestIdentity::class, RecordDelivery::class] as $abstract) {
            self::assertIsObject(app($abstract));
        }

        self::assertSame([], DB::getQueryLog());
        self::assertArrayNotHasKey('audit_unopened', DB::getConnections());
    }

    /**
     * Booting with an event mapped and a model watched issues no statement and
     * opens no connection.
     *
     * @return void
     */
    public function testBootingWithCaptureWiredCostsNoQuery(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('database.connections.audit_unopened', $config->array('database.connections.' . self::CONNECTION));
        $config->set('audit-log.storage.connection', 'audit_unopened');

        $catalogue = new EventCatalogue;
        $mappers   = new MapperRegistry;
        $watcher   = new ModelWatcher($catalogue, app(Dispatcher::class));
        $queries   = [];

        $this->app?->instance(EventCatalogue::class, $catalogue);
        $this->app?->instance(ContributorRegistry::class, new ContributorRegistry);
        $this->app?->instance(MapperRegistry::class, $mappers);
        $this->app?->instance(ModelWatcher::class, $watcher);
        $this->app?->forgetInstance(Recorder::class);

        Event::listen(QueryExecuted::class, static function (QueryExecuted $query) use (&$queries): void {
            $queries[] = $query->sql;
        });

        $recorder = app(Recorder::class);

        $recorder->map(PortalSignedIn::class, PortalMapper::class);
        $recorder->watch(PlainLine::class, as: 'line', fields: ['description']);

        self::assertNotNull($this->app);

        (new AuditLogServiceProvider($this->app))->boot();

        foreach ([CaptureCoordinator::class, CapturedEvents::class, CaptureSettings::class, RecordPipeline::class] as $abstract) {
            self::assertIsObject(app($abstract));
        }

        self::assertSame([], $queries);
        self::assertArrayNotHasKey('audit_unopened', DB::getConnections());
        self::assertTrue($catalogue->isRegistered(EventCode::of(CapturedActivity::SIGNED_IN)));
        self::assertTrue($mappers->isFrozen());
        self::assertTrue($watcher->isFrozen());
    }

    /**
     * Resolving the read path opens no connection: a trail reads only on a
     * terminal call.
     *
     * @return void
     */
    public function testResolvingTheReadPathIssuesNoQueries(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('database.connections.audit_unopened', $config->array('database.connections.' . self::CONNECTION));
        $config->set('audit-log.storage.connection', 'audit_unopened');

        DB::enableQueryLog();

        foreach ([AuditTrail::class, Describer::class, AuditAccessPolicy::class, FieldReader::class] as $abstract) {
            self::assertIsObject(app($abstract));
        }

        self::assertIsObject(app(Recorder::class)->trail());
        self::assertSame([], DB::getQueryLog());
        self::assertArrayNotHasKey('audit_unopened', DB::getConnections());
    }

    /**
     * Resolving the key path, or naming the current wrapping key, opens no
     * connection: a key is looked up only when a value is sealed.
     *
     * @return void
     */
    public function testResolvingTheKeyPathIssuesNoQueries(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('database.connections.audit_unopened', $config->array('database.connections.' . self::CONNECTION));
        $config->set('audit-log.storage.connection', 'audit_unopened');

        DB::enableQueryLog();

        foreach ([FieldEncrypter::class, KeyWrapper::class, KeyStore::class, KeyCreator::class, AuditLifecycle::class] as $abstract) {
            self::assertIsObject(app($abstract));
        }

        self::assertStringStartsWith('d-', app(KeyWrapper::class)->currentKeyId());
        self::assertSame([], DB::getQueryLog());
        self::assertArrayNotHasKey('audit_unopened', DB::getConnections());
    }
}
