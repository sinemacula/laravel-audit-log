<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\AuditLogServiceProvider;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Delivery\RecordDelivery;
use SineMacula\Laravel\AuditLog\Integrity\KeyRing;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Records\RecordFinaliser;
use SineMacula\Laravel\AuditLog\Runtime\ExecutionFrames;
use SineMacula\Laravel\AuditLog\Runtime\RequestIdentity;
use Tests\TestCase;

/**
 * Performance contract for booting the package: registering it adds no query to
 * a request that records nothing, and resolving the store, what finalises a
 * record, or the recorder and what it works with issues none and opens no
 * connection.
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
     * A request through a booted application with the package registered issues
     * no queries.
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
     * Resolving the store, the clock, the key ring and the finaliser issues no
     * statement and opens no connection: the store resolves the storage
     * connection only when it stores a record.
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
     * Resolving the recorder and everything a capture resolves issues no
     * statement and opens no connection, so a request that records nothing pays
     * for none of it.
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
}
