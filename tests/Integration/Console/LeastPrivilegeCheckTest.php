<?php

declare(strict_types = 1);

namespace Tests\Integration\Console;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Connection;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Console\CheckCommand;
use SineMacula\Laravel\AuditLog\Console\LifecycleChecks;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Lifecycle\Authority;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldScope;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\RunsDocumentedSql;
use Tests\TestCase;

/**
 * Integration tests for `audit-log:check` run as the writer under the
 * documented grants, on MySQL and PostgreSQL; SQLite has no privileges.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CheckCommand::class)]
#[CoversClass(LifecycleChecks::class)]
final class LeastPrivilegeCheckTest extends TestCase
{
    use RunsDocumentedSql;

    /** @var string The connection the writer's login uses, which is the storage connection. */
    private const string WRITER = 'audit_writer';

    /** @var string The connection the maintenance user's login uses, which is the maintenance connection. */
    private const string MAINTENANCE = 'audit_maintenance';

    /** @var list<string> The placeholders this test creates a login for. */
    private const array LOGINS = ['audit_writer', 'audit_maintenance', 'audit_verifier'];

    /** @var array<string, string> The names this worker gives the placeholders, once its logins exist. */
    private array $names = [];

    /**
     * Create this worker's logins, grant them as documented, and record an
     * entry and place a hold through them.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $root = $this->root();

        if ($root->getDriverName() === 'sqlite') {
            self::markTestSkipped('SQLite has no logins or privileges.');
        }

        $this->names = self::documentedNames($root);

        foreach (self::LOGINS as $placeholder) {
            self::createLogin($root, $this->names[$placeholder]);
        }

        self::runDocumentedGrants($root, $this->names);
        self::connectAs(self::WRITER, self::CONNECTION, $this->names[self::WRITER]);
        self::connectAs(self::MAINTENANCE, self::CONNECTION, $this->names[self::MAINTENANCE]);

        app(ConfigRepository::class)->set([
            'audit-log.storage.connection'             => self::WRITER,
            'audit-log.storage.maintenance_connection' => self::MAINTENANCE,
        ]);

        AuditLog::event('invoice.approved')->immediately()->record();

        $hold = AuditLog::lifecycle()->hold(HoldScope::all(), new Authority(Reference::of('App\Models\User', '7'), 'case.review', 'app:ticket-123'), HoldBasis::LEGAL_CLAIM);

        self::assertTrue($hold->recorded);
    }

    /**
     * Close the logins' connections and drop the logins.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        if ($this->names !== []) {

            foreach ([self::WRITER, self::MAINTENANCE] as $connection) {
                DB::purge($connection);
            }

            foreach (self::LOGINS as $placeholder) {
                self::dropLogin($this->root(), $this->names[$placeholder]);
            }
        }

        parent::tearDown();
    }

    /**
     * Every subject passes for the documented writer and maintenance user.
     *
     * @return void
     */
    public function testTheCheckPassesUnderTheDocumentedGrants(): void
    {
        $exit   = Artisan::call('audit-log:check');
        $output = Artisan::output();

        self::assertSame(0, $exit, $output);
        self::assertStringContainsString('[lifecycle] OK', $output);
    }

    /**
     * Every freshness signal is judged, and none fails, for the documented
     * writer.
     *
     * @return void
     */
    public function testTheFreshnessCheckPassesUnderTheDocumentedGrants(): void
    {
        $exit   = Artisan::call('audit-log:check', ['--freshness' => true]);
        $output = Artisan::output();

        self::assertSame(0, $exit, $output);
        self::assertSame(6, substr_count($output, '[freshness] '));
    }

    /**
     * The worker's own connection, as the tables' owner.
     *
     * @return \Illuminate\Database\Connection
     */
    private function root(): Connection
    {
        return DB::connection(self::CONNECTION);
    }
}
