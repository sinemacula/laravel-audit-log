<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Auth\Events\Authenticated;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Schema;
use Orchestra\Testbench\Attributes\DefineEnvironment;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Capture\CaptureCoordinator;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Events\AuditCaptureFailed;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Listeners\CaptureMappedEvent;
use SineMacula\Laravel\AuditLog\Listeners\RecordGateDenial;
use SineMacula\Laravel\AuditLog\Listeners\RecordLaravelAuthEvent;
use SineMacula\Laravel\AuditLog\Listeners\RecordModelChange;
use Tests\Concerns\CreatesWatchedModels;
use Tests\Fixtures\Capture\Events\PortalEvent;
use Tests\Fixtures\Capture\Events\PortalSignedIn;
use Tests\Fixtures\Capture\Events\SignedInToPortal;
use Tests\Fixtures\Capture\Mappers\PortalMapper;
use Tests\Fixtures\Capture\Models\SigningInUser;
use Tests\Fixtures\Capture\Models\WatchedInvoice;

/**
 * Statement budget for capturing mapped events, Gate checks, sign-ins and
 * watched changes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CaptureCoordinator::class)]
#[CoversClass(CaptureMappedEvent::class)]
#[CoversClass(RecordLaravelAuthEvent::class)]
#[CoversClass(RecordGateDenial::class)]
#[CoversClass(RecordModelChange::class)]
final class CaptureQueryBudgetTest extends PerformanceContractTestCase
{
    use CreatesWatchedModels;

    /** @var string The ability the Gate allows. */
    private const string ALLOWED = 'view-invoice';

    /** @var string The ability the Gate denies. */
    private const string DENIED = 'approve-invoice';

    /** @var list<\SineMacula\Laravel\AuditLog\Events\AuditCaptureFailed> Every `AuditCaptureFailed` heard. */
    private array $failures = [];

    /** @var \Tests\Fixtures\Capture\Models\SigningInUser The user who signs in and whom the Gate is asked about. */
    private SigningInUser $user;

    /**
     * Create the users' table and a user, turn Gate capture on with one ability
     * allowed and one denied, and hear each capture failure.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createUsersTable();

        $this->user = self::newUser('alice@example.com');

        app(ConfigRepository::class)->set('audit-log.capture.gate.enabled', true);

        Gate::define(self::ALLOWED, static fn (): bool => true);
        Gate::define(self::DENIED, static fn (): bool => false);

        Event::listen(AuditCaptureFailed::class, function (AuditCaptureFailed $failure): void {
            $this->failures[] = $failure;
        });
    }

    /**
     * Roll back any transaction a test left open.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        while (DB::connection()->transactionLevel() > 0) {
            DB::connection()->rollBack();
        }

        parent::tearDown();
    }

    /**
     * An unmapped event the bridge hears costs no statement.
     *
     * @return void
     */
    #[DefineEnvironment('mapThePortalEvents')]
    public function testAnUnmappedEventCostsNoQuery(): void
    {
        $this->assertStatementBudget(0, 0, 0, 0, static function (): void {
            Event::dispatch(new PortalSignedIn);
            Event::dispatch(new \ArrayObject);
        });

        $this->assertWritten(0);
    }

    /**
     * A mapped event is one insert, with no read, savepoint or transaction.
     *
     * @return void
     */
    #[DefineEnvironment('mapThePortalEvents')]
    public function testAMappedEventIsOneInsert(): void
    {
        $dispatch = static function (): void {
            Event::dispatch(new SignedInToPortal);
        };

        $this->assertTransactionBudget(0, 0, fn () => $this->assertStatementBudget(0, 1, 0, 0, $dispatch));

        self::assertStringContainsString(EntrySettings::table(), $this->capturedWrites()[0]);
        $this->assertWritten(1);
    }

    /**
     * An allowed Gate check costs no statement and reads no setting.
     *
     * @return void
     */
    public function testAnAllowedGateCheckCostsNoQuery(): void
    {
        $this->assertStatementBudget(0, 0, 0, 0, fn (): bool => Gate::forUser($this->user)->allows(self::ALLOWED));

        $this->assertWritten(0);
    }

    /**
     * A denied Gate check is one insert.
     *
     * @return void
     */
    public function testADeniedGateCheckIsOneInsert(): void
    {
        $this->assertStatementBudget(0, 1, 0, 0, fn (): bool => Gate::forUser($this->user)->denies(self::DENIED));

        $this->assertWritten(1);
    }

    /**
     * A sign-in of a user already held is one insert; the session guard reads
     * nothing.
     *
     * @return void
     */
    public function testASignInIsOneInsert(): void
    {
        $this->assertStatementBudget(0, 1, 0, 0, function (): void {
            Auth::guard('web')->login($this->user);
        });

        $this->assertWritten(1);
    }

    /**
     * A watched change in a transaction is one insert at commit.
     *
     * @return void
     */
    public function testAWatchedChangeIsOneInsertAtCommit(): void
    {
        DB::connection()->beginTransaction();

        $this->assertStatementBudget(0, 1, 0, 0, static fn (): WatchedInvoice => WatchedInvoice::query()->create(['number' => 'INV-1', 'amount' => 1250]));

        self::assertStringContainsString(WatchedInvoice::TABLE, $this->capturedWrites()[0]);

        $this->assertStatementBudget($this->commitQuestionReads(), 1, 0, 0, static function (): void {
            DB::connection()->commit();
        });

        self::assertStringContainsString(EntrySettings::table(), $this->capturedWrites()[0]);
        $this->assertWritten(1);
    }

    /**
     * A rolled-back watched change writes nothing, at the rollback or after.
     *
     * @return void
     */
    public function testARolledBackWatchedChangeCostsNothing(): void
    {
        DB::connection()->beginTransaction();

        $this->assertStatementBudget(0, 1, 0, 0, static fn (): WatchedInvoice => WatchedInvoice::query()->create(['number' => 'INV-1', 'amount' => 1250]));

        $this->assertStatementBudget(0, 0, 0, 1, static function (): void {
            DB::connection()->rollBack();
        });

        $this->assertStatementBudget(0, 0, 0, 0, static function (): void {
            DB::connection()->transaction(static function (): void {});
        });

        $this->assertWritten(0);
    }

    /**
     * An app that maps nothing never registers the routing bridge.
     *
     * @return void
     */
    public function testAnAppThatMapsNothingRegistersNoWildcardListener(): void
    {
        $dispatcher = app(Dispatcher::class);

        self::assertFalse($dispatcher->hasWildcardListeners(SignedInToPortal::class));

        $this->assertStatementBudget(0, 0, 0, 0, static function (): void {
            Event::dispatch(new SignedInToPortal);
        });

        $this->assertWritten(0);
    }

    /**
     * A thousand `Authenticated` events cost nothing, though a mapping makes
     * the bridge hear each.
     *
     * @return void
     */
    #[DefineEnvironment('mapThePortalEvents')]
    public function testAThousandAuthenticatedEventsCostNothing(): void
    {
        $user = $this->user;

        self::assertTrue(app(Dispatcher::class)->hasWildcardListeners(Authenticated::class));

        $this->assertStatementBudget(0, 0, 0, 0, static function () use ($user): void {
            for ($event = 0; $event < 1000; $event++) {
                Event::dispatch(new Authenticated('api', $user));
            }
        });

        $this->assertWritten(0);
    }

    /**
     * Sign users in from the test's users' table with a cheap hash, and watch
     * the invoices at boot.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $config = app(ConfigRepository::class);

        $config->set('auth.providers.users.model', SigningInUser::class);
        $config->set('hashing.bcrypt.rounds', 4);

        app()->booting(static function (Application $app): void {
            AuditLog::watch(WatchedInvoice::class, as: 'invoice', fields: ['number', 'amount']);
        });
    }

    /**
     * Map the portal events at boot, which registers the routing bridge.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    protected function mapThePortalEvents(Application $app): void
    {
        $app->booting(static function (): void {
            AuditLog::map(PortalEvent::class, PortalMapper::class);
        });
    }

    /**
     * Assert the number of entries written, and that no capture failed.
     *
     * @param  int  $entries
     * @return void
     */
    private function assertWritten(int $entries): void
    {
        self::assertSame($entries, DB::connection()->table(EntrySettings::table())->count());
        self::assertSame([], $this->failures);
    }

    /**
     * Create the users' table, dropping it before the application is destroyed.
     *
     * @return void
     */
    private function createUsersTable(): void
    {
        $schema = Schema::connection(self::CONNECTION);

        $schema->dropIfExists(SigningInUser::TABLE);
        $schema->create(SigningInUser::TABLE, static function (Blueprint $table): void {
            $table->increments('id');
            $table->string('email', 191)->unique();
            $table->string('password', 191);
            $table->rememberToken();
        });

        $this->beforeApplicationDestroyed(static function (): void {
            Schema::connection(self::CONNECTION)->dropIfExists(SigningInUser::TABLE);
        });
    }

    /**
     * A saved user of the email address, with the password every user is made
     * with and the remember token given.
     *
     * @param  string  $email
     * @param  ?string  $rememberToken
     * @return \Tests\Fixtures\Capture\Models\SigningInUser
     */
    private static function newUser(string $email, #[\SensitiveParameter] ?string $rememberToken = null): SigningInUser
    {
        return SigningInUser::query()->create(['email' => $email, 'password' => SigningInUser::PASSWORD, 'remember_token' => $rememberToken]);
    }
}
