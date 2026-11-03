<?php

declare(strict_types = 1);

namespace Tests\Feature\Capture;

use Illuminate\Auth\Access\Events\GateEvaluated;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Registered;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Capture\CaptureCoordinator;
use SineMacula\Laravel\AuditLog\Capture\CaptureFailedException;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Events\AuditCaptureFailed;
use SineMacula\Laravel\AuditLog\Events\AuditWriteFailed;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Listeners\RecordGateDenial;
use SineMacula\Laravel\AuditLog\Listeners\RecordLaravelAuthEvent;
use SineMacula\Laravel\AuditLog\Listeners\RecordModelChange;
use SineMacula\Laravel\AuditLog\Models\AuditEntry;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use Tests\Concerns\CapturesLogLines;
use Tests\Concerns\CreatesWatchedModels;
use Tests\Concerns\SearchesForSecrets;
use Tests\Fixtures\Capture\Events\ExcludedPortalEvent;
use Tests\Fixtures\Capture\Events\PortalEvent;
use Tests\Fixtures\Capture\Events\SignedInToPortal;
use Tests\Fixtures\Capture\Mappers\PortalMapper;
use Tests\Fixtures\Capture\Mappers\ThrowingMapper;
use Tests\Fixtures\Capture\Models\PlainLine;
use Tests\Fixtures\Capture\Models\SigningInUser;
use Tests\Fixtures\Capture\Models\WatchedInvoice;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Stores\CallbackStore;
use Tests\TestCase;

/**
 * Feature tests for how capture fails, through the provider's wiring and the
 * real dispatcher: a failed write of a mapped event, a core event, a Gate
 * denial and a watched change spilled, reported and said once each; the `throw`
 * failure mode never reaching the code that dispatched the event; a failing
 * `AuditCaptureFailed` listener and a failing reporter contained; no failure
 * holding a value of the event; and writing an entry never producing a record.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CaptureCoordinator::class)]
#[CoversClass(RecordLaravelAuthEvent::class)]
#[CoversClass(RecordGateDenial::class)]
#[CoversClass(RecordModelChange::class)]
final class CaptureFailuresTest extends TestCase
{
    use CapturesLogLines, CreatesWatchedModels, SearchesForSecrets;

    /** @var string The ability the Gate denies. */
    private const string ABILITY = 'approve-invoice';

    /** @var \Tests\Fixtures\Privacy\RecordingExceptionHandler What the application's reporter is asked to report. */
    private RecordingExceptionHandler $reporter;

    /** @var list<\SineMacula\Laravel\AuditLog\Events\AuditCaptureFailed> Every `AuditCaptureFailed` heard. */
    private array $failures = [];

    /** @var list<\SineMacula\Laravel\AuditLog\Events\AuditWriteFailed> Every `AuditWriteFailed` heard. */
    private array $writeFailures = [];

    /**
     * Create the users' table, bind the reporter, capture the log lines, turn
     * Gate capture on with an ability it denies, and hear each failure event.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createUsersTable();

        $this->reporter = new RecordingExceptionHandler;

        $this->app?->instance(ExceptionHandler::class, $this->reporter);

        $this->captureLogLines();

        app(ConfigRepository::class)->set('audit-log.capture.gate.enabled', true);

        Gate::define(self::ABILITY, static fn (): bool => false);

        Event::listen(AuditCaptureFailed::class, function (AuditCaptureFailed $failure): void {
            $this->failures[] = $failure;
        });

        Event::listen(AuditWriteFailed::class, function (AuditWriteFailed $failure): void {
            $this->writeFailures[] = $failure;
        });
    }

    /**
     * A failed write of each kind of capture is spilled once, reported once as
     * the write's failure, and said once as `AuditWriteFailed` and once as
     * `AuditCaptureFailed` naming the event, its source and the failure.
     *
     * @return void
     */
    public function testAWriteFailureIsSpilledReportedAndDispatchedOnce(): void
    {
        $user = self::newUser('alice@example.com');

        $this->failTheStore();

        Event::dispatch(new SignedInToPortal);
        Auth::guard('web')->login($user);
        Gate::forUser($user)->allows(self::ABILITY);
        WatchedInvoice::query()->create(['number' => 'INV-1']);

        self::assertCount(4, $this->spillLines());
        self::assertCount(4, $this->writeFailures);
        self::assertCount(4, $this->reporter->reports());

        foreach ($this->reporter->reports() as $report) {
            self::assertInstanceOf(AuditWriteFailedException::class, $report);
        }

        self::assertSame(
            [
                [SignedInToPortal::class, PortalMapper::class, \RuntimeException::class],
                [Login::class, RecordLaravelAuthEvent::class, \RuntimeException::class],
                [GateEvaluated::class, RecordGateDenial::class, \RuntimeException::class],
                [WatchedInvoice::class, RecordModelChange::class, \RuntimeException::class],
            ],
            array_map(self::classesOf(...), $this->failures),
        );
        self::assertSame(1, WatchedInvoice::query()->count());
    }

    /**
     * Under the `throw` failure mode a capture's failed write still never
     * reaches the code that dispatched the event: the sign-in signs the user
     * in, the Gate answers, the change is saved and the dispatch returns, each
     * failure said once.
     *
     * @return void
     */
    public function testTheThrowModeNeverReachesTheDispatchingFlow(): void
    {
        app(ConfigRepository::class)->set('audit-log.failure.mode', 'throw');

        $user = self::newUser('alice@example.com');

        $this->failTheStore();

        Event::dispatch(new SignedInToPortal);

        self::assertTrue(Auth::guard('web')->attempt(['email' => 'alice@example.com', 'password' => SigningInUser::PASSWORD]));
        self::assertSame($user->id, Auth::guard('web')->id());
        self::assertTrue(Gate::forUser($user)->denies(self::ABILITY));
        self::assertTrue(WatchedInvoice::query()->create(['number' => 'INV-1'])->exists);
        self::assertCount(4, $this->failures);
        self::assertCount(4, $this->spillLines());

        try {
            AuditLog::record('invoice.approved');

            self::fail('Expected the explicit record to throw under the throw mode.');
        } catch (AuditWriteFailedException) {
            // An explicit record still follows the mode
        }
    }

    /**
     * A listener of `AuditCaptureFailed` that throws is contained: the dispatch
     * returns, the listener's failure is reported by class names, and every
     * later event is still captured.
     *
     * @return void
     */
    public function testAThrowingCaptureFailedListenerIsContained(): void
    {
        Event::listen(AuditCaptureFailed::class, static function (): never {
            throw new \UnexpectedValueException('The alert failed.');
        });

        Event::dispatch(new ExcludedPortalEvent);
        Event::dispatch(new Registered(self::newUser('alice@example.com')));

        self::assertCount(1, $this->failures);
        self::assertSame(
            [\RuntimeException::class, \UnexpectedValueException::class],
            array_map(static fn (\Throwable $report): string => $report instanceof CaptureFailedException ? $report->exceptionClass : $report::class, $this->reporter->reports()),
        );
        self::assertSame(['account.registered'], $this->codes());
    }

    /**
     * A reporter that throws is contained: a mapper's failure and a failed
     * write are each still said once, the write's reporter failure being
     * reported in turn as the write path reports it, and the dispatch returns.
     *
     * @return void
     */
    public function testAThrowingReporterIsContained(): void
    {
        $reporter = new RecordingExceptionHandler(throwsOnReport: true);

        $this->app?->instance(ExceptionHandler::class, $reporter);

        Event::dispatch(new ExcludedPortalEvent);

        $this->failTheStore();

        Event::dispatch(new Registered(self::newUser('alice@example.com')));

        self::assertSame(
            [CaptureFailedException::class, AuditWriteFailedException::class, AuditWriteFailedException::class],
            array_map(static fn (\Throwable $report): string => $report::class, $reporter->reports()),
        );
        self::assertCount(2, $this->failures);
        self::assertCount(1, $this->spillLines());
    }

    /**
     * No failure holds a value of the event or of its record: neither the
     * reports, nor the failure events, nor the spilled records, whether a
     * mapper or a write failed, though the mapper's exception, the event, the
     * credentials and the failed write's own exception hold the secret.
     *
     * @return void
     */
    public function testNoCaptureFailureHoldsAPayload(): void
    {
        Event::dispatch(new ExcludedPortalEvent);

        $this->app?->instance(AuditStore::class, CallbackStore::failingWith(new \RuntimeException('The store refused ' . self::SECRET . '.')));

        Event::dispatch(new SignedInToPortal(secret: self::SECRET));
        Auth::guard('web')->attempt(['email' => 'alice@example.com', 'password' => self::SECRET]);

        self::assertCount(3, $this->failures);
        self::assertCount(2, $this->spillLines());
        self::assertCount(3, $this->reporter->reports());
        self::assertHoldsNoSecret(array_map(self::whatThePackageHolds(...), $this->reporter->reports()), 'the reports');
        self::assertHoldsNoSecret($this->failures, 'the capture failures');
        self::assertHoldsNoSecret($this->writeFailures, 'the write failures');
        self::assertHoldsNoSecret($this->spillLines(), 'the spill');
    }

    /**
     * Writing an entry never produces a record: a store that, while it writes,
     * dispatches a mapped event, signs a user in, asks the Gate and saves a
     * watched model writes the one entry it was given and says nothing; nor
     * does a listener of a failed write that does the same.
     *
     * @return void
     */
    public function testWritingAnEntryNeverProducesARecord(): void
    {
        $user     = self::newUser('alice@example.com');
        $database = app(DatabaseAuditStore::class);
        $capture  = static function () use ($user): void {
            Event::dispatch(new SignedInToPortal);
            Auth::guard('admin')->login($user);
            Gate::forUser($user)->allows(self::ABILITY);
            PlainLine::query()->create(['description' => 'written while writing']);
        };

        $this->app?->instance(AuditStore::class, new CallbackStore(static function (FinalisedRecord $record) use ($capture, $database): void {
            $capture();
            $database->store($record);
        }));

        AuditLog::record('invoice.approved');

        self::assertSame(['invoice.approved'], $this->codes());

        $this->failTheStore();

        Event::listen(AuditWriteFailed::class, $capture);

        AuditLog::record('invoice.approved');

        self::assertSame(['invoice.approved'], $this->codes());
        self::assertSame([], $this->failures);
        self::assertCount(1, $this->spillLines());
        self::assertSame(2, PlainLine::query()->count());
    }

    /**
     * Sign users in from the test's users' table without waiting, with a cheap
     * hash, add a second session guard, and, while the application boots, map
     * the portal events to a mapper that throws but for one class mapped to the
     * portal mapper, and watch two models.
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
        $config->set('auth.guards.admin', ['driver' => 'session', 'provider' => 'users']);
        $config->set('auth.timebox_duration', 0);
        $config->set('hashing.bcrypt.rounds', 4);

        app()->booting(static function (Application $app): void {
            AuditLog::map(PortalEvent::class, ThrowingMapper::class);
            AuditLog::map(SignedInToPortal::class, PortalMapper::class);
            AuditLog::watch(WatchedInvoice::class, as: 'invoice', fields: ['number']);
            AuditLog::watch(PlainLine::class, as: 'line', fields: ['description']);
        });
    }

    /**
     * Bind a store whose every write fails.
     *
     * @return void
     */
    private function failTheStore(): void
    {
        $this->app?->instance(AuditStore::class, CallbackStore::failingWith(new \RuntimeException('The store is down.')));
    }

    /**
     * The codes of the rows written, oldest first.
     *
     * @return list<string>
     */
    private function codes(): array
    {
        return array_values(array_map(static fn (AuditEntry $entry): string => $entry->event, AuditEntry::query()->orderBy('recorded_at')->orderBy('id')->get()->all()));
    }

    /**
     * What the package puts in a report: its message, its previous exception
     * and the arguments of the package's own frames of its trace. The frames
     * above them are the caller's (the dispatcher's and the guard's), which
     * hold the event they were given while arguments are kept in traces.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \Throwable  $report
     * @return array{0: string, 1: ?\Throwable, 2: list<array<array-key, mixed>>}
     */
    private static function whatThePackageHolds(\Throwable $report): array
    {
        $frames = array_filter($report->getTrace(), static fn (array $frame): bool => str_starts_with($frame['class'] ?? '', 'SineMacula\Laravel\AuditLog\\'));

        return [$report->getMessage(), $report->getPrevious(), array_values(array_map(static fn (array $frame): array => $frame['args'] ?? [], $frames))];
    }

    /**
     * The three class names a capture failure carries.
     *
     * @param  \SineMacula\Laravel\AuditLog\Events\AuditCaptureFailed  $failure
     * @return array{0: string, 1: ?string, 2: string}
     */
    private static function classesOf(AuditCaptureFailed $failure): array
    {
        return [$failure->eventClass, $failure->mapperClass, $failure->exceptionClass];
    }

    /**
     * Create the users' table on the test's connection, and drop it before the
     * application is destroyed.
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
