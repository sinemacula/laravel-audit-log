<?php

declare(strict_types = 1);

namespace Tests\Feature\Delivery;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Encryption\StringEncrypter;
use Illuminate\Database\DeadlockException;
use Illuminate\Database\QueryException;
use Illuminate\Log\Events\MessageLogged;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Monolog\Handler\NullHandler;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Database\DeliveryTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Delivery\DeliveryCoordinator;
use SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode;
use SineMacula\Laravel\AuditLog\Delivery\Enums\FailureRule;
use SineMacula\Laravel\AuditLog\Delivery\Replayer;
use SineMacula\Laravel\AuditLog\Events\AuditWriteFailed;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Privacy\FieldPolicy;
use SineMacula\Laravel\AuditLog\Privacy\Redactor;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Records\RecordFinaliser;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException;
use SineMacula\Laravel\AuditLog\Stores\FailureSpill;
use SineMacula\Laravel\AuditLog\Stores\LogAuditStore;
use SineMacula\Laravel\AuditLog\Stores\StackAuditStore;
use SineMacula\Laravel\AuditLog\Stores\StackDeliveryException;
use Symfony\Component\HttpFoundation\Response;
use Tests\Concerns\CapturesLogLines;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Concerns\InteractsWithOutbox;
use Tests\Concerns\SearchesForSecrets;
use Tests\Concerns\SeedsTheOutbox;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Records\RecordFactory;
use Tests\Fixtures\Stores\CallbackStore;
use Tests\Fixtures\Stores\ThrowingLogHandler;
use Tests\TestCase;

/**
 * Searches everywhere a failed write can leave a planted secret; frames keep
 * their arguments, so no helper may take the secret or a payload.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class NoPayloadInFailuresTest extends TestCase
{
    use CapturesLogLines, InteractsWithAuditStore, InteractsWithOutbox, SearchesForSecrets, SeedsTheOutbox;

    /** @var string The code every test records. */
    private const string CODE = 'invoice.approved';

    /** @var string The setting that turns a frame's arguments off. */
    private const string IGNORE_ARGS = 'zend.exception_ignore_args';

    /** @var string The spill channel, which writes nowhere; the lines are captured as they are logged. */
    private const string SPILL_CHANNEL = 'audit-spill';

    /** @var string The channel a test breaks the spill with. */
    private const string BROKEN_CHANNEL = 'audit-broken';

    /** @var string What a failure Laravel reads as neither a concurrency error nor a lost connection says. */
    private const string DUPLICATE = 'SQLSTATE[23000]: Integrity constraint violation: 1062 Duplicate entry';

    /** @var string A failure Laravel reads as a concurrency error. */
    private const string DEADLOCK = 'SQLSTATE[40001]: Serialization failure: 1213 Deadlock found when trying to get lock';

    /** @var string A failure Laravel reads as a lost connection. */
    private const string LOST = 'SQLSTATE[HY000]: General error: 2006 MySQL server has gone away';

    /** @var string The statement every forced failure quotes. */
    private const string FAILED_SQL = 'insert into "audit_quoted_rows" ("row") values (?)';

    /** @var string Where a report's message starts. */
    private const string SANITISED_MESSAGE = '/\AAudit record [0-9a-f-]{36} \(invoice\.approved\) was not written: [a-z]+ failed on /';

    /** @var \Tests\Fixtures\Privacy\RecordingExceptionHandler What the application's reporter is asked to report. */
    private RecordingExceptionHandler $reporter;

    /** @var \Illuminate\Contracts\Debug\ExceptionHandler The framework's own handler, which writes what it reports to the log. */
    private ExceptionHandler $framework;

    /** @var ?\Throwable What escaped the last write. */
    private ?\Throwable $thrown = null;

    /** @var list<\SineMacula\Laravel\AuditLog\Events\AuditWriteFailed> The failed writes said, in order. */
    private array $events = [];

    /** @var list<string> The long strings the failing insert was bound to. */
    private array $boundStrings = [];

    /** @var bool Whether a listener of a failed write throws the secret, once it has kept the event. */
    private bool $listenerThrows = false;

    /** @var list<string> The files the test wrote. */
    private array $files = [];

    /** @var string The setting as it was before the test. */
    private string $ignoreArgs = '';

    /**
     * Keep every frame's arguments, keep what is reported, logged and said.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->ignoreArgs = (string) ini_get(self::IGNORE_ARGS);

        ini_set(self::IGNORE_ARGS, '0');

        $this->framework = app(ExceptionHandler::class);
        $this->reporter  = new RecordingExceptionHandler;

        $this->app?->instance(ExceptionHandler::class, $this->reporter);

        $this->captureLogLines();

        Event::listen(AuditWriteFailed::class, function (AuditWriteFailed $event): void {
            $this->events[] = $event;

            if ($this->listenerThrows) {
                throw new \RuntimeException('The listener failed: ' . self::SECRET);
            }
        });
    }

    /**
     * Roll back what a test left open, remove what it wrote, and put the
     * setting and the clock back.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->endTheTransaction();

        foreach ($this->files as $file) {
            if (!is_file($file)) {
                continue;
            }

            unlink($file);
        }

        $this->removeProbeTable();
        $this->removeOutboxProbeTable();

        CarbonImmutable::setTestNow();

        ini_set(self::IGNORE_ARGS, $this->ignoreArgs);

        parent::tearDown();
    }

    /**
     * Rows of `[delivery mode]`.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode}>
     */
    public static function provideModes(): iterable
    {
        foreach (DeliveryMode::cases() as $mode) {
            yield $mode->value => [$mode];
        }
    }

    /**
     * The search has something to find: the record, the failure's message, SQL
     * and bindings, and the spill all hold the secret.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode  $mode
     * @return void
     */
    #[DataProvider('provideModes')]
    public function testThePlantedSecretIsThereToFind(DeliveryMode $mode): void
    {
        $this->writeFailing(FailureRule::REPORT, $mode);

        $envelope = self::envelopeOf($this->spillLines()[0] ?? '');

        self::assertSame(self::SECRET, $envelope['properties']['detail'] ?? null);
        self::assertSame(self::SECRET, $envelope['context']['detail'] ?? null);
        self::assertTrue(self::holdsText(self::quoting(self::DUPLICATE, '23000', 1062, 'the row')->getMessage(), self::SECRET));
        self::assertTrue(self::holdsText(self::quoting(self::DUPLICATE, '23000', 1062, 'the row')->getBindings(), self::SECRET));
        self::assertTrue(self::holdsText(self::quoting(self::DUPLICATE, '23000', 1062, 'the row')->getPrevious(), self::SECRET));
    }

    /**
     * Each frame keeps its arguments, so a search of them can find something.
     *
     * @return void
     */
    public function testTheFramesAreThereToSearch(): void
    {
        $thrown = static fn (string $held): \RuntimeException => new \RuntimeException($held);

        self::assertSame('0', ini_get(self::IGNORE_ARGS));
        self::assertSame(['held'], $thrown('held')->getTrace()[0]['args'] ?? null);
    }

    /**
     * Rows of `[failure rule, delivery mode]`: each rule in either mode.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Delivery\Enums\FailureRule, 1: \SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode}>
     */
    public static function provideRulesAndModes(): iterable
    {
        foreach (FailureRule::cases() as $rule) {
            foreach (DeliveryMode::cases() as $mode) {
                yield "{$rule->value}, {$mode->value}" => [$rule, $mode];
            }
        }
    }

    /**
     * Nothing reported holds the secret, and every failure is reported once,
     * only as the sanitised exception.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\FailureRule  $rule
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode  $mode
     * @return void
     */
    #[DataProvider('provideRulesAndModes')]
    public function testAPlantedSecretIsInNoReport(FailureRule $rule, DeliveryMode $mode): void
    {
        $this->writeFailing($rule, $mode);

        self::assertCount($rule === FailureRule::REPORT ? 1 : 0, $this->reporter->reports());
        self::assertHoldsNoSecret($this->reporter->reports(), 'a report');

        $exceptions = $this->exceptions();

        foreach ($exceptions as $exception) {
            self::assertInstanceOf(AuditWriteFailedException::class, $exception);
            self::assertMatchesRegularExpression(self::SANITISED_MESSAGE, $exception->getMessage());

            $this->framework->report($exception);
        }

        self::assertCount(count($exceptions), $this->loggedReports());
        self::assertHoldsNoSecret($this->loggedReports(), 'a logged report');
    }

    /**
     * The event holds its four fixed facts and no secret.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\FailureRule  $rule
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode  $mode
     * @return void
     */
    #[DataProvider('provideRulesAndModes')]
    public function testAPlantedSecretIsInNoEvent(FailureRule $rule, DeliveryMode $mode): void
    {
        $this->writeFailing($rule, $mode);

        self::assertCount(1, $this->events);
        self::assertSame(['id', 'code', 'store', 'exception'], array_keys(get_object_vars($this->events[0])));
        self::assertSame(QueryException::class, $this->events[0]->exception);
        self::assertHoldsNoSecret($this->events, 'an event');
    }

    /**
     * What escapes is the sanitised exception, under a rule that throws; under
     * one that reports nothing escapes.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\FailureRule  $rule
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode  $mode
     * @return void
     */
    #[DataProvider('provideRulesAndModes')]
    public function testAPlantedSecretIsInNoEscapedException(FailureRule $rule, DeliveryMode $mode): void
    {
        $this->writeFailing($rule, $mode);

        if ($rule === FailureRule::REPORT) {
            self::assertNull($this->thrown);

            return;
        }

        self::assertInstanceOf(AuditWriteFailedException::class, $this->thrown);
        self::assertSame(QueryException::class, $this->thrown->exceptionClass);
        self::assertHoldsNoSecret($this->thrown, 'the thrown exception');
        self::assertHoldsNoSecret(get_object_vars($this->thrown), 'the thrown exception\'s fields');
    }

    /**
     * Nothing chains the failure: every exception has no previous one, so there
     * is no chain to search.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\FailureRule  $rule
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode  $mode
     * @return void
     */
    #[DataProvider('provideRulesAndModes')]
    public function testAPlantedSecretIsInNoExceptionChain(FailureRule $rule, DeliveryMode $mode): void
    {
        $this->writeFailing($rule, $mode);

        $exceptions = $this->exceptions();

        self::assertCount(1, $exceptions);

        foreach ($exceptions as $exception) {
            self::assertNull($exception->getPrevious());
        }
    }

    /**
     * No argument of any frame, objects included, holds the secret; the frames
     * that took the payload hold PHP's stand-in.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\FailureRule  $rule
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode  $mode
     * @return void
     */
    #[DataProvider('provideRulesAndModes')]
    public function testAPlantedSecretIsInNoExceptionTrace(FailureRule $rule, DeliveryMode $mode): void
    {
        $this->writeFailing($rule, $mode);

        foreach ($this->exceptions() as $exception) {
            $this->assertTheFramesHoldNoSecret($exception);
        }
    }

    /**
     * The string traces `failed_jobs` stores hold no secret and do show the
     * stand-in, so a frame's argument was written there.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\FailureRule  $rule
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode  $mode
     * @return void
     */
    #[DataProvider('provideRulesAndModes')]
    public function testAPlantedSecretIsInNoTraceString(FailureRule $rule, DeliveryMode $mode): void
    {
        $this->writeFailing($rule, $mode);

        foreach ($this->exceptions() as $exception) {
            self::assertStringContainsString('Object(SensitiveParameterValue)', $exception->getTraceAsString());
            self::assertHoldsNoSecret($exception->getTraceAsString(), 'the trace as a string');
            self::assertHoldsNoSecret((string) $exception, 'the exception as a string');
        }
    }

    /**
     * A real failed insert holds the whole row in its bindings, and nothing of
     * it reaches a report beyond the record's id and code.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\FailureRule  $rule
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode  $mode
     * @return void
     */
    #[DataProvider('provideRulesAndModes')]
    public function testAStoredRowsBindingsAreInNoReport(FailureRule $rule, DeliveryMode $mode): void
    {
        $this->breakTheTableAndKeepTheBindings($mode);

        $this->record($rule, $mode);

        $exceptions = $this->exceptions();

        self::assertNotSame([], $this->boundStrings);
        self::assertCount(1, $exceptions);

        $sanitised = $exceptions[0];

        self::assertInstanceOf(AuditWriteFailedException::class, $sanitised);

        foreach ($this->boundStrings as $value) {
            if ($value === $sanitised->recordId || $value === self::CODE) {
                continue;
            }

            self::assertFalse(self::holdsText($exceptions, $value), 'A binding was found in a report.');
        }

        foreach (['insert into', self::PROBE_TABLE, self::OUTBOX_PROBE_TABLE, 'constraint'] as $text) {
            self::assertFalse(self::holdsText($exceptions, $text), "The report holds [{$text}].");
        }
    }

    /**
     * The driver's own message is not read: it is in no report and no escaped
     * exception, while the SQLSTATE, the numeric code and the alias are kept.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\FailureRule  $rule
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode  $mode
     * @return void
     */
    #[DataProvider('provideRulesAndModes')]
    public function testADriverMessageIsInNoReport(FailureRule $rule, DeliveryMode $mode): void
    {
        $this->writeFailing($rule, $mode);

        $exceptions = $this->exceptions();

        self::assertCount(1, $exceptions);

        $sanitised = $exceptions[0];

        self::assertInstanceOf(AuditWriteFailedException::class, $sanitised);
        self::assertSame('23000', $sanitised->sqlState);
        self::assertSame(1062, $sanitised->driverCode);
        self::assertSame(self::CONNECTION, $sanitised->connection);

        foreach (['Integrity constraint violation', 'Duplicate entry', 'audit_quoted_rows', 'the row'] as $text) {
            self::assertFalse(self::holdsText($exceptions, $text), "The report holds [{$text}].");
        }
    }

    /**
     * Rows of `[what the failing store is found through]`.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideAnonymousStores(): iterable
    {
        yield from [
            'as the store'           => ['store'],
            'in a stack'             => ['stack'],
            'as a drain destination' => ['drain'],
        ];
    }

    /**
     * An anonymous class is named by what it extends, never by its declaring
     * file, which `$e::class` would give with a NUL byte.
     *
     * @param  string  $through
     * @return void
     */
    #[DataProvider('provideAnonymousStores')]
    public function testAnAnonymousStoresPathIsInNoDiagnostic(string $through): void
    {
        $store = self::anonymousStore();

        self::assertStringContainsString(__FILE__, $store::class);

        app()->instance(AuditStore::class, $through === 'stack' ? new StackAuditStore(['first' => $store]) : $store);

        $this->drainOrRecord($through === 'drain');

        $reports = $this->reporter->reports();

        self::assertCount(1, $reports);
        self::assertInstanceOf(AuditWriteFailedException::class, $reports[0]);
        self::assertCount(1, $this->events);

        $diagnostics = [
            $reports[0]->getMessage(),
            $reports[0]->store,
            $reports[0]->exceptionClass,
            $this->events[0]->store,
            $this->events[0]->exception,
            ...$this->rowsLeftBehind(),
        ];

        foreach ($diagnostics as $diagnostic) {
            self::assertIsString($diagnostic);
            self::assertStringNotContainsString("\0", $diagnostic);
            self::assertStringNotContainsString(__FILE__, $diagnostic);
            self::assertStringNotContainsString(basename(__FILE__), $diagnostic);
        }
    }

    /**
     * A throwing spill and listener are each reported naming only their class,
     * and change nothing of what the rule does.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\FailureRule  $rule
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode  $mode
     * @return void
     */
    #[DataProvider('provideRulesAndModes')]
    public function testASecondaryFailureHoldsNoSecret(FailureRule $rule, DeliveryMode $mode): void
    {
        $this->breakTheSpill();

        $this->listenerThrows = true;

        $this->writeFailing($rule, $mode);

        $reports = $this->reporter->reports();

        self::assertSame(
            match ($rule) {
                FailureRule::REPORT          => ['spill', $mode === DeliveryMode::SYNC ? 'store' : 'outbox', 'notify'],
                FailureRule::SPILL_AND_THROW => ['spill', 'notify'],
                FailureRule::THROW           => ['notify'],
            },
            array_map(self::operationOf(...), $reports),
        );

        self::assertSame($rule === FailureRule::REPORT, $this->thrown === null);

        $this->assertTheyHoldNoSecret($this->exceptions());
    }

    /**
     * A reporter that throws the secret stops nothing and leaves it nowhere:
     * its failure is ignored, and the event is still said.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode  $mode
     * @return void
     */
    #[DataProvider('provideModes')]
    public function testABrokenReporterHoldsNoSecret(DeliveryMode $mode): void
    {
        $this->app?->instance(ExceptionHandler::class, self::reporterThrowingTheSecret());

        $this->writeFailing(FailureRule::REPORT, $mode);

        self::assertNull($this->thrown);
        self::assertCount(1, $this->events);
        self::assertHoldsNoSecret($this->events, 'an event');
    }

    /**
     * A finaliser whose clock fails with the secret leaves an unsigned spill,
     * and the report of it holds no secret.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode  $mode
     * @return void
     */
    #[DataProvider('provideModes')]
    public function testAFinaliseFailureHoldsNoSecret(DeliveryMode $mode): void
    {
        app(ConfigRepository::class)->set('audit-log.delivery.mode', $mode->value);

        $this->app?->instance(RecordFinaliser::class, new RecordFinaliser(self::clockThrowingTheSecret(), app(RecordSigner::class)));

        self::pending()->record();

        $reports = $this->reporter->reports();

        self::assertCount(1, $reports);
        self::assertInstanceOf(AuditWriteFailedException::class, $reports[0]);
        self::assertSame('finalise', $reports[0]->operation);

        $this->assertTheyHoldNoSecret($reports);

        $envelope = self::envelopeOf($this->spillLines()[0] ?? '');

        self::assertTrue($envelope['unsigned'] ?? null);
        self::assertArrayNotHasKey('hmac', $envelope);
    }

    /**
     * A deadlock quoting the row inside a host's transaction becomes the fixed
     * `DeadlockException`, holding nothing of the failure.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode  $mode
     * @return void
     */
    #[DataProvider('provideModes')]
    public function testADeadlockHoldsNoSecret(DeliveryMode $mode): void
    {
        $this->breakTheWrite($mode, self::DEADLOCK, '40001', 1213);

        $this->recordInsideAHost();

        self::assertInstanceOf(DeadlockException::class, $this->thrown);
        self::assertSame([], $this->reporter->reports());
        self::assertSame([], $this->spillLines());
        self::assertNull($this->thrown->getPrevious());
        self::assertCount(1, $this->events);
        self::assertHoldsNoSecret($this->events, 'an event');

        $this->assertTheyHoldNoSecret([$this->thrown]);
    }

    /**
     * A lost connection quoting the row inside a host's transaction escapes
     * sanitised, holding nothing of the failure.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode  $mode
     * @return void
     */
    #[DataProvider('provideModes')]
    public function testALostConnectionHoldsNoSecret(DeliveryMode $mode): void
    {
        $this->breakTheWrite($mode, self::LOST, 'HY000', 2006);

        $this->recordInsideAHost();

        self::assertInstanceOf(AuditWriteFailedException::class, $this->thrown);
        self::assertSame([], $this->reporter->reports());
        self::assertSame([], $this->spillLines());
        self::assertNull($this->thrown->getPrevious());
        self::assertCount(1, $this->events);

        $this->assertTheyHoldNoSecret([$this->thrown]);
    }

    /**
     * A concurrency error and a lost connection with no transaction open end
     * nothing, so they follow the rule, and hold no secret either.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode  $mode
     * @return void
     */
    #[DataProvider('provideModes')]
    public function testAFatalFailureWithNoHostHoldsNoSecret(DeliveryMode $mode): void
    {
        foreach ([[self::DEADLOCK, '40001', 1213], [self::LOST, 'HY000', 2006]] as [$message, $state, $code]) {
            $this->breakTheWrite($mode, $message, $state, $code);

            self::pending()->record();
        }

        self::assertNull($this->thrown);
        self::assertCount(2, $this->reporter->reports());

        $this->assertTheyHoldNoSecret($this->reporter->reports());
    }

    /**
     * Rows of `[failure rule]`.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Delivery\Enums\FailureRule}>
     */
    public static function provideRules(): iterable
    {
        foreach (FailureRule::cases() as $rule) {
            yield $rule->value => [$rule];
        }
    }

    /**
     * A stack whose destinations all quote the row leaves only their ids and
     * failure classes, thrown or reported.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\FailureRule  $rule
     * @return void
     */
    #[DataProvider('provideRules')]
    public function testAStackFailureHoldsNoSecret(FailureRule $rule): void
    {
        app()->instance(AuditStore::class, new StackAuditStore([
            'first'  => self::storeQuoting(self::DUPLICATE, '23000', 1062),
            'second' => self::storeQuoting(self::DEADLOCK, '40001', 1213),
        ]));

        $this->record($rule, DeliveryMode::SYNC);

        foreach ($this->exceptions() as $exception) {
            self::assertInstanceOf($rule === FailureRule::THROW ? DeadlockException::class : AuditWriteFailedException::class, $exception);
        }

        self::assertCount(1, $this->exceptions());

        $this->assertTheyHoldNoSecret($this->exceptions());
    }

    /**
     * The exception a stack throws holds each destination's id and class, and
     * nothing of what they failed with, with no previous one.
     *
     * @return void
     */
    public function testAStacksOwnExceptionHoldsNoSecret(): void
    {
        $stack = new StackAuditStore(['first' => self::storeQuoting(self::DUPLICATE, '23000', 1062), 'second' => self::storeQuoting(self::LOST, 'HY000', 2006)]);

        try {
            $stack->store($this->finalisedRecordHoldingTheSecret());

            self::fail('Expected the stack to throw.');
        } catch (StackDeliveryException $exception) {
            self::assertSame(['first' => QueryException::class, 'second' => QueryException::class], $exception->failures);
            self::assertNull($exception->getPrevious());
            self::assertTrue($exception->causedByLostConnection);

            $this->assertTheyHoldNoSecret([$exception]);
        }
    }

    /**
     * A spill keeps the record as minimised, so its line holds no secret, and
     * nothing else logged does.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode  $mode
     * @return void
     */
    #[DataProvider('provideModes')]
    public function testTheSpillHoldsOnlyTheMinimisedValues(DeliveryMode $mode): void
    {
        $this->breakTheWrite($mode, self::DUPLICATE, '23000', 1062);

        $pending = AuditLog::event(self::CODE)->withProperties([
            'password' => self::SECRET,
            'nested'   => ['api_key' => self::SECRET],
            'long'     => str_repeat('y', FieldPolicy::STRING_MAX_BYTES) . self::SECRET,
            'kept'     => 'visible',
        ]);

        $pending->withIdentifier(self::SECRET . '@example.com');
        $pending->fillContext(['api_key' => self::SECRET, 'kept' => 'visible']);

        $pending->record();

        $lines = $this->spillLines();

        self::assertCount(1, $lines);

        $envelope = self::envelopeOf($lines[0]);

        self::assertSame(Redactor::MARKER, $envelope['properties']['password'] ?? null);
        self::assertSame(['api_key' => Redactor::MARKER], $envelope['properties']['nested'] ?? null);
        self::assertSame('visible', $envelope['properties']['kept'] ?? null);
        self::assertSame(str_repeat('y', FieldPolicy::STRING_MAX_BYTES), $envelope['properties']['long'] ?? null);
        self::assertIsString($envelope['properties']['_audit']['identifier_hash'] ?? null);
        self::assertMatchesRegularExpression('/\A[0-9a-f]{16}:[0-9a-f]{64}\z/', $envelope['properties']['_audit']['identifier_hash']);
        self::assertSame(Redactor::MARKER, $envelope['context']['api_key'] ?? null);
        self::assertSame('visible', $envelope['context']['kept'] ?? null);
        self::assertHoldsNoSecret($lines, 'the spill');
        self::assertHoldsNoSecret($this->loggedMessages(), 'the log');
    }

    /**
     * No raw column of an outbox row holds plaintext, before or after undoing
     * its base64, though decrypting it gives every value.
     *
     * @return void
     */
    public function testTheOutboxHoldsNoPlaintext(): void
    {
        $this->outboxModeOn();

        $values = [self::SECRET, self::CODE, 'inv_0042', 'org_01', 'user-42', 'visible-value'];

        $record = self::pending()
            ->on(Reference::of('invoice', 'inv_0042'))
            ->by(Reference::of('user', 'user-42'))
            ->forTenant(Reference::of('organisation', 'org_01'))
            ->withProperties(['detail' => self::SECRET, 'kept' => 'visible-value'])
            ->record();

        $row = (array) $this->outboxConnection()->table(DeliveryTables::outboxTable())->where('id', $record->id)->first();

        self::assertSame(self::OUTBOX_COLUMNS, array_keys($row));
        self::assertIsString($row['payload']);

        $opened   = app(StringEncrypter::class)->decryptString($row['payload']);
        $decoded  = base64_decode($row['payload'], true);
        $sealed   = json_decode((string) $decoded, true);
        $ciphered = is_array($sealed) ? ($sealed['value'] ?? null) : null;

        self::assertIsString($ciphered);

        $haystacks = ['the row' => $row, 'the decoded payload' => $decoded, 'the ciphertext' => base64_decode($ciphered, true)];

        foreach ($values as $value) {
            self::assertStringContainsString($value, $opened);

            foreach ($haystacks as $where => $haystack) {
                self::assertFalse(self::holdsText($haystack, $value), "[{$value}] was found in {$where}.");
            }
        }
    }

    /**
     * A receipt has only its six columns, and neither a failed nor a delivered
     * one holds a payload.
     *
     * @return void
     */
    public function testAReceiptHoldsNoPayload(): void
    {
        $this->outboxModeOn();

        $id = self::pending()->record()->id;

        app()->instance(AuditStore::class, self::storeQuoting(self::DUPLICATE, '23000', 1062));

        Artisan::call('audit-log:drain');

        $failed = $this->rawReceipt($id);

        self::assertSame(self::RECEIPT_COLUMNS, array_keys($failed));
        self::assertSame(QueryException::class, $failed['last_error_class']);
        self::assertSame(DeliveryCoordinator::STORE_DESTINATION, $failed['destination']);
        self::assertHoldsNoSecret($failed, 'the failed receipt');

        CarbonImmutable::setTestNow(CarbonImmutable::now()->addDay());

        app()->instance(AuditStore::class, CallbackStore::saying(true));

        Artisan::call('audit-log:drain');

        self::assertSame(0, $this->outboxCount());

        $delivered = $this->rawReceipt($id);

        self::assertNotNull($delivered['delivered_at']);
        self::assertHoldsNoSecret($delivered, 'the delivered receipt');
    }

    /**
     * Rows of `[what stops the row, the class its report names]`: each way a
     * drain can fail a row whose bytes or destinations hold the secret.
     *
     * @return iterable<string, array{0: string, 1: ?class-string<\Throwable>}>
     */
    public static function provideDrainFailures(): iterable
    {
        yield from [
            'a destination quoting the row'                       => ['destination', QueryException::class],
            'a stack quoting the row'                             => ['stack', QueryException::class],
            'a payload that is not sealed'                        => ['undecryptable', null],
            'an envelope holding the secret that does not verify' => ['rejected', null],
            'a gateway quoting the row'                           => ['gateway', QueryException::class],
        ];
    }

    /**
     * Whatever stops a row in a drain, its row, its receipts, each report, each
     * event and the command's output hold no secret, and name only a class.
     *
     * @param  string  $failure
     * @param  ?class-string<\Throwable>  $class
     * @return void
     */
    #[DataProvider('provideDrainFailures')]
    public function testADrainFailureHoldsNoSecret(string $failure, ?string $class): void
    {
        $this->outboxModeOn();

        app(ConfigRepository::class)->set('audit-log.delivery.outbox.max_attempts', 1);

        $this->stopADrainWith($failure);

        $exit   = Artisan::call('audit-log:drain');
        $output = Artisan::output();

        self::assertNotSame(0, $exit, 'The drain must have failed.');
        self::assertNotSame([], $this->reporter->reports(), 'The drain must have reported.');

        foreach ($this->reporter->reports() as $report) {
            self::assertInstanceOf(AuditWriteFailedException::class, $report);

            if ($class === null) {
                continue;
            }

            self::assertSame($class, $report->exceptionClass);
        }

        $this->assertTheyHoldNoSecret($this->reporter->reports());

        self::assertHoldsNoSecret($output, 'the command\'s output');
        self::assertHoldsNoSecret($this->events, 'an event');
        self::assertHoldsNoSecret($this->rowsLeftBehind(), 'what the drain left');
    }

    /**
     * Rows of `[what stops the line]`: a store that fails, a line altered to
     * hold the secret, and a line that is not even an object.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideReplayFailures(): iterable
    {
        yield from [
            'a signed line a store refuses, quoting it' => ['store'],
            'a line altered to hold the secret'         => ['altered'],
            'a line of nothing but the secret'          => ['garbage'],
        ];
    }

    /**
     * Whatever stops a line of a spill, the result, the command's output and
     * each report hold no secret, though the file does.
     *
     * @param  string  $failure
     * @return void
     */
    #[DataProvider('provideReplayFailures')]
    public function testAReplayFailureHoldsNoSecret(string $failure): void
    {
        $path = $this->spillFileFor($failure);

        self::assertTrue(self::holdsText((string) file_get_contents($path), self::SECRET));

        $result = app(Replayer::class)->spill($path, false);

        self::assertTrue($result->hasSkippedOrFailed());
        self::assertHoldsNoSecret($result, 'the replay\'s result');

        $exit = Artisan::call('audit-log:replay', ['--spill' => $path]);

        self::assertNotSame(0, $exit);
        self::assertHoldsNoSecret(Artisan::output(), 'the command\'s output');
        self::assertHoldsNoSecret($this->reporter->reports(), 'a report');
        self::assertHoldsNoSecret($this->events, 'an event');
    }

    /**
     * A replay of the outbox whose destination still quotes the row keeps the
     * row failed, and neither its output nor what it left holds the secret.
     *
     * @return void
     */
    public function testAnOutboxReplayFailureHoldsNoSecret(): void
    {
        $this->outboxModeOn();

        app(ConfigRepository::class)->set('audit-log.delivery.outbox.max_attempts', 1);

        self::pending()->record();

        app()->instance(AuditStore::class, self::storeQuoting(self::DUPLICATE, '23000', 1062));

        Artisan::call('audit-log:drain');

        $exit = Artisan::call('audit-log:replay', ['--outbox' => true]);

        self::assertNotSame(0, $exit);
        self::assertHoldsNoSecret(Artisan::output(), 'the command\'s output');
        self::assertHoldsNoSecret($this->rowsLeftBehind(), 'what the replay left');

        $this->assertTheyHoldNoSecret($this->reporter->reports());
    }

    /**
     * Spill to a channel that writes nowhere, write reports to no file, and
     * have a broken channel ready.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $config = app(ConfigRepository::class);

        $config->set('logging.default', 'null');
        $config->set('logging.channels.' . self::SPILL_CHANNEL, ['driver' => 'monolog', 'handler' => NullHandler::class]);
        $config->set('logging.channels.' . self::BROKEN_CHANNEL, ThrowingLogHandler::channel());
        $config->set('audit-log.failure.log_channel', self::SPILL_CHANNEL);
    }

    /**
     * Force the write to fail quoting the row, and record under the rule.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\FailureRule  $rule
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode  $mode
     * @return void
     */
    private function writeFailing(FailureRule $rule, DeliveryMode $mode): void
    {
        $this->breakTheWrite($mode, self::DUPLICATE, '23000', 1062);

        $this->record($rule, $mode);
    }

    /**
     * Record in the mode as the rule asks, keeping what escapes, and roll back
     * the transaction a transactional record needs.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\FailureRule  $rule
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode  $mode
     * @return void
     */
    private function record(FailureRule $rule, DeliveryMode $mode): void
    {
        app(ConfigRepository::class)->set('audit-log.delivery.mode', $mode->value);

        try {
            match ($rule) {
                FailureRule::REPORT          => self::pending()->record(),
                FailureRule::SPILL_AND_THROW => self::pending()->failClosed()->record(),
                FailureRule::THROW           => self::recordTransactionally(),
            };
        } catch (\Throwable $thrown) {
            $this->thrown = $thrown;
        }

        $this->endTheTransaction();
    }

    /**
     * Record inside the transaction a transactional record needs.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\AuditRecord
     */
    private static function recordTransactionally(): AuditRecord
    {
        DB::beginTransaction();

        return self::pending()->transactional()->record();
    }

    /**
     * Record inside a host's own `transaction()`, as code that retries would,
     * keeping what escapes, written at once so the failure is inside it.
     *
     * @return void
     */
    private function recordInsideAHost(): void
    {
        try {
            DB::transaction(static function (): void {
                self::pending()->immediately()->record();
            });
        } catch (\Throwable $thrown) {
            $this->thrown = $thrown;
        }

        $this->endTheTransaction();
    }

    /**
     * Roll back whatever a write left open on the worker's connection.
     *
     * @return void
     */
    private function endTheTransaction(): void
    {
        while (DB::transactionLevel() > 0) {
            DB::rollBack();
        }
    }

    /**
     * Put the application in the mode and make the store, or the outbox's
     * insert, fail with the given failure quoting the row.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode  $mode
     * @param  string  $message
     * @param  string  $state
     * @param  int  $code
     * @return void
     */
    private function breakTheWrite(DeliveryMode $mode, string $message, string $state, int $code): void
    {
        app(ConfigRepository::class)->set('audit-log.delivery.mode', $mode->value);

        if ($mode === DeliveryMode::SYNC) {
            app()->instance(AuditStore::class, self::storeQuoting($message, $state, $code));

            return;
        }

        $this->outboxConnection()->beforeExecuting(static function (string $query) use ($message, $state, $code): void {
            if (!str_starts_with($query, 'insert into') || !str_contains($query, DeliveryTables::outboxTable())) {
                return;
            }

            throw self::quoting($message, $state, $code, 'the row');
        });
    }

    /**
     * Make the real insert of the mode fail on a `NOT NULL` column, and keep
     * each long string it is bound to.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode  $mode
     * @return void
     */
    private function breakTheTableAndKeepTheBindings(DeliveryMode $mode): void
    {
        $mode === DeliveryMode::SYNC ? $this->pointAtProbeTable() : $this->pointOutboxAtProbeTable();

        DB::connection()->beforeExecuting(function (string $query, array $bindings): void {
            if (!str_starts_with($query, 'insert into')) {
                return;
            }

            foreach ($bindings as $value) {
                if (!is_string($value) || strlen($value) <= 8) {
                    continue;
                }

                $this->boundStrings[] = $value;
            }
        });
    }

    /**
     * Make the spill's channel fail with the secret.
     *
     * @return void
     */
    private function breakTheSpill(): void
    {
        app(ConfigRepository::class)->set('audit-log.failure.log_channel', self::BROKEN_CHANNEL);
    }

    /**
     * Set up the failure the row of the drain's table names, then leave the row
     * for a drain to find.
     *
     * @param  string  $failure
     * @return void
     */
    private function stopADrainWith(string $failure): void
    {
        match ($failure) {
            'undecryptable' => $this->seedOutboxRow('019a4b2e-7c10-7000-8000-00000000abc1', self::SECRET . ' is not sealed'),
            'rejected'      => $this->seedOutboxRow('019a4b2e-7c10-7000-8000-00000000abc2', app(StringEncrypter::class)->encryptString('{"id":"' . self::SECRET . '"}')),
            default         => self::pending()->record(),
        };

        if ($failure === 'destination') {
            app()->instance(AuditStore::class, self::storeQuoting(self::DUPLICATE, '23000', 1062));
        }

        if ($failure === 'stack') {
            app()->instance(AuditStore::class, new StackAuditStore(['first' => self::storeQuoting(self::DUPLICATE, '23000', 1062)]));
        }

        if ($failure !== 'gateway') {
            return;
        }

        $thrown = false;

        DB::connection(StorageConnection::name())->beforeExecuting(static function (string $query) use (&$thrown): void {
            if ($thrown || !str_starts_with($query, 'select') || !str_contains($query, DeliveryTables::deliveriesTable())) {
                return;
            }

            $thrown = true;

            throw self::quoting(self::DUPLICATE, '23000', 1062, 'the row');
        });
    }

    /**
     * Run a drain that fails, or record in sync mode, with the store bound.
     *
     * @param  bool  $drains
     * @return void
     */
    private function drainOrRecord(bool $drains): void
    {
        if (!$drains) {
            self::pending()->record();

            return;
        }

        $store = app(AuditStore::class);

        app()->forgetInstance(AuditStore::class);

        $this->outboxModeOn();

        app(ConfigRepository::class)->set('audit-log.delivery.outbox.max_attempts', 1);

        self::pending()->record();

        app()->instance(AuditStore::class, $store);

        Artisan::call('audit-log:drain');
    }

    /**
     * A file of one spill line for the row of the replay's table.
     *
     * @param  string  $failure
     * @return string
     */
    private function spillFileFor(string $failure): string
    {
        $line = FailureSpill::line($this->finalisedRecordHoldingTheSecret()->toArray());

        if ($failure === 'store') {
            app()->instance(AuditStore::class, self::storeQuoting(self::DUPLICATE, '23000', 1062));
        }

        $contents = match ($failure) {
            'altered' => str_replace('"detail":"' . self::SECRET . '"', '"detail":"' . self::SECRET . '-altered"', $line),
            'garbage' => FailureSpill::MARKER . self::SECRET,
            default   => $line,
        };

        $path = (string) tempnam(sys_get_temp_dir(), 'audit-spill-');

        $this->files[] = $path;

        file_put_contents($path, $contents . "\n");

        return $path;
    }

    /**
     * A record holding the secret, finalised once by the application.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\FinalisedRecord
     */
    private function finalisedRecordHoldingTheSecret(): FinalisedRecord
    {
        return $this->finalisedRecord(RecordFactory::captured(['detail' => self::SECRET]));
    }

    /**
     * Every exception reported or thrown, in that order.
     *
     * @return list<\Throwable>
     */
    private function exceptions(): array
    {
        return [...$this->reporter->reports(), ...($this->thrown === null ? [] : [$this->thrown])];
    }

    /**
     * The lines logged that are neither a spill nor a log store's, which is
     * what the framework's handler wrote for what it was given.
     *
     * @return list<\Illuminate\Log\Events\MessageLogged>
     */
    private function loggedReports(): array
    {
        return array_values(array_filter(
            $this->loggedMessages(),
            static fn (MessageLogged $logged): bool => !str_starts_with($logged->message, FailureSpill::MARKER) && !str_starts_with($logged->message, LogAuditStore::MARKER),
        ));
    }

    /**
     * What a drain leaves that is meant to be readable: each outbox row but its
     * payload, and each receipt, as their strings.
     *
     * @return list<string>
     */
    private function rowsLeftBehind(): array
    {
        $rows = [
            ...$this->outboxConnection()->table(DeliveryTables::outboxTable())->get(array_values(array_diff(self::OUTBOX_COLUMNS, ['payload'])))->all(),
            ...DB::connection(StorageConnection::name())->table(DeliveryTables::deliveriesTable())->get()->all(),
        ];

        $strings = [];

        foreach ($rows as $row) {
            array_push($strings, ...array_values(array_filter((array) $row, is_string(...))));
        }

        return $strings;
    }

    /**
     * The receipt under the id as the table holds it, in table order.
     *
     * @param  string  $id
     * @return array<string, int|string|null>
     */
    private function rawReceipt(string $id): array
    {
        $row = DB::connection(StorageConnection::name())->table(DeliveryTables::deliveriesTable())->where('entry_id', $id)->first();

        self::assertNotNull($row);

        /** @var array<string, int|string|null> */
        return (array) $row;
    }

    /**
     * Fail when any of the exceptions, or any argument of any of its frames, or
     * its trace as a string, holds the secret.
     *
     * @param  list<\Throwable>  $exceptions
     * @return void
     */
    private function assertTheyHoldNoSecret(array $exceptions): void
    {
        self::assertHoldsNoSecret($exceptions, 'an exception');

        foreach ($exceptions as $exception) {
            $this->assertTheFramesHoldNoSecret($exception);

            self::assertHoldsNoSecret((string) $exception, 'an exception as a string');
        }
    }

    /**
     * Fail when any frame argument holds the secret, however deep, or no frame
     * holds the stand-in for what was hidden.
     *
     * @param  \Throwable  $exception
     * @return void
     */
    private function assertTheFramesHoldNoSecret(\Throwable $exception): void
    {
        $hidden = 0;

        foreach ($exception->getTrace() as $number => $frame) {
            $arguments = $frame['args'] ?? [];
            $where     = sprintf('frame %d, %s%s()', $number, $frame['class'] ?? '', $frame['function']);

            self::assertFalse(self::holdsText($arguments, self::SECRET), "The planted secret was found in {$where}.");

            $hidden += count(array_filter($arguments, static fn (mixed $argument): bool => $argument instanceof \SensitiveParameterValue));
        }

        self::assertGreaterThan(0, $hidden, 'No frame holds the stand-in for a marked parameter.');
    }

    /**
     * The operation a report says failed.
     *
     * @param  \Throwable  $report
     * @return string
     */
    private static function operationOf(\Throwable $report): string
    {
        self::assertInstanceOf(AuditWriteFailedException::class, $report);

        return $report->operation;
    }

    /**
     * The envelope a spill line holds, decoded.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $line
     * @return array<array-key, mixed>
     */
    private static function envelopeOf(string $line): array
    {
        self::assertStringStartsWith(FailureSpill::MARKER, $line);

        $envelope = json_decode(substr($line, strlen(FailureSpill::MARKER)), true, flags: JSON_THROW_ON_ERROR);

        self::assertIsArray($envelope);

        return $envelope;
    }

    /**
     * A builder of the code with the secret in its properties and its context,
     * under keys minimising keeps, so the record really holds it.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\PendingRecord
     */
    private static function pending(): PendingRecord
    {
        $pending = AuditLog::event(self::CODE)->withProperties(['detail' => self::SECRET]);

        $pending->fillContext(['detail' => self::SECRET]);

        return $pending;
    }

    /**
     * A store that joins the worker's connection, whose every call fails
     * quoting the row it was given.
     *
     * @param  string  $message
     * @param  string  $state
     * @param  int  $code
     * @return \Tests\Fixtures\Stores\CallbackStore
     */
    private static function storeQuoting(string $message, string $state, int $code): CallbackStore
    {
        return new CallbackStore(static function (FinalisedRecord $record) use ($message, $state, $code): never {
            throw self::quoting($message, $state, $code, json_encode($record->toArray(), JSON_THROW_ON_ERROR));
        }, true, [self::CONNECTION]);
    }

    /**
     * A real query failure, as Laravel throws one, quoting the row in its
     * message and its bindings, and the secret alongside it.
     *
     * @param  string  $message
     * @param  string  $state
     * @param  int  $code
     * @param  string  $row
     * @return \Illuminate\Database\QueryException
     */
    private static function quoting(string $message, string $state, int $code, string $row): QueryException
    {
        $driver = $message . ' ' . self::SECRET . ' ' . $row;

        $previous = new \PDOException($driver);

        $previous->errorInfo = [$state, $code, $driver];

        return new QueryException(self::CONNECTION, self::FAILED_SQL, [self::SECRET, $row], $previous);
    }

    /**
     * A store of an anonymous class that fails with an exception of an
     * anonymous class, whose names hold this file's path and a NUL byte.
     *
     * @return \SineMacula\Laravel\AuditLog\Contracts\AuditStore
     */
    private static function anonymousStore(): AuditStore
    {
        return new class implements AuditStore {
            /**
             * Fail with an anonymous exception.
             *
             * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
             * @return void
             *
             * @throws \RuntimeException
             */
            #[\Override]
            public function store(#[\SensitiveParameter] FinalisedRecord $record): void
            {
                throw new class ('The store failed.') extends \RuntimeException {};
            }
        };
    }

    /**
     * A clock that fails with the secret.
     *
     * @return \SineMacula\Laravel\AuditLog\Contracts\Clock
     */
    private static function clockThrowingTheSecret(): Clock
    {
        return new class implements Clock {
            /**
             * Fail with the secret.
             *
             * @return \Carbon\CarbonImmutable
             *
             * @throws \RuntimeException
             */
            #[\Override]
            public function now(): CarbonImmutable
            {
                throw new \RuntimeException('The clock stopped: s3cr3t');
            }
        };
    }

    /**
     * A reporter that fails with the secret, whatever it is given.
     *
     * @return \Illuminate\Contracts\Debug\ExceptionHandler
     */
    private static function reporterThrowingTheSecret(): ExceptionHandler
    {
        return new class implements ExceptionHandler {
            /**
             * Fail with the secret.
             *
             * @param  \Throwable  $e
             * @return void
             *
             * @throws \RuntimeException
             */
            #[\Override]
            public function report(\Throwable $e): void
            {
                throw new \RuntimeException('The reporter failed: s3cr3t');
            }

            /**
             * Report everything.
             *
             * @param  \Throwable  $e
             * @return bool
             */
            #[\Override]
            public function shouldReport(\Throwable $e): bool
            {
                return true;
            }

            /**
             * Render a bare response.
             *
             * @param  mixed  $request
             * @param  \Throwable  $e
             * @return \Symfony\Component\HttpFoundation\Response
             */
            #[\Override]
            public function render(mixed $request, \Throwable $e): Response
            {
                return new Response('', 500);
            }

            /**
             * Render nothing to the console.
             *
             * @param  mixed  $output
             * @param  \Throwable  $e
             * @return void
             */
            #[\Override]
            public function renderForConsole(mixed $output, \Throwable $e): void {}
        };
    }
}
