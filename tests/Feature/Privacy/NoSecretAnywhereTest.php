<?php

declare(strict_types = 1);

namespace Tests\Feature\Privacy;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Container\Container;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\DatabaseTransactionRecord;
use Illuminate\Database\DatabaseTransactionsManager;
use Illuminate\Database\QueryException;
use Illuminate\Log\Events\MessageLogged;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Contracts\ContextContributor;
use SineMacula\Laravel\AuditLog\Contracts\DurableAuditStore;
use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;
use SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Delivery\CommitFlush;
use SineMacula\Laravel\AuditLog\Events\AuditRecorded;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Privacy\FieldEncryptionFailedException;
use SineMacula\Laravel\AuditLog\Privacy\FieldPolicy;
use SineMacula\Laravel\AuditLog\Privacy\IdentifierHasher;
use SineMacula\Laravel\AuditLog\Privacy\KeyCeiling;
use SineMacula\Laravel\AuditLog\Privacy\Redactor;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Records\Contribution;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException;
use SineMacula\Laravel\AuditLog\Stores\FailureSpill;
use SineMacula\Laravel\AuditLog\Testing\FakeAuditStore;
use Tests\Concerns\CapturesLogLines;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Concerns\SearchesForSecrets;
use Tests\Fixtures\Privacy\MalformedFieldEncrypter;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Privacy\ThrowingFieldEncrypter;
use Tests\TestCase;
use Tests\Unit\Stubs\StubUser;

/**
 * A secret planted under every built-in key is searched for wherever a capture
 * can leave it: the returned record, the stored row, each event dispatched,
 * each log line, each report and an after-commit capture, and then the same
 * again under each failure a capture can be forced into, the thrown exception
 * and its chain among them.
 *
 * The whole class turns `zend.exception_ignore_args` off, so a thrown exception
 * keeps every frame's arguments to search. Every test records through
 * `AuditLog::event()`, and a helper on the stack takes the key, never the
 * payload, or the search would find the test's own frame.
 *
 * A failed write is searched under the `throw` mode, so what is thrown can be
 * searched too, and a spill line is searched with the rest of the log.
 *
 * It claims no coverage because a fresh application for every key under every
 * search is the slowest class in the suite: a mutant whose covering tests
 * included it would be skipped as taking too long rather than run, so the
 * classes it passes through would go without a mutation check. It pins what a
 * capture leaves behind, end to end; each class's behaviour is pinned by its
 * own test.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class NoSecretAnywhereTest extends TestCase
{
    use CapturesLogLines, InteractsWithAuditStore, SearchesForSecrets;

    /** @var string The code every test records. */
    private const string CODE = 'invoice.approved';

    /** @var string The key most forced failures plant the secret under. */
    private const string KEY = 'password';

    /** @var string A field key matching does not redact, so its rule alone protects it. */
    private const string FIELD = 'card';

    /** @var string A key made from what could be someone's address, holding the secret itself. */
    private const string DYNAMIC_KEY = self::SECRET . '@example.com';

    /** @var string The setting that turns a frame's arguments off. */
    private const string IGNORE_ARGS = 'zend.exception_ignore_args';

    /** @var string What a failing listener throws. */
    private const string LISTENER_FAILURE = 'The listener failed.';

    /** @var string What each failing store throws. */
    private const string STORE_FAILURE = 'The store is down.';

    /** @var string The setting as it was before the test. */
    private string $ignoreArgs = '';

    /** @var list<\Illuminate\Log\Events\MessageLogged> Each line logged during the test. */
    private array $logged = [];

    /**
     * Keep every frame's arguments, write no log file, and hold on to each line
     * logged.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->ignoreArgs = (string) ini_get(self::IGNORE_ARGS);

        ini_set(self::IGNORE_ARGS, '0');

        app(ConfigRepository::class)->set('logging.default', 'null');

        $this->onLogLine(function (MessageLogged $line): void {
            $this->logged[] = $line;
        });
    }

    /**
     * Put the setting back as it was.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        ini_set(self::IGNORE_ARGS, $this->ignoreArgs);

        parent::tearDown();
    }

    /**
     * Rows of `[key]`: one per built-in unit, joined as a key writes it, so a
     * new unit is covered without editing this test.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideBuiltInKeys(): iterable
    {
        foreach (Redactor::SENSITIVE_UNITS as $unit) {
            $key = implode('_', $unit);

            yield $key => [$key];
        }
    }

    /**
     * The record the capture returns holds the marker wherever the secret was
     * planted, and holds the secret nowhere.
     *
     * @param  string  $key
     * @return void
     */
    #[DataProvider('provideBuiltInKeys')]
    public function testTheReturnedRecordHoldsNoSecret(string $key): void
    {
        FakeAuditStore::fake();

        $record = self::planted($key)->record();

        self::assertHoldsNoSecret($record, 'the returned record');
        self::assertHoldsNoSecret($record->toArray(), 'the returned record as an array');

        foreach ([$record->properties, $record->context] as $values) {
            self::assertSame(Redactor::MARKER, $values[$key] ?? null);
            self::assertSame([$key => Redactor::MARKER], $values['nested'] ?? null);
            self::assertSame([[$key => Redactor::MARKER], [$key => Redactor::MARKER]], $values['items'] ?? null);
        }
    }

    /**
     * The row as the database holds it, before any codec or cast, holds the
     * marker and never the secret.
     *
     * @param  string  $key
     * @return void
     */
    #[DataProvider('provideBuiltInKeys')]
    public function testTheStoredRowHoldsNoSecret(string $key): void
    {
        $record = self::planted($key)->record();
        $row    = $this->storageConnection()->table(EntrySettings::table())->where('id', $record->id)->first();

        self::assertNotNull($row);
        self::assertTrue(self::holdsText($row, Redactor::MARKER));
        self::assertHoldsNoSecret($row, 'the stored row');
    }

    /**
     * Nothing dispatched while the record is captured and stored holds the
     * secret: the record's own event, and the queries that wrote it with their
     * bindings.
     *
     * @param  string  $key
     * @return void
     */
    #[DataProvider('provideBuiltInKeys')]
    public function testNoPackageEventHoldsASecret(string $key): void
    {
        $dispatched = [];

        Event::listen('*', static function (string $name, array $payload) use (&$dispatched): void {
            $dispatched[] = [$name, $payload];
        });

        self::planted($key)->record();

        self::assertContains(AuditRecorded::class, array_column($dispatched, 0));
        self::assertTrue(self::holdsText($dispatched, Redactor::MARKER), 'The search must reach what the insert was given.');
        self::assertHoldsNoSecret($dispatched, 'an event');
    }

    /**
     * A store's failure quotes the record it was given, as a refused insert's
     * does, and logging it through the framework's handler holds no secret,
     * frames included. The marker shows the search reached what was minimised.
     *
     * @param  string  $key
     * @return void
     */
    #[DataProvider('provideBuiltInKeys')]
    public function testNoLogLineHoldsASecret(string $key): void
    {
        self::bindStoreQuotingTheRecord();

        $this->assertTheCaptureLeavesNoSecret(static function () use ($key): void {
            self::planted($key)->record();
        });

        self::assertTrue(self::holdsText($this->logged, Redactor::MARKER), 'The search must reach what was minimised.');
    }

    /**
     * A listener's failure is reported, not thrown, and one that quotes the row
     * it was told about holds no secret, frames included. The marker shows the
     * search reached what was minimised.
     *
     * @param  string  $key
     * @return void
     */
    #[DataProvider('provideBuiltInKeys')]
    public function testNoReportHoldsASecret(string $key): void
    {
        $handler = self::recordReports();

        $this->failEveryListenerQuotingTheRow();

        self::planted($key)->record();

        self::assertCount(1, $handler->reports());
        self::assertTrue(self::holdsText($handler->reports(), Redactor::MARKER), 'The search must reach what was minimised.');
        self::assertHoldsNoSecret($handler->reports(), 'a report');
    }

    /**
     * A failing listener is reported through the framework's handler and does
     * not fail the write.
     *
     * @return void
     */
    public function testAFailingListenerIsLogged(): void
    {
        self::failEveryListener();

        self::planted(self::KEY)->record();

        self::assertSame([self::LISTENER_FAILURE], array_column($this->logged, 'message'));
        self::assertSame(1, $this->entryCount());
    }

    /**
     * An after-commit capture waits in the transaction manager as a closure
     * holding the record sealed, so a frame holding the transaction cannot
     * reach it: the search reaches the record once unsealed, finds no secret
     * there, and finds none in the row the commit writes.
     *
     * @param  string  $key
     * @return void
     */
    #[DataProvider('provideBuiltInKeys')]
    public function testADeferredCaptureHoldsNoSecret(string $key): void
    {
        $connection = $this->storageConnection();

        $connection->beginTransaction();

        $record  = self::planted($key)->record();
        $manager = app('db.transactions');

        self::assertInstanceOf(DatabaseTransactionsManager::class, $manager);
        self::assertSame(1, $manager->getPendingTransactions()->sum(static fn (DatabaseTransactionRecord $transaction): int => count($transaction->getCallbacks())));
        $flush = (new \ReflectionFunction($manager->getPendingTransactions()->sole()->getCallbacks()[0]))->getClosureThis();

        self::assertInstanceOf(CommitFlush::class, $flush);
        $entries = (new \ReflectionProperty($flush, 'entries'))->getValue($flush);

        self::assertIsArray($entries);
        self::assertIsArray($entries[0]);
        self::assertInstanceOf(\Closure::class, $entries[0]['work']);
        $sealed = (new \ReflectionFunction($entries[0]['work']))->getClosureUsedVariables()['sealed'] ?? null;

        self::assertInstanceOf(\SensitiveParameterValue::class, $sealed);
        self::assertFalse(self::holdsText($manager, $record->id), 'The deferred record must be out of reach of a frame holding the transaction.');
        self::assertTrue(self::holdsText($sealed->getValue(), $record->id), 'The search must reach the deferred record.');
        self::assertHoldsNoSecret($sealed->getValue(), 'the deferred record');
        self::assertHoldsNoSecret($manager, 'the transaction manager');
        self::assertSame(0, $this->entryCount());

        $connection->commit();

        $row = $connection->table(EntrySettings::table())->where('id', $record->id)->first();

        self::assertNotNull($row);
        self::assertHoldsNoSecret($row, 'the row after commit');
    }

    /**
     * Rows of `[key, setting of configured units]`: a key written each way a
     * tokeniser reads, one that only cleaning makes secret-shaped, and one the
     * application configured.
     *
     * @return iterable<string, array{0: string, 1: list<string>}>
     */
    public static function provideOtherKeys(): iterable
    {
        yield from [
            'upper snake case'           => ['NEW_PASSWORD', []],
            'camel case'                 => ['accessToken', []],
            'kebab case'                 => ['x-api-key', []],
            'an acronym'                 => ['APIKey', []],
            'a header'                   => ['Set-Cookie', []],
            'dotted'                     => ['user.password', []],
            'secret-shaped once cleaned' => ["pass\0word", []],
            'a configured unit'          => ['ssn', ['ssn']],
            'a configured unit, spelt'   => ['ssnNumber', ['ssn_number']],
        ];
    }

    /**
     * A key spelt any way the tokeniser reads, or configured by the
     * application, leaves no secret in the record or the row.
     *
     * @param  string  $key
     * @param  list<string>  $units
     * @return void
     */
    #[DataProvider('provideOtherKeys')]
    public function testASecretUnderAnyOtherKeyIsInNoRecordOrRow(string $key, array $units): void
    {
        app(ConfigRepository::class)->set('audit-log.redaction.keys', $units);

        $record = self::planted($key)->record();
        $row    = $this->storageConnection()->table(EntrySettings::table())->where('id', $record->id)->first();

        self::assertTrue(self::holdsText($record->properties, Redactor::MARKER));
        self::assertHoldsNoSecret($record, 'the returned record');
        self::assertHoldsNoSecret($row, 'the stored row');
    }

    /**
     * Rows of `[whether the record is fail-closed]`: both ways a store's
     * failure reaches the caller.
     *
     * @return iterable<string, array{0: bool}>
     */
    public static function provideFailClosed(): iterable
    {
        yield from [
            'fail-closed'     => [true],
            'not fail-closed' => [false],
        ];
    }

    /**
     * A store that fails leaves no secret in what the caller catches, in a
     * report or in a log, however the record was to be written.
     *
     * @param  bool  $failClosed
     * @return void
     */
    #[DataProvider('provideFailClosed')]
    public function testAFailedWriteHoldsNoSecret(bool $failClosed): void
    {
        self::throwOnAFailedWrite();

        FakeAuditStore::failing(new \RuntimeException(self::STORE_FAILURE));

        $thrown = $this->assertTheCaptureLeavesNoSecret(static function () use ($failClosed): void {
            $pending = self::planted(self::KEY);

            ($failClosed ? $pending->failClosed() : $pending)->record();
        });

        self::assertInstanceOf(AuditWriteFailedException::class, $thrown);
        self::assertSame(\RuntimeException::class, $thrown->exceptionClass);
    }

    /**
     * A garbage address holding the secret, far past the column, is stored
     * nowhere: the record and the row hold no address and no secret, and say
     * only that an address was not kept.
     *
     * @return void
     */
    public function testAGarbageIpHoldingASecretIsInNoRecordOrRow(): void
    {
        $record = self::fromGarbageIp()->record();
        $row    = $this->storageConnection()->table(EntrySettings::table())->where('id', $record->id)->first();

        self::assertNull($record->ip);
        self::assertNotNull($row);
        self::assertTrue(self::holdsText($row, '$ip'));
        self::assertHoldsNoSecret($record, 'the returned record');
        self::assertHoldsNoSecret($row, 'the stored row');
    }

    /**
     * A write that fails after a garbage address was filled holds the address
     * in no exception, report or log line, any frame of the write included.
     *
     * @param  bool  $failClosed
     * @return void
     */
    #[DataProvider('provideFailClosed')]
    public function testAGarbageIpHoldingASecretIsInNoFailure(bool $failClosed): void
    {
        self::throwOnAFailedWrite();
        self::bindThrowingStore();

        $this->assertTheCaptureLeavesNoSecret(static function () use ($failClosed): void {
            $pending = self::fromGarbageIp();

            ($failClosed ? $pending->failClosed() : $pending)->record();
        });
    }

    /**
     * The failing fake's exception was made before the capture, so it has no
     * frame of it: one thrown from inside a store has every frame of the write,
     * and those hold no secret either.
     *
     * @param  bool  $failClosed
     * @return void
     */
    #[DataProvider('provideFailClosed')]
    public function testAStoreThrowingInsideTheWriteHoldsNoSecret(bool $failClosed): void
    {
        self::throwOnAFailedWrite();
        self::bindThrowingStore();

        $thrown = $this->assertTheCaptureLeavesNoSecret(static function () use ($failClosed): void {
            $pending = self::planted(self::KEY);

            ($failClosed ? $pending->failClosed() : $pending)->record();
        });

        self::assertInstanceOf(AuditWriteFailedException::class, $thrown);
        self::assertSame(\RuntimeException::class, $thrown->exceptionClass);
        self::assertContains(Recorder::class, array_column($thrown->getTrace(), 'class'));
    }

    /**
     * A write deferred to the commit fails at the commit, and what escapes from
     * there holds no secret.
     *
     * @return void
     */
    public function testADeferredWriteThatFailsHoldsNoSecret(): void
    {
        self::throwOnAFailedWrite();
        self::bindThrowingStore();

        $connection = $this->storageConnection();
        $thrown     = $this->assertTheCaptureLeavesNoSecret(static function () use ($connection): void {
            $connection->beginTransaction();

            self::planted(self::KEY)->record();

            $connection->commit();
        });

        self::assertInstanceOf(AuditWriteFailedException::class, $thrown);
        self::assertSame(\RuntimeException::class, $thrown->exceptionClass);
    }

    /**
     * The database's own refusal of an insert quotes the query's bindings in
     * its message and keeps them on the exception, so what is thrown is neither
     * that exception nor chained to it, and holds no binding.
     *
     * @return void
     */
    public function testARefusedInsertHoldsNoSecret(): void
    {
        self::throwOnAFailedWrite();

        $this->pointAtProbeTable();

        $this->beforeApplicationDestroyed(fn () => $this->removeProbeTable());

        $thrown = $this->assertTheCaptureLeavesNoSecret(static function (): void {
            self::planted(self::KEY)->record();
        });

        self::assertInstanceOf(AuditWriteFailedException::class, $thrown);
        self::assertSame(QueryException::class, $thrown->exceptionClass);
        self::assertNull($thrown->getPrevious());
        self::assertFalse(self::holdsText($thrown, Redactor::MARKER));
    }

    /**
     * Rows of `[whether it throws an error]`: an exception and an error, both
     * of whose messages hold the plaintext.
     *
     * @return iterable<string, array{0: bool}>
     */
    public static function provideThrowingEncrypters(): iterable
    {
        yield from [
            'an exception' => [false],
            'an error'     => [true],
        ];
    }

    /**
     * An encrypter that throws with the plaintext in its message is contained:
     * the secret is in no record, report or log line, and the encrypter is not
     * called again for the capture.
     *
     * @param  bool  $throwsAnError
     * @return void
     */
    #[DataProvider('provideThrowingEncrypters')]
    public function testAThrowingEncrypterHoldsNoSecret(bool $throwsAnError): void
    {
        $encrypter = new ThrowingFieldEncrypter($throwsAnError);

        app()->instance(FieldEncrypter::class, $encrypter);

        $fake = self::useEncryptedField();

        $thrown = $this->assertTheCaptureLeavesNoSecret(static function (): void {
            self::plantedField()->record();
        });

        self::assertNull($thrown);
        self::assertSame(1, $encrypter->calls());
        self::assertCount(1, $fake->recorded());
        self::assertHoldsNoSecret($fake->finalised(), 'the stored record');
    }

    /**
     * Rows of `[what is wrong with it]`: an envelope that is not one, each
     * holding the secret where a part of it should be. It is made in the test,
     * since a row is an argument of the test's own frame.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMalformedEnvelopes(): iterable
    {
        yield from [
            'no ciphertext'                 => ['no ciphertext'],
            'no key'                        => ['no key'],
            'an extra key'                  => ['an extra key'],
            'a version that is not numeric' => ['a bad version'],
        ];
    }

    /**
     * An envelope that is malformed is never stored, so nothing it holds
     * reaches the record, a report or a log line.
     *
     * @param  string  $fault
     * @return void
     */
    #[DataProvider('provideMalformedEnvelopes')]
    public function testAMalformedEnvelopeHoldsNoSecret(string $fault): void
    {
        app()->instance(FieldEncrypter::class, new MalformedFieldEncrypter(self::malformedEnvelope($fault)));

        $fake = self::useEncryptedField();

        $thrown = $this->assertTheCaptureLeavesNoSecret(static function (): void {
            self::plantedField()->record();
        });

        self::assertNull($thrown);
        self::assertCount(1, $fake->recorded());
        self::assertHoldsNoSecret($fake->finalised(), 'the stored record');
    }

    /**
     * Rows of `[setting, malformed value, whether it fails inside the walker]`:
     * a malformed `redaction.key` is met only once a pseudonymised field asks
     * for a hash, so it throws from the walker with raw values on the stack.
     *
     * @return iterable<string, array{0: string, 1: int|string, 2: bool}>
     */
    public static function provideMalformedSettings(): iterable
    {
        yield from [
            'the ip mode'            => ['audit-log.redaction.ip', 'partial', false],
            'the identifier mode'    => ['audit-log.redaction.identifiers', 'maybe', false],
            'the keys'               => ['audit-log.redaction.keys', 'password', false],
            'the property budget'    => ['audit-log.redaction.max_bytes', 1, false],
            'the context budget'     => ['audit-log.redaction.max_context_bytes', 1, false],
            'the key, in the walker' => ['audit-log.redaction.key', 'short', true],
        ];
    }

    /**
     * A malformed setting fails the write, and nothing the failure carries
     * holds what was being minimised, a pseudonymised field's raw value
     * included.
     *
     * @param  string  $setting
     * @param  int|string  $value
     * @param  bool  $inTheWalker
     * @return void
     */
    #[DataProvider('provideMalformedSettings')]
    public function testAMinimiserFailureHoldsNoSecret(string $setting, int|string $value, bool $inTheWalker): void
    {
        app(ConfigRepository::class)->set($setting, $value);

        $fake = self::useDefinition(EventDefinition::for(self::CODE)->pseudonymise(self::FIELD, 'customer.' . self::FIELD, 'items.*.' . self::FIELD)->retain('customer', 'items'));

        $thrown = $this->assertTheCaptureLeavesNoSecret(static function (): void {
            self::plantedField()->record();
        });

        self::assertInstanceOf(\InvalidArgumentException::class, $thrown);
        self::assertSame($inTheWalker, in_array(FieldPolicy::class, array_column($thrown->getTrace(), 'class'), true));
        self::assertSame(0, $fake->count());
    }

    /**
     * A malformed key met while hashing the identifier fails the write with no
     * trace of the identifier.
     *
     * @return void
     */
    public function testAFailedIdentifierHashHoldsNoSecret(): void
    {
        app(ConfigRepository::class)->set('audit-log.redaction.key', 'short');

        $fake = FakeAuditStore::fake();

        $thrown = $this->assertTheCaptureLeavesNoSecret(static function (): void {
            AuditLog::event(self::CODE)->withIdentifier(self::SECRET)->record();
        });

        self::assertInstanceOf(\InvalidArgumentException::class, $thrown);
        self::assertContains(IdentifierHasher::class, array_column($thrown->getTrace(), 'class'));
        self::assertSame(0, $fake->count());
    }

    /**
     * Rows of `[kind of payload, what the refusal says]`: a payload a builder
     * refuses, each with the secret beside what it refuses.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideRefusedPayloads(): iterable
    {
        yield from [
            'an unsaved model'  => ['model', 'A model must have a key before it can be referenced; save it first.'],
            'a reserved key'    => ['reserved', 'Keys beginning `_audit` are reserved for the package\'s own metadata.'],
            'a nested reserved' => ['nested reserved', 'Keys beginning `_audit` are reserved for the package\'s own metadata.'],
            'a list'            => ['list', 'Properties are a map of names to values, not a list.'],
        ];
    }

    /**
     * A refused payload holds the secret when it is thrown from, and no frame
     * of the refusal shows it.
     *
     * @param  string  $kind
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideRefusedPayloads')]
    public function testARefusedPayloadHoldsNoSecret(string $kind, string $message): void
    {
        FakeAuditStore::fake();

        $thrown = $this->assertTheCaptureLeavesNoSecret(static function () use ($kind): void {
            AuditLog::event(self::CODE)->withProperties(self::refused($kind));
        });

        self::assertInstanceOf(\InvalidArgumentException::class, $thrown);
        self::assertSame($message, $thrown->getMessage());
    }

    /**
     * Rows of `[kind of payload, what the refusal says]`: a context a builder
     * refuses, each with the secret beside what it refuses.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideRefusedContexts(): iterable
    {
        yield from [
            'an unsaved model' => ['model', 'A model must have a key before it can be referenced; save it first.'],
            'a list'           => ['list', 'Context is a map of names to values, not a list.'],
        ];
    }

    /**
     * A refused context holds the secret when it is thrown from, and no frame
     * of the refusal shows it.
     *
     * @param  string  $kind
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideRefusedContexts')]
    public function testARefusedContextHoldsNoSecret(string $kind, string $message): void
    {
        FakeAuditStore::fake();

        $thrown = $this->assertTheCaptureLeavesNoSecret(static function () use ($kind): void {
            AuditLog::event(self::CODE)->fillContext(self::refused($kind));
        });

        self::assertInstanceOf(\InvalidArgumentException::class, $thrown);
        self::assertSame($message, $thrown->getMessage());
    }

    /**
     * A contributor that throws has the builder on the stack by way of its
     * contribution, and what escapes holds no secret, nor what it had filled.
     *
     * @return void
     */
    public function testAThrowingContributorHoldsNoSecret(): void
    {
        $contributor = new class implements ContextContributor {
            /**
             * Fill the context, then fail.
             *
             * @param  \SineMacula\Laravel\AuditLog\Records\Contribution  $contribution
             * @return void
             *
             * @throws \RuntimeException
             */
            #[\Override]
            public function contribute(Contribution $contribution): void
            {
                $contribution->fillContext(['password' => 's3cr3t']);

                throw new \RuntimeException('The contributor failed.');
            }
        };

        $fake = self::useContributor($contributor::class);

        $thrown = $this->assertTheCaptureLeavesNoSecret(static function (): void {
            self::planted(self::KEY)->record();
        });

        self::assertSame('The contributor failed.', $thrown?->getMessage());
        self::assertSame(0, $fake->count());
    }

    /**
     * A contributor whose own fill is refused has the values on the stack at
     * the refusal, and no frame of it shows them.
     *
     * @return void
     */
    public function testARefusedContributionHoldsNoSecret(): void
    {
        $contributor = new class implements ContextContributor {
            /**
             * Fill the context with a list, which is refused.
             *
             * @param  \SineMacula\Laravel\AuditLog\Records\Contribution  $contribution
             * @return void
             *
             * @throws \InvalidArgumentException
             * @throws \LogicException
             */
            #[\Override]
            public function contribute(Contribution $contribution): void
            {
                $contribution->fillContext(['s3cr3t']);
            }
        };

        $fake = self::useContributor($contributor::class);

        $thrown = $this->assertTheCaptureLeavesNoSecret(static function (): void {
            self::planted(self::KEY)->record();
        });

        self::assertSame('Context is a map of names to values, not a list.', $thrown?->getMessage());
        self::assertSame(0, $fake->count());
    }

    /**
     * A contained failure's report names the encrypter's class and nothing
     * else.
     *
     * @return void
     */
    public function testAContainedFailureNamesOnlyTheEncrypterClass(): void
    {
        app()->instance(FieldEncrypter::class, new ThrowingFieldEncrypter);

        $handler = self::recordReports();

        self::useEncryptedField();

        self::plantedField()->record();

        self::assertCount(1, $handler->reports());
        self::assertInstanceOf(FieldEncryptionFailedException::class, $handler->reports()[0]);
        self::assertSame('The field encrypter ' . ThrowingFieldEncrypter::class . ' failed, so the value was dropped.', $handler->reports()[0]->getMessage());
    }

    /**
     * A contained failure's report has no previous exception, since the one the
     * encrypter threw holds the plaintext in its message.
     *
     * @return void
     */
    public function testAContainedFailureHasNoPrevious(): void
    {
        app()->instance(FieldEncrypter::class, new ThrowingFieldEncrypter);

        $handler = self::recordReports();

        self::useEncryptedField();

        self::plantedField()->record();

        self::assertCount(1, $handler->reports());
        self::assertNull($handler->reports()[0]->getPrevious());
    }

    /**
     * An identifier is never stored as given, in the record or in the row.
     *
     * @return void
     */
    public function testAPlantedIdentifierIsInNoRecordOrRow(): void
    {
        $record = AuditLog::event(self::CODE)->withIdentifier(self::SECRET)->record();
        $row    = $this->storageConnection()->table(EntrySettings::table())->where('id', $record->id)->first();

        self::assertNotNull($record->properties['_audit']['identifier_hash'] ?? null);
        self::assertHoldsNoSecret($record, 'the returned record');
        self::assertHoldsNoSecret($row, 'the stored row');
    }

    /**
     * A note with an owner is sealed under the owner's key by the default
     * encrypter, so the record and the row hold its envelope, and its text is
     * in neither.
     *
     * @return void
     */
    public function testAnOwnedNoteIsInNoRecordOrRow(): void
    {
        $record = AuditLog::event(self::CODE)->withNote(self::SECRET, Reference::of('user', '1'))->record();
        $row    = $this->storageConnection()->table(EntrySettings::table())->where('id', $record->id)->first();

        self::assertSame(['v', 'k', 'c'], array_keys($record->properties['_audit']['note'] ?? []));
        self::assertArrayNotHasKey('omitted', $record->properties['_audit'] ?? []);
        self::assertHoldsNoSecret($record, 'the returned record');
        self::assertHoldsNoSecret($row, 'the stored row');
    }

    /**
     * A secret held in a key, by an application that names a field after a
     * value, reaches no diagnostic: a removed field and a collision are each
     * masked, in the properties and in the context.
     *
     * @return void
     */
    public function testASecretInAKeyReachesNoDiagnostic(): void
    {
        $fake = self::useDefinition(EventDefinition::for(self::CODE)->retain('amount'));

        $record = AuditLog::event(self::CODE)
            ->withProperties(['amount' => '1200.00', self::SECRET => 'removed', 'nested' => [self::SECRET => 'kept first', self::SECRET . "\0" => 'collides']])
            ->record();

        self::assertSame(['count' => 3, 'paths' => ['*', '*.*']], $record->properties['_audit']['omitted'] ?? null);
        self::assertHoldsNoSecret($record, 'the returned record');
        self::assertHoldsNoSecret($fake->finalised(), 'the stored record');
    }

    /**
     * A dynamic key under a wildcard rule is part of the concrete path on the
     * walker's stack when an encrypter fails, and no frame of the report holds
     * it, while the diagnostic holds only the rule's path.
     *
     * @return void
     */
    public function testADynamicKeyIsInNoFrameOfAReportedFailure(): void
    {
        app()->instance(FieldEncrypter::class, new ThrowingFieldEncrypter);

        $fake = self::useDefinition(EventDefinition::for(self::CODE)->encrypt('*.' . self::FIELD, KeyOwner::ACTOR));

        $thrown = $this->assertTheCaptureLeavesNoSecret(static function (): void {
            AuditLog::event(self::CODE)->by(Reference::of('user', '1'))->withProperties([self::DYNAMIC_KEY => [self::FIELD => '4111']])->record();
        });

        self::assertNull($thrown);
        self::assertSame(1, $fake->count());
        self::assertHoldsNoSecret($fake->finalised(), 'the stored record');
    }

    /**
     * A dynamic key under a wildcard rule is part of the concrete path on the
     * walker's stack when a malformed key is met, and no frame of what is
     * thrown holds it.
     *
     * @return void
     */
    public function testADynamicKeyIsInNoFrameOfAThrownFailure(): void
    {
        app(ConfigRepository::class)->set('audit-log.redaction.key', 'short');

        $fake = self::useDefinition(EventDefinition::for(self::CODE)->pseudonymise('customer.*'));

        $thrown = $this->assertTheCaptureLeavesNoSecret(static function (): void {
            AuditLog::event(self::CODE)->withProperties(['customer' => [self::DYNAMIC_KEY => 'x']])->record();
        });

        self::assertInstanceOf(\InvalidArgumentException::class, $thrown);
        self::assertContains(FieldPolicy::class, array_column($thrown->getTrace(), 'class'));
        self::assertSame(0, $fake->count());
    }

    /**
     * A key past the ceiling is removed with its value at every depth, even
     * with room in the budgets, so the secret in it and under it is in no
     * record, row, event or diagnostic.
     *
     * @return void
     */
    public function testASecretInAKeyPastTheCeilingIsInNoRecordOrRow(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('audit-log.redaction.max_bytes', 262144);
        $config->set('audit-log.redaction.max_context_bytes', 262144);

        $key     = self::SECRET . str_repeat('k', KeyCeiling::MAX_BYTES);
        $pending = AuditLog::event(self::CODE)->withProperties([$key => self::SECRET, 'nested' => [$key => self::SECRET]]);

        $pending->fillContext([$key => self::SECRET, 'nested' => [$key => self::SECRET]]);

        $record = $pending->record();
        $row    = $this->storageConnection()->table(EntrySettings::table())->where('id', $record->id)->first();

        self::assertSame(['count' => 4, 'paths' => ['*', 'context.*']], $record->properties['_audit']['omitted'] ?? null);
        self::assertHoldsNoSecret($record, 'the returned record');
        self::assertHoldsNoSecret($row, 'the stored row');
    }

    /**
     * The class's set-up leaves the arguments in a frame for the search, or
     * every search of a frame would pass by finding nothing.
     *
     * @return void
     */
    public function testTheFramesAreThereToSearch(): void
    {
        self::assertSame('0', ini_get(self::IGNORE_ARGS));
        self::assertSame(['held'], self::thrownHolding('held')->getTrace()[0]['args'] ?? null);
    }

    /**
     * Rows of `[what makes a haystack]`: each place the search must reach, or a
     * search that finds nothing would prove nothing.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return iterable<string, array{0: \Closure(): mixed}>
     */
    public static function provideHidingPlaces(): iterable
    {
        yield from [
            'a string'              => [static fn (): string => self::SECRET],
            'inside a string'       => [static fn (): string => 'a ' . self::SECRET . ' b'],
            'in another case'       => [static fn (): string => strtoupper(self::SECRET)],
            'an array element'      => [static fn (): array => ['a' => ['b' => [self::SECRET]]]],
            'an array key'          => [static fn (): array => [self::SECRET => 1]],
            'a dynamic property'    => [static fn (): object => (object) ['held' => self::SECRET]],
            'a private property'    => [static fn (): \Stringable => self::holder()],
            'a parent\'s property'  => [static fn (): object => (new StubUser)->forceFill(['name' => self::SECRET])],
            'a closure\'s variable' => [static function (): \Closure {
                $held = self::SECRET;

                return static fn (): string => $held;
            }],
            'a closure\'s object' => [static fn (): \Closure => self::holder()->__toString(...)],
            'an array object'     => [static fn (): object => new \ArrayObject([self::SECRET])],
            'a weak map'          => [static function (): array {
                $key = new \stdClass;
                $map = new \WeakMap;

                $map[$key] = self::SECRET;

                return [$key, $map];
            }],
            'an object storage' => [static function (): object {
                $storage = new \SplObjectStorage;

                $storage[new \stdClass] = self::SECRET;

                return $storage;
            }],
            'a thrown message'         => [static fn (): \Throwable => new \RuntimeException(self::SECRET)],
            'a previous message'       => [static fn (): \Throwable => new \RuntimeException('Outer.', 0, new \LogicException(self::SECRET))],
            'a scalar frame argument'  => [static fn (): \Throwable => self::thrownHolding(self::SECRET)],
            'an array frame argument'  => [static fn (): \Throwable => self::thrownHolding(['a' => [self::SECRET]])],
            'a thrown object\'s field' => [static fn (): \Throwable => self::thrownWithAField()],
        ];
    }

    /**
     * The search reaches each place, and its failure names where it looked and
     * never what it found.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \Closure(): mixed  $makes
     * @return void
     */
    #[DataProvider('provideHidingPlaces')]
    public function testTheSearchFindsTheSecret(\Closure $makes): void
    {
        $failure = null;

        try {
            self::assertHoldsNoSecret($makes(), 'the place looked in');
        } catch (AssertionFailedError $exception) {
            $failure = $exception;
        }

        self::assertNotNull($failure, 'The search must find the secret.');
        self::assertStringContainsString('the place looked in', $failure->getMessage());
        self::assertStringNotContainsStringIgnoringCase(self::SECRET, $failure->getMessage());
    }

    /**
     * The search stops at a container and at what a marked parameter leaves in
     * a frame, and it does not follow an object passed straight to a frame,
     * since a trace writes that as its class alone.
     *
     * @return void
     */
    public function testTheSearchStopsWhereItMust(): void
    {
        $container = new Container;

        $container->instance('held', self::SECRET);

        self::assertHoldsNoSecret($container, 'a container');
        self::assertHoldsNoSecret(new \SensitiveParameterValue(self::SECRET), 'a marked parameter');
        self::assertHoldsNoSecret(self::thrownHolding((object) ['held' => self::SECRET]), 'an object in a frame');
    }

    /**
     * The search does not read a test case, which holds its own data set.
     *
     * @return void
     */
    public function testTheSearchDoesNotReadATestCase(): void
    {
        self::assertFalse(self::holdsText($this, $this->name()));
        self::assertFalse(self::holdsText(['test' => $this], $this->name()));
    }

    /**
     * An object that refers to itself is searched once, and the search ends.
     *
     * @return void
     */
    public function testTheSearchEndsOnACycle(): void
    {
        $first  = new \stdClass;
        $second = new \stdClass;

        $first->other  = $second;
        $second->other = $first;
        $second->held  = 'cycle';

        self::assertTrue(self::holdsText($first, 'cycle'));
        self::assertFalse(self::holdsText($first, self::SECRET));
    }

    /**
     * Run the capture with its reports recorded, pass what escaped it and what
     * it reported through the framework's own handler, as an application would,
     * so each is logged, then search the record, the thrown exception and its
     * chain, the reports and the log, spill lines included, which alone are not
     * logged reports.
     *
     * @param  \Closure(): void  $capture
     * @return ?\Throwable
     */
    private function assertTheCaptureLeavesNoSecret(\Closure $capture): ?\Throwable
    {
        $framework = app(ExceptionHandler::class);
        $handler   = self::recordReports();
        $thrown    = null;

        try {
            $capture();
        } catch (\Throwable $exception) {
            $thrown = $exception;
        }

        $reported = [...($thrown === null ? [] : [$thrown]), ...$handler->reports()];

        foreach ($reported as $report) {
            $framework->report($report);
        }

        self::assertNotSame([], $reported, 'The capture must have failed.');
        $lines = array_filter($this->logged, static fn (MessageLogged $line): bool => !str_starts_with($line->message, FailureSpill::MARKER));

        self::assertCount(count($reported), $lines, 'Each failure must have been logged.');
        self::assertHoldsNoSecret($thrown, 'the thrown exception');
        self::assertHoldsNoSecret($handler->reports(), 'a report');
        self::assertHoldsNoSecret($this->logged, 'a log line');

        return $thrown;
    }

    /**
     * A builder for the code with the secret under the key at the top level, in
     * a nested map and in a list of maps, in the properties and the context.
     *
     * @param  string  $key
     * @return \SineMacula\Laravel\AuditLog\Records\PendingRecord
     */
    private static function planted(string $key): PendingRecord
    {
        $pending = AuditLog::event(self::CODE)->withProperties(self::payload($key));

        $pending->fillContext(self::payload($key));

        return $pending;
    }

    /**
     * A builder for the code filled with an address that is no address, holding
     * the secret and longer than the column.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\PendingRecord
     */
    private static function fromGarbageIp(): PendingRecord
    {
        $pending = AuditLog::event(self::CODE);

        $pending->fillClient(str_repeat(self::SECRET, 50), null);

        return $pending;
    }

    /**
     * The secret under the key at the top level, in a nested map and in a list
     * of maps.
     *
     * @param  string  $key
     * @return array<string, array<array-key, array<string, string>|string>|string>
     */
    private static function payload(string $key): array
    {
        return [$key => self::SECRET, 'nested' => [$key => self::SECRET], 'items' => [[$key => self::SECRET], [$key => self::SECRET]]];
    }

    /**
     * A builder holding the secret raw under a field no key rule matches, so
     * only that field's rule protects it, beside a secret-shaped key and in a
     * note that needs sealing.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\PendingRecord
     */
    private static function plantedField(): PendingRecord
    {
        $properties = [
            self::KEY   => self::SECRET,
            self::FIELD => self::SECRET,
            'customer'  => [self::FIELD => self::SECRET],
            'items'     => [[self::FIELD => self::SECRET], [self::FIELD => self::SECRET]],
        ];

        return AuditLog::event(self::CODE)
            ->on(Reference::of('invoice', '42'))
            ->withProperties($properties)
            ->withNote(self::SECRET, Reference::of('user', '1'));
    }

    /**
     * A payload a builder refuses, with the secret beside what it refuses.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $kind
     * @return array<array-key, mixed>
     */
    private static function refused(string $kind): array
    {
        return match ($kind) {
            'model'           => [self::KEY => self::SECRET, 'invoice' => new StubUser],
            'reserved'        => [self::KEY => self::SECRET, '_audit' => ['note' => self::SECRET]],
            'nested reserved' => [self::KEY => self::SECRET, 'nested' => ['_audit_note' => self::SECRET]],
            default           => [self::SECRET, self::SECRET],
        };
    }

    /**
     * An envelope with the fault, holding the secret.
     *
     * @param  string  $fault
     * @return array<string, int|string>
     */
    private static function malformedEnvelope(string $fault): array
    {
        return match ($fault) {
            'no ciphertext' => ['v' => 1, 'k' => self::SECRET],
            'no key'        => ['v' => 1, 'c' => self::SECRET],
            'an extra key'  => ['v' => 1, 'k' => 'key_1', 'c' => 'sealed', 'x' => self::SECRET],
            default         => ['v' => self::SECRET, 'k' => 'key_1', 'c' => 'sealed'],
        };
    }

    /**
     * Make the definition's recorder the facade's, with a fake store.
     *
     * @param  \SineMacula\Laravel\AuditLog\Definitions\EventDefinition  $definition
     * @return \SineMacula\Laravel\AuditLog\Testing\FakeAuditStore
     */
    private static function useDefinition(EventDefinition $definition): FakeAuditStore
    {
        $recorder = new Recorder(new EventCatalogue, new ContributorRegistry);

        $recorder->define($definition);

        AuditLog::swap($recorder);

        return FakeAuditStore::fake();
    }

    /**
     * Make a definition that encrypts the planted field the facade's, with a
     * fake store.
     *
     * @return \SineMacula\Laravel\AuditLog\Testing\FakeAuditStore
     */
    private static function useEncryptedField(): FakeAuditStore
    {
        return self::useDefinition(
            EventDefinition::for(self::CODE)
                ->encrypt(self::FIELD, KeyOwner::SUBJECT)
                ->encrypt('customer.' . self::FIELD, KeyOwner::SUBJECT)
                ->encrypt('items.*.' . self::FIELD, KeyOwner::SUBJECT),
        );
    }

    /**
     * Make a recorder running the contributor the facade's, with a fake store.
     *
     * @param  string  $contributor
     * @return \SineMacula\Laravel\AuditLog\Testing\FakeAuditStore
     */
    private static function useContributor(string $contributor): FakeAuditStore
    {
        $recorder = new Recorder(new EventCatalogue, new ContributorRegistry);

        $recorder->contribute($contributor);

        AuditLog::swap($recorder);

        return FakeAuditStore::fake();
    }

    /**
     * Bind a handler that keeps what is reported, and return it.
     *
     * @return \Tests\Fixtures\Privacy\RecordingExceptionHandler
     */
    private static function recordReports(): RecordingExceptionHandler
    {
        $handler = new RecordingExceptionHandler;

        app()->instance(ExceptionHandler::class, $handler);

        return $handler;
    }

    /**
     * Make every listener of the record's event fail.
     *
     * @return void
     */
    private static function failEveryListener(): void
    {
        Event::listen(AuditRecorded::class, static function (): never {
            throw new \RuntimeException(self::LISTENER_FAILURE);
        });
    }

    /**
     * Make every listener of the record's event fail quoting the stored row, so
     * a capture has a report that carries the payload to search.
     *
     * @return void
     */
    private function failEveryListenerQuotingTheRow(): void
    {
        $connection = $this->storageConnection();

        Event::listen(AuditRecorded::class, static function (AuditRecorded $event) use ($connection): never {
            throw new \RuntimeException(json_encode($connection->table(EntrySettings::table())->where('id', $event->id)->first(), JSON_THROW_ON_ERROR));
        });
    }

    /**
     * Make a failed write throw, whatever its timing.
     *
     * @return void
     */
    private static function throwOnAFailedWrite(): void
    {
        app(ConfigRepository::class)->set('audit-log.failure.mode', 'throw');
    }

    /**
     * Bind a store that fails quoting the record it was given, as the
     * database's own refusal of an insert quotes its bindings, and let its
     * failure throw.
     *
     * @return void
     */
    private static function bindStoreQuotingTheRecord(): void
    {
        self::throwOnAFailedWrite();

        app()->instance(AuditStore::class, new class implements DurableAuditStore {
            /**
             * Fail, quoting the record.
             *
             * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
             * @return void
             *
             * @throws \RuntimeException
             */
            #[\Override]
            public function store(FinalisedRecord $record): void
            {
                throw new \RuntimeException(json_encode($record->toArray(), JSON_THROW_ON_ERROR));
            }

            /**
             * Say a return is durable, so a fail-closed record reaches the
             * write.
             *
             * @return bool
             */
            #[\Override]
            public function isDurable(): bool
            {
                return true;
            }

            /**
             * Say the write joins no transaction.
             *
             * @param  string  $connection
             * @return bool
             */
            #[\Override]
            public function participatesIn(string $connection): bool
            {
                return false;
            }
        });
    }

    /**
     * Bind a store that throws from inside the write, so its exception has
     * every frame of the capture.
     *
     * @return void
     */
    private static function bindThrowingStore(): void
    {
        app()->instance(AuditStore::class, new class implements DurableAuditStore {
            /**
             * Fail.
             *
             * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
             * @return void
             *
             * @throws \RuntimeException
             */
            #[\Override]
            public function store(FinalisedRecord $record): void
            {
                throw new \RuntimeException('The store is down.');
            }

            /**
             * Say a return is durable, so a fail-closed record reaches the
             * write.
             *
             * @return bool
             */
            #[\Override]
            public function isDurable(): bool
            {
                return true;
            }

            /**
             * Say the write joins no transaction.
             *
             * @param  string  $connection
             * @return bool
             */
            #[\Override]
            public function participatesIn(string $connection): bool
            {
                return false;
            }
        });
    }

    /**
     * An exception whose only frame of interest holds the value as an argument.
     *
     * @param  array<string, list<string>>|object|string  $value
     * @return \RuntimeException
     */
    private static function thrownHolding(array|object|string $value): \RuntimeException
    {
        return new \RuntimeException('Held a ' . get_debug_type($value) . '.');
    }

    /**
     * An exception holding the secret in a field of its own class.
     *
     * @return \RuntimeException
     */
    private static function thrownWithAField(): \RuntimeException
    {
        return new class (self::SECRET) extends \RuntimeException {
            /**
             * Constructor.
             *
             * @param  string  $held
             */
            public function __construct(

                /** What the exception holds. */
                public readonly string $held,
            ) {
                parent::__construct('Held a field.');
            }
        };
    }

    /**
     * An object holding the secret in a private property.
     *
     * @return \Stringable
     */
    private static function holder(): \Stringable
    {
        return new class (self::SECRET) implements \Stringable {
            /**
             * Constructor.
             *
             * @param  string  $held
             */
            public function __construct(

                /** What the object holds. */
                private readonly string $held,
            ) {}

            /**
             * What the object holds.
             *
             * @return string
             */
            #[\Override]
            public function __toString(): string
            {
                return $this->held;
            }
        };
    }
}
