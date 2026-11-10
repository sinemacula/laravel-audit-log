<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;
use SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode;
use SineMacula\Laravel\AuditLog\Delivery\OutboxDrainer;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Keys\KeyUnit;
use SineMacula\Laravel\AuditLog\Privacy\SubjectKeyEncrypter;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use Tests\Concerns\MakesSubjectKeys;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;

/**
 * Statement-budget contract for a record's write under the package's encrypter,
 * each path measured against a plain record's cost in the same process: a
 * record that encrypts nothing keeps its single insert and opens no
 * transaction; one whose owner has a key adds one lookup and one key-use
 * insert, in one transaction of its own; a first owner adds what creating its
 * key on the key session costs, measured on its own; several owners still cost
 * one lookup and one key-use insert; inside a host transaction the key uses
 * share the entry's one savepoint; and under the outbox the lookup is paid at
 * capture and the key-use insert at the drain.
 *
 * Every count is of statements and transactions, never a time. The creation's
 * statements run on the key session, which on MySQL and PostgreSQL is a
 * connection of its own, so the first owner's budget counts statements on every
 * connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SubjectKeyEncrypter::class)]
#[CoversClass(DatabaseAuditStore::class)]
final class EncryptedWriteBudgetTest extends PerformanceContractTestCase
{
    use MakesSubjectKeys;

    /** @var string The code whose card is stored as it is. */
    private const string PLAIN_CODE = 'billing.card_noted';

    /** @var string The code whose card is encrypted for its actor, its account for its subject and its payee name for its payee. */
    private const string ENCRYPTED_CODE = 'billing.card_charged';

    /** @var string The category of both codes. */
    private const string CATEGORY = 'billing';

    /** @var list<string> Each statement run on any connection since counting began, as its connection and its statement. */
    private array $everywhere = [];

    /**
     * Bind the package's key wrapper and its encrypter, as the provider will,
     * fresh on every resolution, define both codes, keep reports from the
     * framework, and count the statements every connection runs.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->keyWrapper();

        app()->bind(FieldEncrypter::class, SubjectKeyEncrypter::class);
        app()->instance(ExceptionHandler::class, new RecordingExceptionHandler);

        $catalogue = new EventCatalogue;

        $catalogue->define(EventDefinition::for(self::PLAIN_CODE)->category(self::CATEGORY)->retain('amount', 'card', 'iban', 'payee', 'payee_name'));
        $catalogue->define(
            EventDefinition::for(self::ENCRYPTED_CODE)
                ->category(self::CATEGORY)
                ->retain('amount', 'payee')
                ->encrypt('card', KeyOwner::ACTOR)
                ->encrypt('iban', KeyOwner::SUBJECT)
                ->encrypt('payee_name', 'payee'),
        );

        $recorder = new Recorder($catalogue, new ContributorRegistry);

        app()->instance(EventCatalogue::class, $catalogue);
        app()->instance(Recorder::class, $recorder);

        AuditLog::swap($recorder);

        Event::listen(QueryExecuted::class, function (QueryExecuted $query): void {
            $this->everywhere[] = $query->connectionName . ': ' . $query->sql;
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
     * A record that encrypts nothing, under the package's encrypter, keeps its
     * single insert: no read, no savepoint, no transaction, and nothing asked
     * of the key store.
     *
     * @return void
     */
    public function testAnUnencryptedRecordKeepsItsSingleInsert(): void
    {
        $this->warmUp();

        self::assertSame([0, 1, 0], $this->costOf(0, fn () => $this->plain()));
        self::assertSame([], $this->keyStatements());
    }

    /**
     * A record whose owner has a key costs a plain record's statements and one
     * lookup of its keys and one insert of its key uses, both inside one
     * transaction of its own, committed once, with no savepoint.
     *
     * @return void
     */
    public function testAnExistingOwnerAddsOneLookupAndOneKeyUseInsertInOneTransaction(): void
    {
        $actor = Reference::of('App\Models\User', '7');

        $this->makeSubjectKey($actor, null, self::CATEGORY);
        $this->warmUp();

        [$reads, $writes, $savepoints] = $this->costOf(0, fn () => $this->plain($actor));

        self::assertSame([$reads + 1, $writes + 1, $savepoints], $this->costOf(1, fn () => $this->encrypted($actor)));
        self::assertCount(1, array_filter($this->capturedStatements(), static fn (string $statement): bool => str_contains($statement, KeyTables::subjectKeysTable())));
        self::assertStringContainsString(KeyTables::keyUsesTable(), $this->capturedWrites()[1] ?? '');
    }

    /**
     * A record whose owner has no key costs what one whose owner has a key
     * costs, plus what creating a key on the key session costs, measured on its
     * own for another owner: its statements on every connection, and one
     * transaction more.
     *
     * @return void
     */
    public function testAFirstOwnerAddsTheSessionsCreation(): void
    {
        $known = Reference::of('App\Models\User', '7');

        $this->makeSubjectKey($known, null, self::CATEGORY);
        $this->warmUp();

        $existing = $this->everywhereDuring(1, fn () => $this->encrypted($known));
        $creation = $this->everywhereDuring(1, fn () => $this->keyCreator()->create(new KeyUnit(Reference::of('App\Models\User', '9'), null, self::CATEGORY)));
        $first    = $this->everywhereDuring(2, fn () => $this->encrypted(Reference::of('App\Models\User', '8')));

        self::assertNotSame([], $creation);
        self::assertCount(count($existing) + count($creation), $first);
    }

    /**
     * A record of three owners, each with a key, still costs one lookup, of
     * every unit at once, and one insert of its three key uses.
     *
     * @return void
     */
    public function testSeveralOwnersCostOneLookup(): void
    {
        $actor   = Reference::of('App\Models\User', '7');
        $subject = Reference::of('App\Models\Account', '42');
        $payee   = Reference::of('App\Models\Payee', '5');

        foreach ([$actor, $subject, $payee] as $owner) {
            $this->makeSubjectKey($owner, null, self::CATEGORY);
        }

        $this->warmUp();

        [$reads, $writes, $savepoints] = $this->costOf(0, fn () => $this->plain($actor, $subject, $payee));

        self::assertSame([$reads + 1, $writes + 1, $savepoints], $this->costOf(1, fn () => $this->encrypted($actor, $subject, $payee)));
        self::assertSame(3, DB::connection()->table(KeyTables::keyUsesTable())->count());
    }

    /**
     * Inside a host transaction a record written now costs a plain record's
     * statements and savepoint, and one lookup and one key-use insert, the key
     * uses in the entry's one savepoint, with no transaction of its own.
     *
     * @return void
     */
    public function testInsideAHostTransactionTheKeyUsesShareTheSavepoint(): void
    {
        $actor = Reference::of('App\Models\User', '7');

        $this->makeSubjectKey($actor, null, self::CATEGORY);
        $this->warmUp();

        DB::connection()->beginTransaction();

        [$reads, $writes, $savepoints] = $this->costOf(0, fn () => $this->plain($actor, immediately: true));

        self::assertSame(1, $savepoints);
        self::assertSame([$reads + 1, $writes + 1, $savepoints], $this->costOf(0, fn () => $this->encrypted($actor, immediately: true)));
        self::assertSame(1, DB::connection()->transactionLevel());

        DB::connection()->commit();
    }

    /**
     * Under the outbox the record is encrypted at capture, which costs a plain
     * capture's statements and one lookup and writes no key use; the drain
     * writes the key uses with the entry, in the savepoint its store's insert
     * takes inside the drain's transaction, which costs a plain drain's
     * statements and one insert.
     *
     * @return void
     */
    public function testTheOutboxPathEncryptsAtCaptureAndWritesKeyUsesAtTheDrain(): void
    {
        $actor = Reference::of('App\Models\User', '7');

        $this->makeSubjectKey($actor, null, self::CATEGORY);

        app(ConfigRepository::class)->set('audit-log.delivery.mode', DeliveryMode::OUTBOX->value);

        $this->warmUp();
        $this->drain();

        [$captureReads, $captureWrites, $captureSavepoints] = $this->costOf(0, fn () => $this->plain($actor));
        [$drainReads, $drainWrites, $drainSavepoints]       = $this->costOf(1, fn () => $this->drain());

        self::assertSame([$captureReads + 1, $captureWrites, $captureSavepoints], $this->costOf(0, fn () => $this->encrypted($actor)));
        self::assertSame(0, DB::connection()->table(KeyTables::keyUsesTable())->count());
        self::assertSame([$drainReads, $drainWrites + 1, $drainSavepoints], $this->costOf(1, fn () => $this->drain()));
        self::assertSame(1, DB::connection()->table(KeyTables::keyUsesTable())->count());
    }

    /**
     * Record one plain record and drop what it cost, so nothing a process pays
     * once is counted in a budget.
     *
     * @return void
     */
    private function warmUp(): void
    {
        $this->capture(fn () => $this->plain());
    }

    /**
     * Run the subject, check it began and committed the transactions given, and
     * return its reads, writes and savepoints on the default connection.
     *
     * @template TResult
     *
     * @param  int  $transactions
     * @param  callable(): TResult  $subject
     * @return array{0: int, 1: int, 2: int}
     */
    private function costOf(int $transactions, callable $subject): array
    {
        $this->assertTransactionBudget($transactions, $transactions, $subject);

        $writes = count($this->capturedWrites());

        return [count($this->capturedStatements()) - $writes, $writes, $this->capturedSavepoints()];
    }

    /**
     * Run the subject, check it began and committed the transactions given, and
     * return every statement it ran on any connection.
     *
     * @template TResult
     *
     * @param  int  $transactions
     * @param  callable(): TResult  $subject
     * @return list<string>
     */
    private function everywhereDuring(int $transactions, callable $subject): array
    {
        $this->everywhere = [];

        $this->assertTransactionBudget($transactions, $transactions, $subject);

        return $this->everywhere;
    }

    /**
     * The statements the last subject ran on the key tables.
     *
     * @return list<string>
     */
    private function keyStatements(): array
    {
        $tables = [KeyTables::subjectKeysTable(), KeyTables::ownerErasuresTable(), KeyTables::keyUsesTable()];
        $named  = static fn (string $statement): bool => array_filter($tables, static fn (string $table): bool => str_contains($statement, $table)) !== [];

        return array_values(array_filter($this->capturedStatements(), $named));
    }

    /**
     * Drain the outbox with the drainer the container builds.
     *
     * @return void
     */
    private function drain(): void
    {
        app(OutboxDrainer::class)->drain(100, false);
    }

    /**
     * Capture the plain code, by the actor and of the subject given, with a
     * card, an account and a payee's name stored as they are.
     *
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $actor
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $subject
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $payee
     * @param  bool  $immediately
     * @return \SineMacula\Laravel\AuditLog\Records\AuditRecord
     */
    private function plain(?Reference $actor = null, ?Reference $subject = null, ?Reference $payee = null, bool $immediately = false): AuditRecord
    {
        return self::capturing(self::PLAIN_CODE, $actor, $subject, $payee, $immediately);
    }

    /**
     * Capture the encrypted code, by the actor and of the subject given, its
     * card, account and payee's name encrypted for each one present.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $actor
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $subject
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $payee
     * @param  bool  $immediately
     * @return \SineMacula\Laravel\AuditLog\Records\AuditRecord
     */
    private function encrypted(Reference $actor, ?Reference $subject = null, ?Reference $payee = null, bool $immediately = false): AuditRecord
    {
        return self::capturing(self::ENCRYPTED_CODE, $actor, $subject, $payee, $immediately);
    }

    /**
     * Capture the code by the actor, of the subject, with a card, and with an
     * account and a payee's name when there is a subject and a payee, written
     * now when asked.
     *
     * @param  string  $code
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $actor
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $subject
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Reference  $payee
     * @param  bool  $immediately
     * @return \SineMacula\Laravel\AuditLog\Records\AuditRecord
     */
    private static function capturing(string $code, ?Reference $actor, ?Reference $subject, ?Reference $payee, bool $immediately): AuditRecord
    {
        $properties = ['amount' => '12.00', 'card' => '4242'];

        if ($subject !== null) {
            $properties['iban'] = 'GB29NWBK60161331926819';
        }

        if ($payee !== null) {
            $properties['payee']      = ['type' => $payee->type, 'id' => $payee->id];
            $properties['payee_name'] = 'A. Payee';
        }

        $pending = AuditLog::event($code)->by($actor)->withProperties($properties);

        if ($subject !== null) {
            $pending->on($subject);
        }

        return ($immediately ? $pending->immediately() : $pending)->record();
    }
}
