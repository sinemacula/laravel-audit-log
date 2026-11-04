<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;
use SineMacula\Laravel\AuditLog\Contracts\RetentionPolicy;
use SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Keys\KeyUses;
use SineMacula\Laravel\AuditLog\Lifecycle\AuditImporter;
use SineMacula\Laravel\AuditLog\Lifecycle\Authority;
use SineMacula\Laravel\AuditLog\Lifecycle\ConfiguredRetentionPolicy;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportStatus;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportBatches;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportLine;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportSource;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportTally;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportWriter;
use SineMacula\Laravel\AuditLog\Privacy\SubjectKeyEncrypter;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\MakesSubjectKeys;

/**
 * Statement budgets of an import: ten thousand rows open no savepoint and one
 * transaction per chunk; a chunk's statements are fixed, apart from its
 * inserts, which scale with the rows each insert carries on its engine and
 * never with the rows themselves; an encrypted chunk adds its records' key
 * lookups and the inserts of its key uses, which scale with the key uses each
 * insert carries, never one per entry; and a dry run writes nothing. Every
 * budget is a count of statements and transactions, never a time, and an
 * encrypted chunk's is measured against a plain chunk's in the same process.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ImportWriter::class)]
#[CoversClass(AuditImporter::class)]
final class ImportStatementBudgetTest extends PerformanceContractTestCase
{
    use MakesSubjectKeys;

    /** @var string The code whose card is encrypted for its actor. */
    private const string ENCRYPTED_CODE = 'billing.card_charged';

    /** @var string The source every import is of. */
    private const string SOURCE = 'crm-eu';

    /** @var string The batch the writer's chunks are of. */
    private const string BATCH = '01932b4e-a000-7000-8000-0000000000b1';

    /** @var list<string> The files this test wrote. */
    private array $files = [];

    /**
     * Name this installation and bind the configured retention policy.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        app(ConfigRepository::class)->set('audit-log.source.id', 'app-eu-1');
        app()->bindIf(RetentionPolicy::class, ConfiguredRetentionPolicy::class);
    }

    /**
     * Remove the files this test wrote.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        foreach ($this->files as $file) {
            if (!is_file($file)) {
                continue;
            }

            unlink($file);
        }

        parent::tearDown();
    }

    /**
     * Ten thousand rows in chunks of 500 open no savepoint: one transaction per
     * chunk and one for each of the journal's start and finish, none nested,
     * counted by the transaction events, since a savepoint never reaches the
     * statement log, and nothing rolled back.
     *
     * @return void
     */
    public function testTenThousandRowsOpenNoSavepoint(): void
    {
        $path   = $this->file(10000);
        $result = $this->assertTransactionBudget(22, 22, fn () => $this->importer()->import(ImportSource::fromFile($path, self::SOURCE), self::authority()));

        self::assertSame(ImportStatus::COMPLETE, $result->status);
        self::assertSame(10000, $result->imported);
        self::assertSame(0, $this->capturedSavepoints());
        self::assertSame(0, $this->capturedRollbacks());
        self::assertSame(10000, DB::connection()->table(EntrySettings::table())->count());
    }

    /**
     * A chunk's statements are fixed but for its inserts: a chunk of 500 new
     * lines and one of 100 differ only by the inserts, which are as many as the
     * engine's rows per insert need, and each chunk is one transaction with no
     * savepoint.
     *
     * @return void
     */
    public function testTheStatementsAreFixedPerChunk(): void
    {
        $this->startBatch();

        $perInsert = DB::connection()->getDriverName() === 'sqlite' ? ImportWriter::SQLITE_ROWS_PER_INSERT : ImportWriter::ROWS_PER_INSERT;
        $budgets   = [];

        foreach ([[1, 500], [501, 100]] as [$first, $count]) {
            $this->assertStatementBudget(...$this->chunkBudget($first, $count, $perInsert));

            $statements = $this->capturedStatements();
            $inserts    = count(array_filter($statements, static fn (string $statement): bool => str_starts_with(strtolower($statement), 'insert')));

            self::assertSame((int) ceil($count / $perInsert), $inserts);

            $budgets[] = count($statements) - $inserts;
        }

        self::assertSame($budgets[0], $budgets[1]);
    }

    /**
     * An encrypted chunk of 500 lines by one actor whose key exists costs what
     * a plain chunk of 500 costs, measured first, plus one key lookup per
     * record and the inserts of its 500 key uses, as many as the engine's rows
     * per statement need: two on SQLite, at 400 rows each, and one elsewhere,
     * never one per entry; it is still one transaction with no savepoint.
     *
     * @return void
     */
    public function testAnEncryptedChunkAddsItsKeyUseInsertsByThePlaceholderLimit(): void
    {
        $this->startBatch();

        $plain = $this->chunkStatements(array_map(static fn (int $number): ImportLine => self::line($number), range(1, 500)));
        $actor = Reference::of('App\Models\User', '7');

        $this->encryptCardsFor($actor);

        $encrypted = $this->chunkStatements(array_map(static fn (int $number): ImportLine => self::encryptedLine($number, $actor), range(501, 1000)));
        $perInsert = KeyUses::rowsPerStatement(DB::connection());
        $uses      = self::statementsOn($encrypted, 'insert', KeyTables::keyUsesTable());
        $lookups   = self::statementsOn($encrypted, 'select', KeyTables::subjectKeysTable());

        self::assertCount((int) ceil(500 / $perInsert), $uses);
        self::assertCount(500, $lookups);
        self::assertCount(count($plain) + 500 + count($uses), $encrypted);
        self::assertSame(0, $this->capturedSavepoints());
        self::assertSame(500, DB::connection()->table(KeyTables::keyUsesTable())->count());
        self::assertSame(1000, DB::connection()->table(EntrySettings::table())->count());
    }

    /**
     * A dry run of a thousand lines writes nothing and opens no transaction:
     * every statement it issues is a read.
     *
     * @return void
     */
    public function testADryRunIssuesNoWrite(): void
    {
        $path   = $this->file(1000);
        $result = $this->assertTransactionBudget(0, 0, fn () => $this->importer()->import(ImportSource::fromFile($path, self::SOURCE), self::authority(), dryRun: true));

        self::assertSame(1000, $result->imported);
        $writes = array_filter($this->capturedStatements(), static fn (string $statement): bool => !str_starts_with(strtolower(ltrim($statement)), 'select'));

        self::assertSame([], array_values($writes));
        self::assertNotSame([], $this->capturedStatements());
    }

    /**
     * The budget of a chunk of new lines from the first given: one read to
     * classify, and the claim, the inserts and the counts as writes, with no
     * savepoint and no rollback.
     *
     * @param  int  $first
     * @param  int  $count
     * @param  int  $perInsert
     * @return array{0: int, 1: int, 2: int, 3: int, 4: callable(): void}
     */
    private function chunkBudget(int $first, int $count, int $perInsert): array
    {
        $lines = array_map(static fn (int $number): ImportLine => self::line($number), range($first, $first + $count - 1));
        $tally = new ImportTally;

        foreach ($lines as $line) {
            $tally->countRead();
        }

        return [1, 2 + (int) ceil($count / $perInsert), 0, 0, fn () => app(ImportWriter::class)->write(self::BATCH, $lines, $tally, CarbonImmutable::now())];
    }

    /**
     * Start the batch the writer's chunks are of.
     *
     * @return void
     */
    private function startBatch(): void
    {
        app(ImportBatches::class)->start([
            'id'                  => self::BATCH,
            'source_id'           => self::SOURCE,
            'source_region'       => null,
            'input_format'        => 'audit-log-import/v1',
            'importer_type'       => 'App\Models\User',
            'importer_id'         => '7',
            'reason'              => 'case.review',
            'external_reference'  => null,
            'file_sha256'         => str_repeat('f', 64),
            'externally_verified' => false,
            'hold_id'             => null,
        ]);
    }

    /**
     * Write a file of the number of lines given, and return its path.
     *
     * @param  int  $count
     * @return string
     */
    private function file(int $count): string
    {
        $path   = (string) tempnam(sys_get_temp_dir(), 'import-budget-');
        $handle = fopen($path, 'wb');

        assert($handle !== false);

        for ($number = 1; $number <= $count; $number++) {
            $line = ['format' => 'audit-log-import/v1', 'source_record_id' => 'rec-' . $number, 'occurred_at' => '2026-10-01T09:00:00.000001Z', 'event' => 'invoice.approved'];

            fwrite($handle, json_encode([...$line, 'outcome' => 'success', 'category' => 'finance', 'properties' => ['amount' => '1200.00']]) . "\n");
        }

        fclose($handle);

        $this->files[] = $path;

        return $path;
    }

    /**
     * A line of the number given.
     *
     * @param  int  $number
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ImportLine
     */
    private static function line(int $number): ImportLine
    {
        return new ImportLine(
            $number,
            self::SOURCE,
            null,
            'rec-' . $number,
            'invoice.approved',
            '2026-10-01T09:00:00.000001Z',
            Outcome::SUCCESS,
            null,
            null,
            null,
            null,
            null,
            'finance',
            null,
            ['amount' => '1200.00'],
            null,
            null,
            null,
        );
    }

    /**
     * Write the chunk of lines and return the statements it ran, checking it
     * was one transaction, committed once.
     *
     * @param  list<\SineMacula\Laravel\AuditLog\Lifecycle\ImportLine>  $lines
     * @return list<string>
     */
    private function chunkStatements(array $lines): array
    {
        $tally = new ImportTally;

        foreach ($lines as $line) {
            $tally->countRead();
        }

        $this->assertTransactionBudget(1, 1, static fn () => app(ImportWriter::class)->write(self::BATCH, $lines, $tally, CarbonImmutable::now()));

        self::assertSame(count($lines), $tally->imported());

        return $this->capturedStatements();
    }

    /**
     * The statements of the verb given on the table given.
     *
     * @param  list<string>  $statements
     * @param  'insert'|'select'  $verb
     * @param  string  $table
     * @return list<string>
     */
    private static function statementsOn(array $statements, string $verb, string $table): array
    {
        return array_values(array_filter($statements, static fn (string $statement): bool => str_starts_with(strtolower($statement), $verb) && str_contains($statement, $table)));
    }

    /**
     * Encrypt the card of the encrypted code for its actor, under the package's
     * encrypter and wrapper, and make each actor's key first, so a chunk only
     * looks the keys up.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  ...$actors
     * @return void
     */
    private function encryptCardsFor(Reference ...$actors): void
    {
        $catalogue = new EventCatalogue;

        $catalogue->define(EventDefinition::for(self::ENCRYPTED_CODE)->category('finance')->retain('amount')->encrypt('card', KeyOwner::ACTOR));

        app()->instance(EventCatalogue::class, $catalogue);
        app()->instance(Recorder::class, new Recorder($catalogue, new ContributorRegistry));
        app()->bind(FieldEncrypter::class, SubjectKeyEncrypter::class);

        foreach ($actors as $actor) {
            $this->makeSubjectKey($actor, null, 'finance');
        }
    }

    /**
     * A line of the encrypted code of the number given, by the actor, its card
     * to be encrypted for them.
     *
     * @param  int  $number
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $actor
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ImportLine
     */
    private static function encryptedLine(int $number, Reference $actor): ImportLine
    {
        return new ImportLine(
            $number,
            self::SOURCE,
            null,
            'rec-' . $number,
            self::ENCRYPTED_CODE,
            '2026-10-01T09:00:00.000001Z',
            Outcome::SUCCESS,
            null,
            $actor,
            null,
            null,
            null,
            'finance',
            null,
            ['amount' => '12.00', 'card' => '4242'],
            null,
            null,
            null,
        );
    }

    /**
     * The authority every import is made on.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\Authority
     */
    private static function authority(): Authority
    {
        return new Authority(Reference::of('App\Models\User', '7'), 'case.review');
    }

    /**
     * The importer the container builds.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\AuditImporter
     */
    private function importer(): AuditImporter
    {
        return app(AuditImporter::class);
    }
}
