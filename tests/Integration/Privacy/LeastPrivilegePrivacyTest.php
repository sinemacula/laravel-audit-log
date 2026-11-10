<?php

declare(strict_types = 1);

namespace Tests\Integration\Privacy;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\Connection;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\AuditLogServiceProvider;
use SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Lifecycle\AuditLifecycle;
use SineMacula\Laravel\AuditLog\Lifecycle\Authority;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ErasureStatus;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\RewrapStatus;
use SineMacula\Laravel\AuditLog\Querying\TrailEntry;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\ReadsTheTrail;
use Tests\Concerns\RunsDocumentedSql;
use Tests\Concerns\SearchesForSecrets;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\TestCase;

/**
 * Integration tests for owners' keys under the grants the storage note
 * documents, the key block's included, run exactly as written by the tables'
 * owner, on MySQL and PostgreSQL: the writer, granted exactly its privileges,
 * seals a field under a key it creates on its own session, writes the key uses
 * with the entry and reads the field back through the grant; the maintenance
 * user erases, reinstates and rewraps, rotation included; the verifier verifies
 * the key store with `SELECT` alone; and with the documented triggers
 * installed, the key tables' among them, every privacy operation still runs.
 *
 * Each worker creates logins of its own, `audit_writer_<token>`,
 * `audit_maintenance_<token>` and `audit_verifier_<token>`, which the
 * documented grants and triggers name; the writer's login is the storage
 * connection and the maintenance user's the maintenance connection. Every
 * operation goes through the facade or a command, on the provider's default
 * bindings. SQLite has no privileges, so these tests are skipped there.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuditLogServiceProvider::class)]
#[CoversClass(AuditLifecycle::class)]
final class LeastPrivilegePrivacyTest extends TestCase
{
    use ReadsTheTrail, RunsDocumentedSql, SearchesForSecrets;

    /** @var string The connection the writer's login uses, which is the storage connection. */
    private const string WRITER = 'audit_writer';

    /** @var string The connection the maintenance user's login uses, which is the maintenance connection. */
    private const string MAINTENANCE = 'audit_maintenance';

    /** @var string The connection the verifier's login uses. */
    private const string VERIFIER = 'audit_verifier';

    /** @var string The code a card charge is captured under, sealing the card for the actor. */
    private const string CHARGE = 'billing.card_charged';

    /** @var string What a fragment shows once its owner's key was destroyed. */
    private const string ERASED = '[ERASED]';

    /** @var string The card every charge is made with: the planted secret, which no hex, base64url or UUID holds by chance. */
    private const string CARD = self::SECRET . '-4242';

    /** @var string The secret of the wrapping key every key is first wrapped under. */
    private const string FIRST_SECRET = 'first-wrapping-secret-of-32-byte';

    /** @var string The secret of the wrapping key a rewrap moves every key onto. */
    private const string SECOND_SECRET = 'second-wrapping-secret-of-32-byt';

    /** @var array<string, string> The names this worker gives the placeholders, once its logins exist. */
    private array $names = [];

    /** @var bool Whether this test installed the documented triggers. */
    private bool $triggers = false;

    /**
     * Create this worker's logins, run the documented grants for them, the key
     * block after the others, as the tables' owner, make the writer's login the
     * storage connection and the maintenance user's the maintenance connection,
     * wrap every key under a wrapping key of the test's own, freeze the clock,
     * report to a recording handler and define the charge, on MySQL and
     * PostgreSQL only.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $root   = $this->root();
        $driver = $root->getDriverName();

        if ($driver === 'sqlite') {
            self::markTestSkipped('SQLite has no logins or privileges.');
        }

        $this->names = self::documentedNames($root);

        foreach ([self::WRITER, self::MAINTENANCE, self::VERIFIER] as $placeholder) {
            self::createLogin($root, $this->names[$placeholder]);
        }

        self::runDocumentedGrants($root, $this->names);

        foreach ([self::WRITER, self::MAINTENANCE, self::VERIFIER] as $placeholder) {
            self::connectAs($placeholder, self::CONNECTION, $this->names[$placeholder]);
        }

        app(ConfigRepository::class)->set([
            'audit-log.storage.connection'             => self::WRITER,
            'audit-log.storage.maintenance_connection' => self::MAINTENANCE,
            'audit-log.source.id'                      => 'app-eu-1',
            'audit-log.privacy.keys'                   => ['w1' => self::FIRST_SECRET],
            'audit-log.privacy.current'                => 'w1',
        ]);

        CarbonImmutable::setTestNow(new CarbonImmutable('2026-11-04 10:00:00', 'UTC'));

        app()->instance(ExceptionHandler::class, new RecordingExceptionHandler);

        $this->define();
    }

    /**
     * Close the logins' connections, rolling back what any left open, drop the
     * documented triggers when this test installed them, drop the logins and
     * put the clock back.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        if ($this->names !== []) {
            $this->dropLogins();
        }

        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * The writer, granted exactly its documented privileges, seals a card under
     * a key it creates, writes the key use with the entry, and reads the card
     * back through the grant, the key and its erasure rows read on its own
     * credentials.
     *
     * @return void
     */
    public function testTheWriterSealsAndRevealsWithExactlyTheDocumentedPrivileges(): void
    {
        $id = $this->charge('42');

        self::assertSame(1, $this->root()->table(KeyTables::subjectKeysTable())->count());
        self::assertSame(1, $this->root()->table(KeyTables::keyUsesTable())->where('entry_id', $id)->count());
        self::assertHoldsNoSecret((array) $this->root()->table(EntrySettings::table())->where('id', $id)->first(), 'the stored row');

        $this->revealEverything();

        self::assertSame(self::CARD, $this->shown($id)->properties['card'] ?? null);
    }

    /**
     * The maintenance user, granted exactly its documented privileges, erases
     * an owner, reinstates it, rewraps every key onto a new wrapping key and
     * rotates them; each is recorded through the writer, the erased card reads
     * `[ERASED]`, and the card sealed after the reinstatement, in the next
     * generation, reads.
     *
     * @return void
     */
    public function testTheMaintenanceUserErasesReinstatesAndRewraps(): void
    {
        $first = $this->charge('42');

        $erased = AuditLog::lifecycle()->erase(self::customer('42'), self::authority());

        self::assertSame([ErasureStatus::COMPLETE, 1, true], [$erased->status, $erased->keysDestroyed, $erased->recorded]);
        self::assertTrue(AuditLog::lifecycle()->reinstate(self::customer('42'), self::authority())->recorded);

        $second = $this->charge('42');

        app(ConfigRepository::class)->set(['audit-log.privacy.keys' => ['w1' => self::FIRST_SECRET, 'w2' => self::SECOND_SECRET], 'audit-log.privacy.current' => 'w2']);

        $rewrap  = AuditLog::lifecycle()->rewrap(self::authority());
        $rotated = AuditLog::lifecycle()->rewrap(self::authority(), rotate: true);

        self::assertSame([RewrapStatus::COMPLETE, 1, true], [$rewrap->status, $rewrap->rewrapped, $rewrap->recorded]);
        self::assertSame([RewrapStatus::COMPLETE, 1], [$rotated->status, $rotated->rotated]);
        self::assertSame(['erased', 'superseded'], $this->statesOf('42'));

        $this->revealEverything();

        self::assertSame(self::ERASED, $this->shown($first)->properties['card'] ?? null);
        self::assertSame(self::CARD, $this->shown($second)->properties['card'] ?? null);
    }

    /**
     * After the writer seals and the maintenance user erases, the verifier,
     * which only reads the entries, the seals, the journal and the key tables
     * and writes only the progress of verification, verifies the whole log, its
     * key store included, with no finding.
     *
     * @return void
     */
    public function testTheVerifierVerifiesTheKeyStoreWithSelectAlone(): void
    {
        $this->charge('42');
        $this->charge('43');
        $this->seal();

        AuditLog::lifecycle()->erase(self::customer('42'), self::authority());

        $this->seal();

        app(ConfigRepository::class)->set('audit-log.storage.connection', self::VERIFIER);

        [$exit, $printed] = $this->verify();

        self::assertSame(0, $exit, $printed);
        self::assertMatchesRegularExpression('/^Keys: 2 verified, 1 erased, 0 findings\.$/m', $printed);
    }

    /**
     * With the engine's documented triggers installed, the key tables' among
     * them, every privacy operation still runs on the users' own credentials:
     * sealing a field, an erasure, a reinstatement, a rotating rewrap and a
     * verification.
     *
     * @return void
     */
    public function testWithTheTriggersInstalledEveryPrivacyOperationStillRuns(): void
    {
        $this->installTriggers();

        $first = $this->charge('42');

        $this->seal();

        self::assertSame(ErasureStatus::COMPLETE, AuditLog::lifecycle()->erase(self::customer('42'), self::authority())->status);
        self::assertTrue(AuditLog::lifecycle()->reinstate(self::customer('42'), self::authority())->recorded);

        $second = $this->charge('42');

        self::assertSame(RewrapStatus::COMPLETE, AuditLog::lifecycle()->rewrap(self::authority(), rotate: true)->status);

        $this->seal();

        self::assertSame(0, $this->verify()[0]);

        $this->revealEverything();

        self::assertSame(self::ERASED, $this->shown($first)->properties['card'] ?? null);
        self::assertSame(self::CARD, $this->shown($second)->properties['card'] ?? null);
    }

    /**
     * Define the charge on a recorder of the test's own, behind the facade.
     *
     * @return void
     */
    private function define(): void
    {
        $catalogue = new EventCatalogue;

        $catalogue->define(EventDefinition::for(self::CHARGE)->category('billing')->retain('amount')->encrypt('card', KeyOwner::ACTOR));

        $recorder = new Recorder($catalogue, new ContributorRegistry);

        app()->instance(EventCatalogue::class, $catalogue);
        app()->instance(Recorder::class, $recorder);

        AuditLog::swap($recorder);
    }

    /**
     * Capture a charge of a card by the customer with the id, through the
     * writer, and return its id; the clock moves on a second after it.
     *
     * @param  string  $customerId
     * @return string
     */
    private function charge(string $customerId): string
    {
        $id = AuditLog::event(self::CHARGE)->by(self::customer($customerId))->withProperties(['amount' => '12.00', 'card' => self::CARD])->record()->id;

        CarbonImmutable::setTestNow(CarbonImmutable::now()->addSecond());

        return $id;
    }

    /**
     * The states of the customer's keys, read as the tables' owner, by
     * generation.
     *
     * @param  string  $customerId
     * @return list<string>
     */
    private function statesOf(string $customerId): array
    {
        $states = $this->root()->table(KeyTables::subjectKeysTable())
            ->where('owner_type', 'App\Models\Customer')
            ->where('owner_id', $customerId)
            ->orderBy('generation')
            ->pluck('state')
            ->all();

        return self::strings($states);
    }

    /**
     * The entry with the id, as a page of the trail shows it to the viewer,
     * which the test fails without.
     *
     * @param  string  $id
     * @return \SineMacula\Laravel\AuditLog\Querying\TrailEntry
     */
    private function shown(string $id): TrailEntry
    {
        foreach (AuditLog::trail()->visibleTo($this->viewer())->cursorPaginate(100)->entries as $entry) {
            if ($entry->id === $id) {
                return $entry;
            }
        }

        self::fail("The page does not show {$id}.");
    }

    /**
     * Seal every entry recorded so far through `audit-log:seal --sweep`, on the
     * storage connection's credentials.
     *
     * @return void
     */
    private function seal(): void
    {
        self::assertSame(0, Artisan::call('audit-log:seal', ['--sweep' => true]), Artisan::output());
    }

    /**
     * Run `audit-log:verify` on the storage connection's credentials and return
     * its exit code and what it printed.
     *
     * @return array{0: int, 1: string}
     */
    private function verify(): array
    {
        $exit = Artisan::call('audit-log:verify');

        return [$exit, Artisan::output()];
    }

    /**
     * Install the engine's documented triggers and the key tables' triggers,
     * for this worker's logins, as the tables' owner.
     *
     * @return void
     */
    private function installTriggers(): void
    {
        $this->triggers = true;

        self::runDocumentedTriggers($this->root(), $this->names);
    }

    /**
     * Roll back and close the logins' connections, drop the documented triggers
     * when this test installed them, the key tables' included, then drop the
     * logins.
     *
     * @return void
     */
    private function dropLogins(): void
    {
        $root = $this->root();

        foreach ([self::WRITER, self::MAINTENANCE, self::VERIFIER] as $placeholder) {
            $connection = DB::connection($placeholder);

            while ($connection->transactionLevel() > 0) {
                $connection->rollBack();
            }

            DB::purge($placeholder);
        }

        if ($this->triggers) {
            self::dropDocumentedTriggers($root);
        }

        foreach ([self::WRITER, self::MAINTENANCE, self::VERIFIER] as $placeholder) {
            self::dropLogin($root, $this->names[$placeholder]);
        }
    }

    /**
     * A customer, the owner of a card.
     *
     * @param  string  $id
     * @return \SineMacula\Laravel\AuditLog\Records\Reference
     */
    private static function customer(string $id): Reference
    {
        return Reference::of('App\Models\Customer', $id);
    }

    /**
     * The authority every operation is asked for on.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\Authority
     */
    private static function authority(): Authority
    {
        return new Authority(Reference::of('App\Models\User', '7'), 'gdpr.article_17', 'app:case-118');
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
