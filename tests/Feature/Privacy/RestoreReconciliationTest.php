<?php

declare(strict_types = 1);

namespace Tests\Feature\Privacy;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Support\Facades\Artisan;
use PHPUnit\Framework\Attributes\CoversNothing;
use SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry;
use SineMacula\Laravel\AuditLog\Database\DeliveryTables;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Querying\TrailEntry;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\MakesSubjectKeys;
use Tests\Concerns\ReadsTheTrail;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\TestCase;

/**
 * Proofs of a database restored from a backup taken before an erasure, on the
 * provider's own bindings, through the commands: with a disk anchor that holds
 * a seal the restored database does not, `audit-log:check` refuses, and a
 * restored key decrypts again, until `audit-log:erase --reapply` erases the
 * owners again and journals the restore as reconciled with the anchored head;
 * and a key table restored on its own brings back a key an erasure destroyed,
 * which `audit-log:verify` and `audit-log:check` each report until the erasure
 * is re-applied.
 *
 * A backup is every row of the package's tables, read as the database holds
 * them, and a restore deletes every row and puts the backup's back. It claims
 * no coverage: it pins what the check, the verification and the reapply do
 * together, each of which its own test pins.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class RestoreReconciliationTest extends TestCase
{
    use MakesSubjectKeys, ReadsTheTrail;

    /** @var string The code a card charge is captured under, sealing the card for the actor. */
    private const string CHARGE = 'billing.card_charged';

    /** @var string What a fragment shows once its owner's key was destroyed. */
    private const string ERASED = '[ERASED]';

    /** @var array<string, string> The options of the authority every command is run on. */
    private const array AUTHORITY = ['--by-type' => 'App\Models\User', '--by-id' => '7', '--reason' => 'gdpr.article_17'];

    /** @var array{type: string, id: string} The owner erased before the restore. */
    private const array OWNER = ['type' => 'App\Models\Customer', 'id' => '42'];

    /** @var ?string The root of the anchor disk, when a test made one. */
    private ?string $anchorRoot = null;

    /** @var list<string> The files this test wrote. */
    private array $files = [];

    /**
     * Freeze the clock, report to a recording handler, and define the charge on
     * a recorder of the test's own, behind the facade.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(new CarbonImmutable('2026-11-04 10:00:00', 'UTC'));

        app()->instance(ExceptionHandler::class, new RecordingExceptionHandler);

        $catalogue = new EventCatalogue;

        $catalogue->define(EventDefinition::for(self::CHARGE)->category('billing')->retain('amount')->encrypt('card', KeyOwner::ACTOR));

        $recorder = new Recorder($catalogue, new ContributorRegistry);

        app()->instance(EventCatalogue::class, $catalogue);
        app()->instance(Recorder::class, $recorder);

        AuditLog::swap($recorder);
    }

    /**
     * Put the clock back, and remove the anchor disk and the files this test
     * wrote.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();

        foreach ($this->files as $file) {
            if (!is_file($file)) {
                continue;
            }

            unlink($file);
        }

        if ($this->anchorRoot !== null) {
            self::removeDirectory($this->anchorRoot);
        }

        parent::tearDown();
    }

    /**
     * A database restored from before an erasure, while its disk anchor holds
     * the seal made after it, fails `audit-log:check` on the anchored head, and
     * the erased owner's card decrypts again.
     *
     * @return void
     */
    public function testARestoreBehindTheAnchorRefusesTheCheck(): void
    {
        $charge = $this->restoredBehindTheAnchor();

        [$exit, $printed] = $this->command('audit-log:check');

        self::assertSame(1, $exit, $printed);
        self::assertStringContainsString('[privacy] The database does not hold the seal its anchor holds at sequence 2, so it was restored from a backup', $printed);

        $this->revealEverything();

        self::assertSame('4242', $this->shown($charge)->properties['card'] ?? null);
    }

    /**
     * Re-applying the erasures since the backup, from a file naming the erased
     * owner, erases the owner again and journals the restore as reconciled at
     * the anchored head, after which `audit-log:check` passes and the card
     * reads `[ERASED]` again.
     *
     * @return void
     */
    public function testReapplyingTheErasuresLetsTheCheckPass(): void
    {
        $charge = $this->restoredBehindTheAnchor();

        [$exit, $printed] = $this->command('audit-log:erase', ['--reapply' => $this->erasuresFile(), ...self::AUTHORITY]);

        self::assertSame(0, $exit, $printed);
        self::assertStringContainsString('Owners 1: 1 erased, 0 already erased, 0 erased in part, 0 refused; 0 lines rejected.', $printed);
        self::assertMatchesRegularExpression('/Restore reconciled in journal row [0-9a-f-]{36}, at anchored sequence 2\./', $printed);

        [$exit, $printed] = $this->command('audit-log:check');

        self::assertSame(0, $exit, $printed);

        $this->revealEverything();

        self::assertSame(self::ERASED, $this->shown($charge)->properties['card'] ?? null);
    }

    /**
     * A key table restored on its own brings back the key an erasure destroyed:
     * `audit-log:verify` reports it `key_restored` and fails, `audit-log:check`
     * names it, and the card decrypts again, until the erasure is re-applied,
     * after which both pass and the card reads `[ERASED]`.
     *
     * @return void
     */
    public function testARestoredKeyIsFoundByVerifyAndTheCheck(): void
    {
        $charge = $this->charge();

        self::assertSame(0, $this->command('audit-log:seal')[0]);

        $keys = $this->backup([KeyTables::subjectKeysTable()]);
        $key  = (string) ($keys[KeyTables::subjectKeysTable()][0]['id'] ?? '');

        self::assertSame(0, $this->command('audit-log:erase', [...self::OWNER, ...self::AUTHORITY])[0]);

        $this->restore($keys);

        [$exit, $printed] = $this->command('audit-log:verify');

        self::assertSame(1, $exit, $printed);
        self::assertStringContainsString("finding key_restored integrity=tampered count=1 first={$key}", $printed);

        [$exit, $printed] = $this->command('audit-log:check');

        self::assertSame(1, $exit, $printed);
        self::assertStringContainsString("[privacy] 1 key of erased owners holds a key again (`key_restored`, the first `{$key}`)", $printed);

        $this->revealEverything();

        self::assertSame('4242', $this->shown($charge)->properties['card'] ?? null);
        self::assertSame(0, $this->command('audit-log:erase', ['--reapply' => $this->erasuresFile(), ...self::AUTHORITY])[0]);
        self::assertSame(0, $this->command('audit-log:verify')[0]);
        self::assertSame(0, $this->command('audit-log:check')[0]);
        self::assertSame(self::ERASED, $this->shown($charge)->properties['card'] ?? null);
    }

    /**
     * Anchor seals on a disk of the test's own, charge the owner's card, seal
     * and anchor it, back the database up, erase the owner, charge again, seal
     * and anchor the second seal, then restore the backup; and return the first
     * charge's id.
     *
     * @return string
     */
    private function restoredBehindTheAnchor(): string
    {
        $this->anchorRoot = sys_get_temp_dir() . '/audit-log-restore-anchors-' . getmypid() . '-' . hrtime(true);

        app(ConfigRepository::class)->set([
            'filesystems.disks.anchors'         => ['driver' => 'local', 'root' => $this->anchorRoot],
            'audit-log.integrity.anchor.driver' => 'disk',
            'audit-log.integrity.anchor.disk'   => 'anchors',
        ]);

        $charge = $this->charge();

        self::assertSame(0, $this->command('audit-log:seal')[0]);
        self::assertSame(0, $this->command('audit-log:check')[0]);

        $backup = $this->backup(self::packageTables());

        self::assertSame(0, $this->command('audit-log:erase', [...self::OWNER, ...self::AUTHORITY])[0]);

        $this->charge();

        self::assertSame(0, $this->command('audit-log:seal')[0]);

        $this->restore($backup);

        return $charge;
    }

    /**
     * Capture a charge of the owner's card and return its id; the clock moves
     * on a second after it.
     *
     * @return string
     */
    private function charge(): string
    {
        $id = AuditLog::event(self::CHARGE)->by(Reference::of(self::OWNER['type'], self::OWNER['id']))->withProperties(['amount' => '12.00', 'card' => '4242'])->record()->id;

        CarbonImmutable::setTestNow(CarbonImmutable::now()->addSecond());

        return $id;
    }

    /**
     * Every row of each table given, as the database holds it, by table.
     *
     * @param  list<string>  $tables
     * @return array<string, list<array<string, scalar|null>>>
     */
    private function backup(array $tables): array
    {
        $backup = [];

        foreach ($tables as $table) {

            /** @var list<array<string, scalar|null>> $rows */
            $rows = array_map(static fn (object $row): array => (array) $row, $this->keyConnection()->table($table)->get()->all());

            $backup[$table] = $rows;
        }

        return $backup;
    }

    /**
     * Delete every row of each table the backup holds and put its rows back.
     *
     * @param  array<string, list<array<string, scalar|null>>>  $backup
     * @return void
     */
    private function restore(array $backup): void
    {
        $connection = $this->keyConnection();

        foreach ($backup as $table => $rows) {
            $connection->table($table)->delete();

            foreach (array_chunk($rows, 50) as $chunk) {
                $connection->table($table)->insert($chunk);
            }
        }
    }

    /**
     * Run the command with the arguments given, and return its exit code and
     * what it printed.
     *
     * @param  string  $command
     * @param  array<string, bool|string>  $arguments
     * @return array{0: int, 1: string}
     */
    private function command(string $command, array $arguments = []): array
    {
        $exit = Artisan::call($command, $arguments);

        return [$exit, Artisan::output()];
    }

    /**
     * Write the file of the erasures since the backup, naming the owner, and
     * return its path.
     *
     * @return string
     */
    private function erasuresFile(): string
    {
        $path = (string) tempnam(sys_get_temp_dir(), 'erasures-');

        file_put_contents($path, json_encode(self::OWNER, JSON_THROW_ON_ERROR) . "\n");

        $this->files[] = $path;

        return $path;
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
     * Every package table on the storage connection, which a backup of the
     * database holds.
     *
     * @return list<string>
     */
    private static function packageTables(): array
    {
        return [
            EntrySettings::table(),
            EntrySettings::artifactsTable(),
            DeliveryTables::outboxTable(),
            DeliveryTables::deliveriesTable(),
            IntegrityTables::checkpointsTable(),
            IntegrityTables::membersTable(),
            IntegrityTables::stateTable(),
            LifecycleTables::journalTable(),
            LifecycleTables::holdsTable(),
            LifecycleTables::lockTable(),
            LifecycleTables::importBatchesTable(),
            KeyTables::subjectKeysTable(),
            KeyTables::ownerErasuresTable(),
            KeyTables::keyUsesTable(),
        ];
    }

    /**
     * Remove the directory and everything under it.
     *
     * @param  string  $directory
     * @return void
     */
    private static function removeDirectory(string $directory): void
    {
        if (!is_dir($directory)) {
            return;
        }

        $items = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($directory, \FilesystemIterator::SKIP_DOTS), \RecursiveIteratorIterator::CHILD_FIRST);

        foreach ($items as $item) {
            assert($item instanceof \SplFileInfo);

            $item->isDir() ? rmdir($item->getPathname()) : unlink($item->getPathname());
        }

        rmdir($directory);
    }
}
