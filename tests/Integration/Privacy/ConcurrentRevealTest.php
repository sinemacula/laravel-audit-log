<?php

declare(strict_types = 1);

namespace Tests\Integration\Privacy;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Contracts\FieldReader;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Lifecycle\Authority;
use SineMacula\Laravel\AuditLog\Lifecycle\Eraser;
use SineMacula\Laravel\AuditLog\Privacy\EncryptedField;
use SineMacula\Laravel\AuditLog\Privacy\Enums\FieldState;
use SineMacula\Laravel\AuditLog\Privacy\SubjectKeyFieldReader;
use SineMacula\Laravel\AuditLog\Querying\AuditTrail;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\MakesSubjectKeys;
use Tests\Concerns\ReadsTheTrail;
use Tests\Concerns\RunsKilledChildren;
use Tests\TestCase;

/**
 * Integration tests for reading an owner's fragments while another process
 * erases the owner: a read changes at the erasure's commit, never before.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SubjectKeyFieldReader::class)]
#[CoversClass(Eraser::class)]
final class ConcurrentRevealTest extends TestCase
{
    use MakesSubjectKeys, ReadsTheTrail, RunsKilledChildren;

    /** @var string When the entry is stored and the erasure runs, before a child moves its clock on. */
    private const string NOW = '2026-11-04 10:00:00.000000';

    /** @var string The gate a reading child opens once it read the fragment revealed. */
    private const string READ = 'read';

    /** @var string The gate the erasing process opens once its erasure committed. */
    private const string ERASED = 'erased';

    /** @var string The gate an erasing child opens once it tombstoned the keys, uncommitted. */
    private const string TOMBSTONED = 'tombstoned';

    /** @var string The gate that lets an erasing child commit. */
    private const string COMMIT = 'commit';

    /** @var string The file a child writes what it read to. */
    private const string RESULTS = 'results';

    /** @var string The card every entry holds, encrypted for the owner. */
    private const string CARD = '4242';

    /** @var string The id of the entry holding the card. */
    private string $entryId;

    /** @var array{v: int, k: string, c: string} The card's envelope. */
    private array $envelope;

    /**
     * Freeze the clock, reveal every entry, and store the owner's sealed card.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(new CarbonImmutable(self::NOW, 'UTC'));

        $this->keyWrapper();

        app()->bind(FieldReader::class, SubjectKeyFieldReader::class);

        $this->bindReading();
        $this->revealEverything();

        [$key, $dataKey] = $this->makeSubjectKey(self::owner(), Reference::of('organisation', 'org_01'), 'finance');

        $this->entryId  = Str::uuid7()->toString();
        $this->envelope = $this->sealEnvelope($dataKey, $key->id, self::CARD, $this->entryId, ['properties', 'card']);

        $this->seedEntry(['properties' => ['card' => $this->envelope]], id: $this->entryId);
    }

    /**
     * Restore the clock, and remove the children's files after the rollback.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();

        parent::tearDown();

        $this->removeChildren();
    }

    /**
     * A read after the erasure commits shows the card erased.
     *
     * @return void
     */
    public function testAReadAfterTheErasureCommitsNeverReveals(): void
    {
        $child = $this->startChild(function (): void {
            CarbonImmutable::setTestNow(CarbonImmutable::now()->addSeconds(1));

            $reader = app(SubjectKeyFieldReader::class);

            $this->appendToChildFile(self::RESULTS, $this->trailCard());
            $this->appendToChildFile(self::RESULTS, $this->readWith($reader));
            $this->openGate(self::READ);
            $this->awaitGate(self::ERASED);
            $this->appendToChildFile(self::RESULTS, $this->trailCard());
            $this->appendToChildFile(self::RESULTS, $this->readWith($reader));
        });

        $this->awaitGate(self::READ);
        $this->erase();
        $this->openGate(self::ERASED);
        $this->assertKilled($this->waitForChild($child));

        self::assertSame([self::CARD, self::CARD, '[ERASED]', FieldState::ERASED->value], $this->childFileLines(self::RESULTS));
    }

    /**
     * A read while the erasure is uncommitted still reveals the card.
     *
     * @return void
     */
    public function testAReadBeforeTheErasureCommitsStillReveals(): void
    {
        $child = $this->startChild(function (): void {
            CarbonImmutable::setTestNow(CarbonImmutable::now()->addSeconds(1));

            $this->pauseOnceTombstoned();
            $this->erase();
        });

        $this->awaitGate(self::TOMBSTONED);

        $reader = app(SubjectKeyFieldReader::class);
        $during = $this->readWith($reader);

        $this->openGate(self::COMMIT);
        $this->assertKilled($this->waitForChild($child));

        self::assertSame(self::CARD, $during);
        self::assertSame(FieldState::ERASED->value, $this->readWith($reader));
    }

    /**
     * Put SQLite on a WAL file shared across the fork, so reads never block.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $this->useFileDatabaseOnSqlite($app);

        $config = app(ConfigRepository::class);
        $key    = 'database.connections.' . self::CONNECTION;

        if ($config->get($key . '.driver') !== 'sqlite') {
            return;
        }

        $config->set($key . '.journal_mode', 'wal');
    }

    /**
     * Erase the owner with the eraser the container builds.
     *
     * @return void
     */
    private function erase(): void
    {
        app(Eraser::class)->erase('01932b4e-9000-7000-8000-0000000000a1', self::owner(), new Authority(Reference::of('user', '7'), 'case.review'), false, false);
    }

    /**
     * In a child, pause inside the erasure once it tombstoned the keys.
     *
     * @return void
     */
    private function pauseOnceTombstoned(): void
    {
        $paused  = false;
        $pattern = '/^update \W?' . preg_quote(KeyTables::subjectKeysTable(), '/') . '\W/';

        DB::listen(function (QueryExecuted $query) use (&$paused, $pattern): void {
            if ($paused || preg_match($pattern, $query->sql) !== 1) {
                return;
            }

            $paused = true;

            $this->openGate(self::TOMBSTONED);
            $this->awaitGate(self::COMMIT);
        });
    }

    /**
     * The card as a page of the trail shows it to the viewer.
     *
     * @return string
     */
    private function trailCard(): string
    {
        foreach (app(AuditTrail::class)->visibleTo($this->viewer())->inCategory('finance')->cursorPaginate(50)->entries as $entry) {
            if ($entry->id === $this->entryId) {
                $card = $entry->properties['card'] ?? null;

                self::assertIsString($card);

                return $card;
            }
        }

        self::fail('The page does not show the entry.');
    }

    /**
     * The card through the reader: its value when revealed, else its state.
     *
     * @param  \SineMacula\Laravel\AuditLog\Privacy\SubjectKeyFieldReader  $reader
     * @return string
     */
    private function readWith(SubjectKeyFieldReader $reader): string
    {
        $field = EncryptedField::fromEnvelope($this->entryId, ['properties', 'card'], $this->envelope);

        self::assertNotNull($field);

        $reading = $reader->readAll([$field])[0];

        if ($reading->state !== null) {
            return $reading->state->value;
        }

        self::assertIsString($reading->value);

        return $reading->value;
    }

    /**
     * The owner whose card every entry holds.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\Reference
     */
    private static function owner(): Reference
    {
        return Reference::of('user', '42');
    }
}
