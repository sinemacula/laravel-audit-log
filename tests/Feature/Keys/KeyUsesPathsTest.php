<?php

declare(strict_types = 1);

namespace Tests\Feature\Keys;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;
use SineMacula\Laravel\AuditLog\Contracts\RetentionPolicy;
use SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode;
use SineMacula\Laravel\AuditLog\Delivery\OutboxDrainer;
use SineMacula\Laravel\AuditLog\Delivery\Replayer;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow;
use SineMacula\Laravel\AuditLog\Keys\KeyUnit;
use SineMacula\Laravel\AuditLog\Lifecycle\AuditImporter;
use SineMacula\Laravel\AuditLog\Lifecycle\Authority;
use SineMacula\Laravel\AuditLog\Lifecycle\ConfiguredRetentionPolicy;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportResult;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportSource;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportWriter;
use SineMacula\Laravel\AuditLog\Privacy\SubjectKeyEncrypter;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use SineMacula\Laravel\AuditLog\Stores\FailureSpill;
use SineMacula\Laravel\AuditLog\Testing\FakeAuditStore;
use Tests\Concerns\MakesSubjectKeys;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\TestCase;

/**
 * Feature tests for the key uses on every path that inserts an entry holding an
 * envelope, on whichever engine the suite runs against: the outbox drain, the
 * spill replay and an import each write the key uses of the entries they store,
 * through the store or with each chunk, and a dry import writes none.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DatabaseAuditStore::class)]
#[CoversClass(ImportWriter::class)]
final class KeyUsesPathsTest extends TestCase
{
    use MakesSubjectKeys;

    /** @var string The code every record here is captured or imported under. */
    private const string CODE = 'billing.card_charged';

    /** @var string The category of the code's definition. */
    private const string CATEGORY = 'billing';

    /** @var string The source every import here is of. */
    private const string SOURCE = 'crm-eu';

    /** @var list<string> The files this test wrote. */
    private array $files = [];

    /**
     * Bind the package's key wrapper and its encrypter, as the provider will,
     * define the code with its card encrypted for its actor, and keep reports
     * from the framework.
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

        self::define(EventDefinition::for(self::CODE)->category(self::CATEGORY)->retain('amount')->encrypt('card', KeyOwner::ACTOR));
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
     * A record captured into the outbox has no key use until it is drained: the
     * drain stores its entry and the key use of its key together.
     *
     * @return void
     */
    public function testTheOutboxDrainWritesKeyUses(): void
    {
        app(ConfigRepository::class)->set('audit-log.delivery.mode', DeliveryMode::OUTBOX->value);

        $actor  = Reference::of('App\Models\User', '7');
        $record = $this->chargeCard($actor);

        self::assertSame([], $this->keyUses());
        self::assertSame(0, $this->entries());

        self::assertSame(1, app(OutboxDrainer::class)->drain(100, false)->delivered());
        self::assertSame(1, $this->entries());
        self::assertSame([[$this->keyOf($actor)->id, $record->id]], $this->keyUses());
    }

    /**
     * A spilled record holding an envelope is replayed with its key use: the
     * replay stores the entry and the key use together.
     *
     * @return void
     */
    public function testSpillReplayWritesKeyUses(): void
    {
        $fake   = FakeAuditStore::fake();
        $actor  = Reference::of('App\Models\User', '7');
        $record = $this->chargeCard($actor);
        $path   = $this->file(FailureSpill::line($fake->finalised()[0]->toArray()) . "\n");

        app()->instance(AuditStore::class, app(DatabaseAuditStore::class));

        self::assertSame(1, app(Replayer::class)->spill($path, false)->replayed());
        self::assertSame(1, $this->entries());
        self::assertSame([[$this->keyOf($actor)->id, $record->id]], $this->keyUses());
    }

    /**
     * An import writes the key use of each entry it stores, each under the key
     * of its own line's actor.
     *
     * @return void
     */
    public function testAnImportWritesKeyUses(): void
    {
        $first  = Reference::of('App\Models\User', '7');
        $second = Reference::of('App\Models\User', '8');
        $result = $this->import([$first, $second, $first], false);

        self::assertSame(3, $result->imported);

        $entries = self::strings($this->keyConnection()->table(EntrySettings::table())->orderBy('source_record_id')->pluck('id')->all());
        $keys    = self::strings([$this->keyOf($first)->id, $this->keyOf($second)->id, $this->keyOf($first)->id]);
        $uses    = array_map(static fn (string $key, string $entry): array => [$key, $entry], $keys, $entries);

        usort($uses, static fn (array $left, array $right): int => strcmp($left[0], $right[0]) ?: strcmp($left[1], $right[1]));

        self::assertSame($uses, $this->keyUses());
    }

    /**
     * A dry import stores nothing, so it writes no key use, and, encrypting
     * nothing, makes no key.
     *
     * @return void
     */
    public function testADryImportWritesNone(): void
    {
        $result = $this->import([Reference::of('App\Models\User', '7')], true);

        self::assertSame(1, $result->imported);
        self::assertSame(0, $this->entries());
        self::assertSame([], $this->keyUses());
        self::assertSame([], $this->storedSubjectKeys());
    }

    /**
     * Capture a charge of a card the actor owns, encrypted under the actor's
     * key.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $actor
     * @return \SineMacula\Laravel\AuditLog\Records\AuditRecord
     */
    private function chargeCard(Reference $actor): AuditRecord
    {
        return AuditLog::event(self::CODE)->by($actor)->withProperties(['amount' => '12.00', 'card' => '4242'])->record();
    }

    /**
     * Import a file of a card charge by each actor, in order, as a dry run or
     * not.
     *
     * @param  list<\SineMacula\Laravel\AuditLog\Records\Reference>  $actors
     * @param  bool  $dryRun
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ImportResult
     */
    private function import(array $actors, bool $dryRun): ImportResult
    {
        app(ConfigRepository::class)->set('audit-log.source.id', 'app-eu-1');
        app()->bindIf(RetentionPolicy::class, ConfiguredRetentionPolicy::class);

        $lines = '';

        foreach ($actors as $index => $actor) {
            $lines .= json_encode([
                'format'           => 'audit-log-import/v1',
                'source_record_id' => sprintf('rec-%d', $index + 1),
                'occurred_at'      => '2026-10-01T09:00:00.000001Z',
                'event'            => self::CODE,
                'outcome'          => 'success',
                'actor'            => ['type' => $actor->type, 'id' => $actor->id],
                'properties'       => ['amount' => '12.00', 'card' => '4242'],
            ], JSON_THROW_ON_ERROR) . "\n";
        }

        $authority = new Authority(Reference::of('App\Models\User', '1'), 'case.review');

        return app(AuditImporter::class)->import(ImportSource::fromFile($this->file($lines), self::SOURCE), $authority, $dryRun);
    }

    /**
     * The actor's key in the code's category, with no tenant, which the test
     * fails without.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $actor
     * @return \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow
     */
    private function keyOf(Reference $actor): SubjectKeyRow
    {
        $unit = (new KeyUnit($actor, null, self::CATEGORY))->digest();
        $keys = array_values(array_filter($this->storedSubjectKeys(), static fn (SubjectKeyRow $key): bool => $key->unit === $unit));

        self::assertCount(1, $keys, 'The actor has no key, or more than one.');

        return $keys[0];
    }

    /**
     * Every stored key use, as its key and entry, sorted.
     *
     * @return list<array{0: string, 1: string}>
     */
    private function keyUses(): array
    {
        $rows = $this->keyConnection()->table(KeyTables::keyUsesTable())->orderBy('key_id')->orderBy('entry_id')->get();

        return array_values(array_map(static fn (object $row): array => [(string) $row->key_id, (string) $row->entry_id], $rows->all()));
    }

    /**
     * The count of stored entries.
     *
     * @return int
     */
    private function entries(): int
    {
        return $this->keyConnection()->table(EntrySettings::table())->count();
    }

    /**
     * Write the contents to a file removed when the test ends, and return its
     * path.
     *
     * @param  string  $contents
     * @return string
     */
    private function file(string $contents): string
    {
        $path = tempnam(sys_get_temp_dir(), 'audit-log-key-uses');

        self::assertIsString($path);

        $this->files[] = $path;

        file_put_contents($path, $contents);

        return $path;
    }

    /**
     * Make the definition the only one the facade's recorder and the container
     * know, as an application registers it while it boots.
     *
     * @param  \SineMacula\Laravel\AuditLog\Definitions\EventDefinition  $definition
     * @return void
     */
    private static function define(EventDefinition $definition): void
    {
        $catalogue = new EventCatalogue;

        $catalogue->define($definition);

        $recorder = new Recorder($catalogue, new ContributorRegistry);

        app()->instance(EventCatalogue::class, $catalogue);
        app()->instance(Recorder::class, $recorder);

        AuditLog::swap($recorder);
    }
}
