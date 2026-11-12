<?php

declare(strict_types = 1);

namespace Tests\Feature\Querying;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;
use SineMacula\Laravel\AuditLog\Contracts\FieldReader;
use SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Privacy\Enums\FieldState;
use SineMacula\Laravel\AuditLog\Querying\AuditTrail;
use SineMacula\Laravel\AuditLog\Querying\Describer;
use SineMacula\Laravel\AuditLog\Querying\EntryProjector;
use SineMacula\Laravel\AuditLog\Querying\TrailEntry;
use SineMacula\Laravel\AuditLog\Querying\TrailReader;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Records\Enums\ArtifactKind;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\InteractsWithReadWriteSplit;
use Tests\Concerns\ReadsTheTrail;
use Tests\Concerns\SeedsArtifacts;
use Tests\Fixtures\Capture\Models\SigningInUser;
use Tests\Fixtures\Privacy\RecordingFieldEncrypter;
use Tests\Fixtures\Querying\RevealingFieldReader;
use Tests\Fixtures\Records\RecordFactory;
use Tests\TestCase;

/**
 * Feature tests for what the trail shows as it is read.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TrailReader::class)]
#[CoversClass(EntryProjector::class)]
final class TrailReadingTest extends TestCase
{
    use InteractsWithReadWriteSplit, ReadsTheTrail, SeedsArtifacts;

    /** @var string The migration of the artifacts table, which a read's record needs. */
    private const string ARTIFACTS_MIGRATION = __DIR__ . '/../../../database/migrations/2026_11_02_000600_create_audit_log_artifacts_table.php';

    /** @var string A card number no shown entry may hold. */
    private const string CARD = '4242424242424242';

    /**
     * Bind the read path and a policy that lets the viewer see every entry.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->bindReading();
        $this->allowEverything();
    }

    /**
     * Remove the read/write split a test made.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->removeReadWriteSplit();

        parent::tearDown();
    }

    /**
     * A deleted user's history reads exactly as before.
     *
     * @return void
     */
    public function testADeletedUsersHistoryReadsAsBefore(): void
    {
        $this->createUsers();

        $user = SigningInUser::query()->create(['email' => 'ada@example.test', 'password' => SigningInUser::PASSWORD]);

        $this->actingAs($user);

        AuditLog::record('invoice.approved', Reference::of('invoice', 'inv_0042'));
        AuditLog::record('invoice.voided', Reference::of('invoice', 'inv_0042'));

        $before = $this->historyOf($user);

        $user->delete();

        self::assertFalse(SigningInUser::query()->whereKey($user->getKey())->exists());
        self::assertCount(2, $before);
        self::assertSame($before, $this->historyOf($user));
        self::assertSame(['type' => $user->getMorphClass(), 'id' => (string) $user->id], $before[0]['actor']);
    }

    /**
     * An encrypted property reads as `[ENCRYPTED]`, its ciphertext nowhere.
     *
     * @return void
     */
    public function testAnEncryptedPropertyReadsAsEncrypted(): void
    {
        $this->recordEncrypted();

        $entry = $this->trail()->forEvent('invoice.approved')->cursorPaginate()->entries[0];

        self::assertSame('[ENCRYPTED]', $entry->properties['card']);
        self::assertSame('[ENCRYPTED]', $entry->ip);

        foreach ([self::CARD, base64_encode(self::CARD), '203.0.113.7', base64_encode('203.0.113.7')] as $secret) {
            self::assertStringNotContainsString($secret, json_encode($entry->toArray(), JSON_THROW_ON_ERROR));
        }
    }

    /**
     * An erased field reads `[ERASED]` through the bound field reader.
     *
     * @return void
     */
    public function testAnErasedFieldReadsAsErasedThroughTheSeam(): void
    {
        $reader = new RevealingFieldReader(['properties.card' => FieldState::ERASED, 'ip' => FieldState::ERASED]);

        app()->instance(FieldReader::class, $reader);

        $this->recordEncrypted();

        $sealed = $this->trail()->forEvent('invoice.approved')->cursorPaginate()->entries[0];

        self::assertSame(['[ENCRYPTED]', '[ENCRYPTED]'], [$sealed->properties['card'], $sealed->ip]);
        self::assertSame(0, $reader->calls());

        $this->revealEverything();

        $entry = $this->trail()->forEvent('invoice.approved')->cursorPaginate()->entries[0];

        self::assertSame(['[ERASED]', '[ERASED]'], [$entry->properties['card'], $entry->ip]);
        self::assertSame(['properties.card', 'ip'], $reader->paths());
        self::assertSame(1, $reader->calls());
    }

    /**
     * The trail reads the replica of a read/write split, never the writer.
     *
     * @return void
     */
    public function testTheTrailIsNotReadYourWrites(): void
    {
        $this->useReadWriteSplit();
        $this->migrateArtifactsOnTheSplit();

        $id = $this->seedEntry();

        $unseen = $this->trail()->cursorPaginate()->entries;
        $row    = (array) DB::connection(self::PRIMARY_CONNECTION)->table(EntrySettings::table())->where('id', $id)->first();

        DB::connection(self::REPLICA_CONNECTION)->table(EntrySettings::table())->insert($row);

        $seen = $this->trail()->cursorPaginate()->entries;

        self::assertSame([], $unseen);
        self::assertSame([$id], array_map(static fn (TrailEntry $entry): string => $entry->id, $seen));
        self::assertSame(2, DB::connection(self::PRIMARY_CONNECTION)->table(EntrySettings::table())->where('event', 'audit_log.trail_read')->count());
        self::assertSame(0, DB::connection(self::REPLICA_CONNECTION)->table(EntrySettings::table())->where('event', 'audit_log.trail_read')->count());
    }

    /**
     * A described page never shows a concealed reason.
     *
     * @return void
     */
    public function testADescribedPageNeverShowsAConcealedReason(): void
    {
        AuditLog::record('account.sign_in_refused', null, ['concealed' => true, 'attempts' => 3], Outcome::DENIED, 'account_rate_limited');
        AuditLog::record('account.sign_in_refused', null, ['attempts' => 1], Outcome::DENIED, 'wrong_password');

        $entries      = $this->trail()->forEvent('account.sign_in_refused')->cursorPaginate()->entries;
        $describer    = app(Describer::class);
        $descriptions = array_map(static fn (TrailEntry $entry): array => $describer->describe($entry)->toArray(), $entries);

        self::assertSame(['wrong_password', null], array_map(static fn (TrailEntry $entry): ?string => $entry->reason, $entries));
        self::assertSame(['wrong_password', null], array_column($descriptions, 'reason'));
        $shown = json_encode([array_map(static fn (TrailEntry $entry): array => $entry->toArray(), $entries), $descriptions], JSON_THROW_ON_ERROR);

        self::assertStringNotContainsString('account_rate_limited', $shown);
    }

    /**
     * A bulk entry shows its manifest's descriptor and nothing else.
     *
     * @return void
     */
    public function testTheBulkManifestIsADescriptorOnly(): void
    {
        $id       = $this->seedBundle(3);
        $artifact = $this->artifactOf($id);

        $this->captureQueries();

        $entry = $this->trail()->cursorPaginate()->entries[0];
        $shown = json_encode($entry->toArray(), JSON_THROW_ON_ERROR);
        $reads = array_map(static fn (QueryExecuted $query): string => $query->sql, $this->capturedQueries());

        self::assertSame($id, $entry->id);
        self::assertSame(['kind', 'count', 'digest'], array_keys($entry->manifest ?? []));
        self::assertSame([ArtifactKind::BULK->value, 3], [$entry->manifest['kind'] ?? null, $entry->manifest['count'] ?? null]);
        self::assertArrayNotHasKey('_audit', $entry->properties);
        self::assertIsArray($artifact);
        self::assertStringNotContainsString(RecordFactory::MEMBER_TYPE, $shown);
        self::assertStringNotContainsString((string) $artifact['id'], $shown);
        $artifactReads = array_filter($reads, static fn (string $sql): bool => str_starts_with($sql, 'select') && str_contains($sql, EntrySettings::artifactsTable()));

        self::assertSame([], array_values($artifactReads));
    }

    /**
     * The trail read for the viewer.
     *
     * @return \SineMacula\Laravel\AuditLog\Querying\AuditTrail
     */
    private function trail(): AuditTrail
    {
        return app(AuditTrail::class)->visibleTo($this->viewer());
    }

    /**
     * Every entry the user acted in, as the trail shows it, newest first.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \Tests\Fixtures\Capture\Models\SigningInUser  $user
     * @return list<array<string, array<array-key, mixed>|int|string|null>>
     */
    private function historyOf(SigningInUser $user): array
    {
        return array_map(static fn (TrailEntry $entry): array => $entry->toArray(), $this->trail()->forActor($user)->cursorPaginate()->entries);
    }

    /**
     * Record an approved invoice with an encrypted card and address.
     *
     * @return void
     */
    private function recordEncrypted(): void
    {
        app(ConfigRepository::class)->set('audit-log.redaction.ip', 'encrypt');
        app()->instance(FieldEncrypter::class, new RecordingFieldEncrypter);

        $recorder = new Recorder(new EventCatalogue, new ContributorRegistry);
        $recorder->define(EventDefinition::for('invoice.approved')->encrypt('card', KeyOwner::ACTOR));

        AuditLog::swap($recorder);

        $pending = AuditLog::event('invoice.approved')->by(Reference::of('user', '42'))->withProperties(['card' => self::CARD]);
        $pending->fillClient('203.0.113.7', null);

        $pending->immediately()->record();
    }

    /**
     * Create the artifacts table on both sides of the split.
     *
     * @return void
     */
    private function migrateArtifactsOnTheSplit(): void
    {
        $config    = app(ConfigRepository::class);
        $migration = require self::ARTIFACTS_MIGRATION;

        assert($migration instanceof Migration && method_exists($migration, 'up'));

        foreach ([self::PRIMARY_CONNECTION, self::REPLICA_CONNECTION] as $connection) {
            $config->set('audit-log.storage.connection', $connection);
            $migration->up();
        }

        $config->set('audit-log.storage.connection', self::SPLIT_CONNECTION);
    }

    /**
     * Create the users' table, dropped before the application is destroyed.
     *
     * @return void
     */
    private function createUsers(): void
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
}
