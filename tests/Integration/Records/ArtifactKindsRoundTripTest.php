<?php

declare(strict_types = 1);

namespace Tests\Integration\Records;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Encryption\StringEncrypter;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Delivery\OutboxDrainer;
use SineMacula\Laravel\AuditLog\Delivery\Replayer;
use SineMacula\Laravel\AuditLog\Integrity\ManifestVerifier;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Records\Attachment;
use SineMacula\Laravel\AuditLog\Records\Enums\ArtifactKind;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Stores\FailureSpill;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Concerns\InteractsWithOutbox;
use Tests\Concerns\SeedsTheOutbox;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Records\RecordFactory;
use Tests\Fixtures\Stores\DocumentedSpillChannel;
use Tests\TestCase;

/**
 * Integration tests for storing, draining and replaying every artifact kind.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Attachment::class)]
final class ArtifactKindsRoundTripTest extends TestCase
{
    use InteractsWithAuditStore, InteractsWithOutbox, SeedsTheOutbox;

    /** @var string When each test starts. */
    private const string NOW = '2026-11-01T12:00:00.000000Z';

    /** @var string The documented spill channel's name. */
    private const string SPILL_CHANNEL = 'audit-spill';

    /** @var string The documented channel's file. */
    private string $file = '';

    /**
     * Freeze the clock, silence reports, and spill to a file of the test's own.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->moveClockTo(self::NOW);

        app()->instance(ExceptionHandler::class, new RecordingExceptionHandler);

        $file = tempnam(sys_get_temp_dir(), 'audit-log-spill');

        self::assertIsString($file);

        $this->file = $file;

        app(ConfigRepository::class)->set([
            'logging.channels.' . self::SPILL_CHANNEL => DocumentedSpillChannel::config($this->file),
            'audit-log.failure.log_channel'           => self::SPILL_CHANNEL,
        ]);
    }

    /**
     * Put the clock back and remove the file.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();

        if (is_file($this->file)) {
            unlink($this->file);
        }

        parent::tearDown();
    }

    /**
     * Rows of `[kind, members]`: an artifact of each kind, holding members.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\AuditLog\Records\Enums\ArtifactKind, 1: int}>
     */
    public static function provideKinds(): iterable
    {
        yield from [
            'a bulk operation' => [ArtifactKind::BULK, 3],
            'a disclosure'     => [ArtifactKind::DISCLOSURE, 3],
            'an export'        => [ArtifactKind::EXPORT, 2],
        ];
    }

    /**
     * The database store writes an artifact of each kind with its entry.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\ArtifactKind  $kind
     * @param  int  $members
     * @return void
     */
    #[DataProvider('provideKinds')]
    public function testEachKindIsStoredWithItsEntry(ArtifactKind $kind, int $members): void
    {
        $record = self::recordOf($kind, $members);

        $this->store()->store($record);

        $this->assertStoredWhole($record, $kind, $members);
    }

    /**
     * An artifact of each kind drains from the outbox once, and the row goes.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\ArtifactKind  $kind
     * @param  int  $members
     * @return void
     */
    #[DataProvider('provideKinds')]
    public function testEachKindIsDrainedFromTheOutboxWhole(ArtifactKind $kind, int $members): void
    {
        $record = self::recordOf($kind, $members);

        $this->outboxModeOn();
        $this->enqueue($record);

        self::assertSame(1, app(OutboxDrainer::class)->drain(100, false)->delivered());
        self::assertSame(0, $this->outboxCount());

        $this->assertStoredWhole($record, $kind, $members);
    }

    /**
     * An artifact of each kind replays from the spill file once, and only once.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\ArtifactKind  $kind
     * @param  int  $members
     * @return void
     */
    #[DataProvider('provideKinds')]
    public function testEachKindIsReplayedFromTheSpillWhole(ArtifactKind $kind, int $members): void
    {
        $record = self::recordOf($kind, $members);

        app(FailureSpill::class)->spillFinalised($record);

        self::assertSame(0, $this->entryCount());
        self::assertSame(1, app(Replayer::class)->spill($this->file, false)->replayed());

        $this->assertStoredWhole($record, $kind, $members);

        app(Replayer::class)->spill($this->file, false);

        self::assertSame(1, $this->entryCount());
        self::assertSame(1, $this->artifactCount());
    }

    /**
     * An empty disclosure and export store, drain and replay with a count of 0.
     *
     * @return void
     */
    public function testAnEmptyDisclosureIsStoredDrainedAndReplayed(): void
    {
        foreach ([ArtifactKind::DISCLOSURE, ArtifactKind::EXPORT] as $kind) {
            $stored   = self::recordOf($kind, 0);
            $drained  = self::recordOf($kind, 0);
            $replayed = self::recordOf($kind, 0);

            $this->store()->store($stored);

            $this->outboxModeOn();
            $this->enqueue($drained);

            app(OutboxDrainer::class)->drain(100, false);
            app(FailureSpill::class)->spillFinalised($replayed);
            app(Replayer::class)->spill($this->file, false);

            foreach ([$stored, $drained, $replayed] as $record) {
                $this->assertArtifactWhole($record, $kind, 0);
            }

            $this->storageConnection()->table(EntrySettings::artifactsTable())->delete();
            $this->storageConnection()->table(EntrySettings::table())->delete();

            file_put_contents($this->file, '');
        }
    }

    /**
     * Assert the record is stored whole and once: one entry and one artifact.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\ArtifactKind  $kind
     * @param  int  $members
     * @return void
     */
    private function assertStoredWhole(FinalisedRecord $record, ArtifactKind $kind, int $members): void
    {
        self::assertSame(1, $this->entryCount());
        self::assertSame(1, $this->artifactCount());

        $this->assertArtifactWhole($record, $kind, $members);
    }

    /**
     * Assert the entry verifies and the artifact is stored as sealed, its
     * members opening to the canonical form.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\ArtifactKind  $kind
     * @param  int  $members
     * @return void
     */
    private function assertArtifactWhole(FinalisedRecord $record, ArtifactKind $kind, int $members): void
    {
        $id         = $record->record->id;
        $attachment = $record->record->attachment;
        $artifact   = $this->storageConnection()->table(EntrySettings::artifactsTable())->where('entry_id', $id)->first();
        $entry      = $this->storageConnection()->table(EntrySettings::table())->where('id', $id)->first();

        self::assertNotNull($attachment);
        self::assertNotNull($attachment->members);
        self::assertNotNull($artifact, "The entry {$id} has no artifact.");
        self::assertNotNull($entry, "No entry is stored under {$id}.");
        self::assertTrue(app(RecordSigner::class)->verifies($this->storedRow($id)));

        self::assertSame(
            [$attachment->id, $id, $kind->value, $members, $attachment->digest],
            [$artifact->id, $artifact->entry_id, $artifact->kind, (int) $artifact->member_count, $artifact->digest],
        );

        // Each build has its own disclosure nonce, so compare the sealed form
        $encrypter = app(StringEncrypter::class);
        $stored    = $encrypter->decryptString((string) $artifact->members);

        self::assertSame($encrypter->decryptString($attachment->members), $stored);
        self::assertSame($attachment->digest, hash('sha256', $stored));
        self::assertSame(self::withoutNonce(RecordFactory::canonical($kind, $members)), self::withoutNonce($stored));

        $verifier   = app(ManifestVerifier::class);
        $descriptor = $verifier->descriptorOf((array) $entry);

        self::assertNotNull($descriptor);
        self::assertSame([], $verifier->findings([$id => $descriptor]));

        // An engine's JSON column may keep the keys in an order of its own
        ksort($descriptor);

        self::assertSame(['artifact_id' => $attachment->id, 'count' => $members, 'digest' => $attachment->digest, 'kind' => $kind->value], $descriptor);
    }

    /**
     * The canonical form with a disclosure's nonce blanked, to compare builds.
     *
     * @param  string  $canonical
     * @return string
     */
    private static function withoutNonce(string $canonical): string
    {
        return (string) preg_replace('/"nonce":"[0-9a-f]{64}"/', '"nonce":""', $canonical);
    }

    /**
     * A finalised record with an artifact of the kind and that many members.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\ArtifactKind  $kind
     * @param  int  $members
     * @return \SineMacula\Laravel\AuditLog\Records\FinalisedRecord
     */
    private static function recordOf(ArtifactKind $kind, int $members): FinalisedRecord
    {
        return RecordFactory::finalisedWithArtifact($kind, RecordFactory::canonical($kind, $members), $members);
    }
}
