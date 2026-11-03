<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Encryption\EncryptException;
use Illuminate\Contracts\Encryption\StringEncrypter;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Capture\CapturedEvents;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Delivery\CaptureSignal;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\RecordPipeline;
use SineMacula\Laravel\AuditLog\Records\Attachment;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\EventCode;
use SineMacula\Laravel\AuditLog\Records\Manifest;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException;
use SineMacula\Laravel\AuditLog\Testing\FakeAuditStore;
use Tests\Fixtures\Contributors\TenantContributor;
use Tests\Fixtures\Definitions\Enums\InvoiceActivity;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Records\RecordFactory;
use Tests\Fixtures\Stores\CallbackStore;
use Tests\TestCase;

/**
 * Feature tests for the record pipeline every write runs, explicit or captured:
 * the definition, the timing's checks, the contributors, minimising,
 * sealing a manifest, and delivery; the default timing of each kind of record;
 * the refusals that leave the builder usable, a write while a mapper runs among
 * them; and the definitions and contributors it was made with.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecordPipeline::class)]
final class RecordPipelineTest extends TestCase
{
    /** @var string The code most tests record. */
    private const string CODE = 'invoice.approved';

    /** @var string The code a bulk record is written under. */
    private const string BULK_CODE = 'invoice.bulk_approved';

    /** @var string Why a write while a mapper runs is refused. */
    private const string WRITE_WHILE_MAPPING = 'A record is never written while an event mapper runs; the mapper returns its builder and the capture writes it.';

    /** @var \SineMacula\Laravel\AuditLog\Testing\FakeAuditStore The store records reach. */
    private FakeAuditStore $fake;

    /** @var list<string> The class each capture's signal was told, in order. */
    private array $signalled = [];

    /**
     * Fake the store.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->fake = AuditLog::fake();
    }

    /**
     * Roll back any transaction a test left open.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $connection = DB::connection(self::CONNECTION);

        while ($connection->transactionLevel() > 0) {
            $connection->rollBack();
        }

        parent::tearDown();
    }

    /**
     * A write runs every stage: the registered definition's version and
     * category, a contributor's tenant, minimising that drops an unlisted
     * field, and delivery to the store of the record returned.
     *
     * @return void
     */
    public function testItRunsTheDefinitionContributorsMinimiserAndDelivery(): void
    {
        $pipeline = self::pipeline(TenantContributor::class);
        $pending  = (new PendingRecord)->event(InvoiceActivity::APPROVED)->withProperties(['amount' => '1200.00', 'note' => 'unlisted']);

        $record = $pipeline->write($pending);

        self::assertSame(2, $record->eventVersion);
        self::assertSame('finance', $record->category);
        self::assertSame(TenantContributor::ID, $record->tenantId);
        self::assertSame('1200.00', $record->properties['amount'] ?? null);
        self::assertArrayNotHasKey('note', $record->properties ?? []);
        self::assertTrue($pending->isConsumed());
        self::assertSame([$record], $this->fake->recorded());
    }

    /**
     * An explicit record with no timing of its own waits for the transaction to
     * commit.
     *
     * @return void
     */
    public function testAnExplicitRecordDefaultsToAfterCommit(): void
    {
        DB::connection(self::CONNECTION)->transaction(function (): void {
            self::pipeline()->write((new PendingRecord)->event(self::CODE));

            self::assertSame(0, $this->fake->count());
        });

        self::assertSame(1, $this->fake->count());
    }

    /**
     * A captured record with no timing of its own is written at once, inside
     * the transaction, and its signal is told nothing.
     *
     * @return void
     */
    public function testACapturedRecordDefaultsToImmediate(): void
    {
        $signal = $this->signal();

        DB::connection(self::CONNECTION)->transaction(function () use ($signal): void {
            self::pipeline()->write((new PendingRecord)->event(self::CODE), $signal);

            self::assertSame(1, $this->fake->count());
        });

        self::assertFalse($signal->isDeferred());
        self::assertSame([], $this->signalled);
    }

    /**
     * A captured record that chose to wait for the commit, as the package's
     * model source does, keeps that timing, and its signal says it is deferred.
     *
     * @return void
     */
    public function testACapturedRecordKeepsTheTimingItChose(): void
    {
        $signal = $this->signal();

        DB::connection(self::CONNECTION)->transaction(function () use ($signal): void {
            self::pipeline()->write((new PendingRecord)->event(self::CODE)->afterCommit(), $signal);

            self::assertSame(0, $this->fake->count());
            self::assertTrue($signal->isDeferred());
        });

        self::assertSame(1, $this->fake->count());
    }

    /**
     * A bulk record's manifest is sealed before the record is delivered: what
     * the store receives carries the attachment, its members encrypted, and the
     * descriptor the record signs.
     *
     * @return void
     */
    public function testAManifestIsSealedBeforeDelivery(): void
    {
        $manifest = self::manifest();

        self::pipeline()->write((new PendingRecord)->event(self::BULK_CODE)->withManifest($manifest)->immediately());

        $stored     = $this->fake->recorded()[0] ?? null;
        $attachment = $stored?->attachment;

        self::assertInstanceOf(AuditRecord::class, $stored);
        self::assertInstanceOf(Attachment::class, $attachment);
        self::assertNotSame($manifest->canonical, $attachment->members);
        self::assertSame($manifest->canonical, RecordFactory::encrypter()->decryptString($attachment->members));
        self::assertSame(['artifact_id' => $manifest->id, 'digest' => $manifest->digest, 'count' => $manifest->count], $stored->properties['_audit']['manifest'] ?? null);
    }

    /**
     * The attachment is the manifest's own artifact: its id, kind, count and
     * digest, and the record returned is the one carrying it.
     *
     * @return void
     */
    public function testTheAttachmentIsTheManifestsArtifact(): void
    {
        $manifest = self::manifest();

        $record = self::pipeline()->write((new PendingRecord)->event(self::BULK_CODE)->withManifest($manifest));

        self::assertSame($manifest->id, $record->attachment?->id);
        self::assertSame(Attachment::KIND_BULK, $record->attachment->kind);
        self::assertSame(3, $record->attachment->memberCount);
        self::assertSame($manifest->digest, $record->attachment->digest);
        self::assertTrue($record->attachment->describes(['artifact_id' => $manifest->id, 'digest' => $manifest->digest, 'count' => 3]));
    }

    /**
     * A record with no manifest carries no attachment.
     *
     * @return void
     */
    public function testARecordWithoutAManifestHasNoAttachment(): void
    {
        self::assertNull(self::pipeline()->write((new PendingRecord)->event(self::CODE))->attachment);
    }

    /**
     * A builder with no code is refused before anything is consumed or stored,
     * whether explicit or captured.
     *
     * @return void
     */
    public function testAMissingCodeIsRefused(): void
    {
        foreach ([null, $this->signal()] as $capture) {
            $pending = (new PendingRecord)->on(Reference::of('invoice', '42'));

            try {
                self::pipeline()->write($pending, $capture);

                self::fail('Expected a builder with no code to be refused.');
            } catch (\LogicException $exception) {
                self::assertSame('A pending record needs an event code before it is recorded; set one with `event()`.', $exception->getMessage());
            }

            self::assertFalse($pending->isConsumed());
        }

        self::assertSame(0, $this->fake->count());
    }

    /**
     * An encrypter that cannot seal the manifest is a refusal: nothing is
     * stored and the builder stays usable, so it is written once an encrypter
     * can seal it.
     *
     * @return void
     */
    public function testAnUnencryptableManifestLeavesTheBuilderUsable(): void
    {
        $real    = app(StringEncrypter::class);
        $pending = (new PendingRecord)->event(self::BULK_CODE)->withManifest(self::manifest());

        $this->app?->instance(StringEncrypter::class, self::failingEncrypter());

        try {
            self::pipeline()->write($pending);

            self::fail('Expected the encrypter\'s failure to refuse the write.');
        } catch (EncryptException $exception) {
            self::assertSame('The encrypter is down.', $exception->getMessage());
        }

        self::assertFalse($pending->isConsumed());
        self::assertSame(0, $this->fake->count());

        $this->app?->instance(StringEncrypter::class, $real);

        self::pipeline()->write($pending);

        self::assertSame(1, $this->fake->count());
    }

    /**
     * A captured record that is fail-closed, or transactional, is refused
     * before anything is consumed and before any contributor runs.
     *
     * @return void
     */
    public function testACaptureIsRefusedFailClosedBeforeAnythingIsConsumed(): void
    {
        $connection = DB::connection(self::CONNECTION);
        $builders   = [
            'fail-closed'   => (new PendingRecord)->event(self::CODE)->failClosed(),
            'transactional' => (new PendingRecord)->event(self::CODE)->transactional(),
        ];

        $connection->beginTransaction();

        foreach ($builders as $kind => $pending) {
            try {
                self::pipeline(TenantContributor::class)->write($pending, $this->signal());

                self::fail(sprintf('Expected a %s capture to be refused.', $kind));
            } catch (\LogicException $exception) {
                self::assertSame('A captured record is written immediately or after commit, never fail-closed or transactional.', $exception->getMessage(), $kind);
            }

            self::assertFalse($pending->isConsumed(), $kind);
            self::assertNull($pending->snapshot()->tenant, $kind);
        }

        $connection->rollBack();

        self::assertSame(0, $this->fake->count());
        self::assertSame([], $this->signalled);
    }

    /**
     * While a mapper runs an explicit write is refused before anything is
     * consumed, and the same builder is written once the window has closed. A
     * captured write, which comes with its capture's signal, is written inside
     * the window, since it is a capture of its own the mapper set off.
     *
     * @return void
     */
    public function testOnlyAnExplicitWriteIsRefusedWhileAMapperRuns(): void
    {
        $events   = app(CapturedEvents::class);
        $pending  = (new PendingRecord)->event(self::CODE)->immediately();
        $captured = (new PendingRecord)->event(self::CODE);

        [$refusal, $written] = $events->whileMapping(function () use ($pending, $captured): array {
            try {
                self::pipeline()->write($pending);
            } catch (\LogicException $exception) {
                $refusal = $exception->getMessage();
            }

            return [$refusal ?? null, self::pipeline()->write($captured, $this->signal())];
        });

        self::assertSame(self::WRITE_WHILE_MAPPING, $refusal);
        self::assertFalse($pending->isConsumed());
        self::assertTrue($captured->isConsumed());
        self::assertSame([$written], $this->fake->recorded());

        self::pipeline()->write($pending);

        self::assertSame(2, $this->fake->count());
    }

    /**
     * The refusal while a mapper runs comes first, before the code is read or
     * any contributor runs, so a builder with no code is refused for the write
     * and not for its code.
     *
     * @return void
     */
    public function testTheMappingRefusalComesBeforeAnyOther(): void
    {
        $pending = new PendingRecord;

        $message = app(CapturedEvents::class)->whileMapping(static function () use ($pending): string {
            try {
                self::pipeline(TenantContributor::class)->write($pending);
            } catch (\LogicException $exception) {
                return $exception->getMessage();
            }

            return '';
        });

        self::assertSame(self::WRITE_WHILE_MAPPING, $message);
        self::assertNull($pending->snapshot()->tenant);
    }

    /**
     * A pipeline writes with the definitions and contributors it was made with,
     * never the application's: a code defined only in its own catalogue takes
     * that definition, and its own contributor fills the tenant.
     *
     * @return void
     */
    public function testItUsesTheCatalogueAndContributorsItWasMadeWith(): void
    {
        $own = self::pipeline(TenantContributor::class);

        $record  = $own->write((new PendingRecord)->event(InvoiceActivity::APPROVED));
        $plain   = (new RecordPipeline(app(EventCatalogue::class), app(ContributorRegistry::class)))->write((new PendingRecord)->event(InvoiceActivity::APPROVED));
        $catalog = app(EventCatalogue::class);

        self::assertFalse($catalog->isRegistered(EventCode::of(InvoiceActivity::APPROVED)));
        self::assertSame('finance', $record->category);
        self::assertSame(TenantContributor::ID, $record->tenantId);
        self::assertSame('general', $plain->category);
        self::assertNull($plain->tenantId);
    }

    /**
     * A captured record's failed write follows the `REPORT` rule under the
     * `throw` mode: the record is returned, the failure reported once and its
     * signal told once, and nothing is thrown.
     *
     * @return void
     */
    public function testACapturedWriteFailureIsSignalledNotThrown(): void
    {
        $reporter = new RecordingExceptionHandler;
        $signal   = $this->signal();

        app(ConfigRepository::class)->set('audit-log.failure.mode', 'throw');

        $this->app?->instance(ExceptionHandler::class, $reporter);
        $this->app?->instance(AuditStore::class, CallbackStore::failingWith(new \RuntimeException('The store is down.')));

        $record = self::pipeline()->write((new PendingRecord)->event(self::CODE), $signal);

        self::assertSame(self::CODE, $record->event);
        self::assertTrue($signal->hasFailed());
        self::assertSame([\RuntimeException::class], $this->signalled);
        self::assertCount(1, $reporter->reports());
        self::assertInstanceOf(AuditWriteFailedException::class, $reporter->reports()[0]);
    }

    /**
     * Bind the scoped capture state as the provider does, so the pipeline and a
     * test share one mapping window.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        app()->scopedIf(CapturedEvents::class);
    }

    /**
     * A pipeline of a test's own, with the invoice definitions and the
     * contributors given.
     *
     * @param  class-string<\SineMacula\Laravel\AuditLog\Contracts\ContextContributor>  ...$contributors
     * @return \SineMacula\Laravel\AuditLog\RecordPipeline
     */
    private static function pipeline(string ...$contributors): RecordPipeline
    {
        $catalogue = new EventCatalogue;
        $registry  = new ContributorRegistry;

        $catalogue->define(InvoiceActivity::class);

        foreach ($contributors as $contributor) {
            $registry->add($contributor);
        }

        return new RecordPipeline($catalogue, $registry);
    }

    /**
     * The manifest of three invoices.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\Manifest
     */
    private static function manifest(): Manifest
    {
        return Manifest::of(RecordFactory::members(3), 100, 65536);
    }

    /**
     * An encrypter that fails to encrypt anything.
     *
     * @return \Illuminate\Contracts\Encryption\StringEncrypter
     */
    private static function failingEncrypter(): StringEncrypter
    {
        $encrypter = \Mockery::mock(StringEncrypter::class);

        $encrypter->shouldReceive('encryptString')->andThrow(new EncryptException('The encrypter is down.'));

        return $encrypter;
    }

    /**
     * A capture's signal that keeps the class of each failure it is told.
     *
     * @return \SineMacula\Laravel\AuditLog\Delivery\CaptureSignal
     */
    private function signal(): CaptureSignal
    {
        return new CaptureSignal(function (string $exceptionClass): void {
            $this->signalled[] = $exceptionClass;
        });
    }
}
