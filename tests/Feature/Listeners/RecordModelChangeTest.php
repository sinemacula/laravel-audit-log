<?php

declare(strict_types = 1);

namespace Tests\Feature\Listeners;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Capture\CapturedEvents;
use SineMacula\Laravel\AuditLog\Capture\CaptureFailedException;
use SineMacula\Laravel\AuditLog\Capture\MapperRegistry;
use SineMacula\Laravel\AuditLog\Capture\ModelWatcher;
use SineMacula\Laravel\AuditLog\Events\AuditCaptureFailed;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Listeners\RecordModelChange;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Testing\FakeAuditStore;
use Tests\Concerns\CreatesWatchedModels;
use Tests\Fixtures\Capture\Models\HaltingInvoice;
use Tests\Fixtures\Capture\Models\PlainLine;
use Tests\Fixtures\Capture\Models\WatchedInvoice;
use Tests\Fixtures\Capture\Models\WatchedInvoiceRevision;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\TestCase;

/**
 * Feature tests for the listener that records a watched model's changes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecordModelChange::class)]
final class RecordModelChangeTest extends TestCase
{
    use CreatesWatchedModels;

    /** @var \SineMacula\Laravel\AuditLog\Testing\FakeAuditStore The store records reach. */
    private FakeAuditStore $fake;

    /** @var \Tests\Fixtures\Privacy\RecordingExceptionHandler What the application's reporter is asked to report. */
    private RecordingExceptionHandler $reporter;

    /** @var list<\SineMacula\Laravel\AuditLog\Events\AuditCaptureFailed> Every `AuditCaptureFailed` heard. */
    private array $failures = [];

    /**
     * Fake the store, bind the reporter and hear each capture failure.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->fake     = AuditLog::fake();
        $this->reporter = new RecordingExceptionHandler;

        $this->app?->instance(ExceptionHandler::class, $this->reporter);

        Event::listen(AuditCaptureFailed::class, function (AuditCaptureFailed $failure): void {
            $this->failures[] = $failure;
        });
    }

    /**
     * An unwatched model is ignored, saved or handed to the listener.
     *
     * @return void
     */
    public function testAnUnwatchedModelIsIgnored(): void
    {
        $line = PlainLine::query()->create(['description' => 'Widgets']);

        self::listener()->created($line);
        self::listener()->deleted($line);

        self::assertSame(0, $this->fake->count());
        self::assertSame([], $this->failures);
    }

    /**
     * A subclass of a watched class is not watched through its parent.
     *
     * @return void
     */
    public function testASubclassOfAWatchedModelIsIgnored(): void
    {
        $revision = WatchedInvoiceRevision::query()->create(['number' => 'REV-1']);

        self::listener()->created($revision);

        $revision->update(['number' => 'REV-2']);
        $revision->forceDelete();

        self::assertSame(0, $this->fake->count());
    }

    /**
     * Each method records its own change every time it is called.
     *
     * @return void
     */
    public function testEachMethodRecordsItsEvent(): void
    {
        $invoice = WatchedInvoice::query()->create(['number' => 'INV-1', 'amount' => 1250]);

        $invoice->update(['amount' => 990]);

        $this->fake->forget();

        $listener = self::listener();

        $listener->created($invoice);
        $listener->updated($invoice);
        $listener->deleted($invoice);
        $listener->forceDeleted($invoice);
        $listener->created($invoice);

        self::assertSame(['invoice.created', 'invoice.updated', 'invoice.deleted', 'invoice.force_deleted', 'invoice.created'], $this->codes());
    }

    /**
     * Each Eloquent event of a watched model gives one record.
     *
     * @return void
     */
    public function testEachChangeOfAWatchedModelIsRecorded(): void
    {
        $invoice = WatchedInvoice::query()->create(['number' => 'INV-1', 'amount' => 1250]);

        $invoice->update(['amount' => 990]);
        $invoice->delete();
        self::restores($invoice);
        $invoice->forceDelete();

        self::assertSame(['invoice.created', 'invoice.updated', 'invoice.deleted', 'invoice.restored', 'invoice.force_deleted'], $this->codes());
        self::assertSame([], $this->failures);
    }

    /**
     * A model naming no connection waits for the default connection's commit.
     *
     * @return void
     */
    public function testAModelWithoutAConnectionNameWaitsForTheDefaultConnectionsName(): void
    {
        $this->useSecondModelConnection();

        $config  = app(ConfigRepository::class);
        $default = DB::connection(self::MODELS_CONNECTION);
        $testing = DB::connection(self::CONNECTION);
        $named   = [];

        Event::listen('eloquent.created: ' . WatchedInvoice::class, static function (WatchedInvoice $invoice) use (&$named): void {
            $named[] = $invoice->getConnectionName();
        });

        $config->set('database.default', self::MODELS_CONNECTION);

        try {
            $default->beginTransaction();
            $testing->beginTransaction();

            (new WatchedInvoice(['number' => 'INV-1']))->save();

            $testing->commit();

            self::assertSame([null], $named);
            self::assertSame(0, $this->fake->count());

            $default->commit();
        } finally {
            $config->set('database.default', self::CONNECTION);
        }

        self::assertSame(['invoice.created'], $this->codes());
    }

    /**
     * A failed capture names the model and listener and stops nothing after it.
     *
     * @return void
     */
    public function testAFailureNamesTheModelAndTheListener(): void
    {
        $invoice = WatchedInvoice::query()->create(['number' => 'INV-1', 'amount' => 1250]);
        $heard   = 0;

        Event::listen('eloquent.updated: ' . WatchedInvoice::class, static function () use (&$heard): void {
            $heard++;
        });

        $this->fake->forget();

        $invoice->makeHidden('amount')->update(['amount' => 990]);

        $expected = [WatchedInvoice::class, RecordModelChange::class, \LogicException::class];

        self::assertSame(0, $this->fake->count());
        self::assertCount(1, $this->failures);
        self::assertSame($expected, [$this->failures[0]->eventClass, $this->failures[0]->mapperClass, $this->failures[0]->exceptionClass]);
        self::assertCount(1, $this->reporter->reports());
        self::assertInstanceOf(CaptureFailedException::class, $this->reporter->reports()[0]);
        self::assertSame(1, $heard);
        self::assertSame(990, WatchedInvoice::query()->value('amount'));
    }

    /**
     * A model whose custom events halt Eloquent's own records nothing.
     *
     * @return void
     */
    public function testACustomEventThatStopsTheFallbackRecordsNothing(): void
    {
        $invoice = HaltingInvoice::query()->create(['number' => 'INV-1']);

        $invoice->update(['number' => 'INV-2']);
        $invoice->delete();

        self::assertSame(0, $this->fake->count());
        self::assertSame(0, HaltingInvoice::query()->count());

        self::listener()->created($invoice);

        self::assertSame(['halting_invoice.created'], $this->codes());
    }

    /**
     * Bind the watcher and capture state as the provider does; watch invoices.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        app()->singletonIf(ModelWatcher::class);
        app()->instance(MapperRegistry::class, new MapperRegistry);
        app()->scopedIf(CapturedEvents::class);

        app()->booting(static function (Application $app): void {
            $watcher = $app->make(ModelWatcher::class);

            $watcher->watch(WatchedInvoice::class, 'invoice', ['number', 'amount']);
            $watcher->watch(HaltingInvoice::class, 'halting_invoice', ['number']);
        });
    }

    /**
     * The codes of the records written, in order.
     *
     * @return list<string>
     */
    private function codes(): array
    {
        return array_map(static fn (AuditRecord $record): string => $record->event, $this->fake->recorded());
    }

    /**
     * The listener, as the dispatcher makes it.
     *
     * @return \SineMacula\Laravel\AuditLog\Listeners\RecordModelChange
     */
    private static function listener(): RecordModelChange
    {
        return app(RecordModelChange::class);
    }

    /**
     * Whether restoring the invoice, as Eloquent does, restored it.
     *
     * @param  \Tests\Fixtures\Capture\Models\WatchedInvoice  $invoice
     * @return bool
     */
    private static function restores(WatchedInvoice $invoice): bool
    {
        // Larastan's soft-delete stub declares the builder's static restore()
        // @phpstan-ignore staticMethod.dynamicCall
        return $invoice->restore();
    }
}
