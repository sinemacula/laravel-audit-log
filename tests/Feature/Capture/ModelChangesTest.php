<?php

declare(strict_types = 1);

namespace Tests\Feature\Capture;

use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Capture\ModelChangeDescriber;
use SineMacula\Laravel\AuditLog\Capture\ModelWatcher;
use SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling;
use SineMacula\Laravel\AuditLog\Events\AuditCaptureFailed;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Listeners\RecordModelChange;
use SineMacula\Laravel\AuditLog\Models\AuditEntry;
use SineMacula\Laravel\AuditLog\Privacy\Redactor;
use SineMacula\Laravel\AuditLog\Recorder;
use Tests\Concerns\CreatesWatchedModels;
use Tests\Fixtures\Capture\Models\HaltingInvoice;
use Tests\Fixtures\Capture\Models\PlainLine;
use Tests\Fixtures\Capture\Models\Tag;
use Tests\Fixtures\Capture\Models\TaggedInvoice;
use Tests\Fixtures\Capture\Models\WatchedInvoice;
use Tests\Fixtures\Capture\Models\WatchedInvoiceRevision;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\TestCase;

/**
 * Feature tests for watched models through the provider's wiring and Eloquent's
 * own events, each watch registered while the application boots: each change
 * written as one row under its code, a restore and a force delete one row each;
 * hidden and encrypted values never written; every path that changes a row
 * without a model event (query-builder writes, quiet saves, raw statements, a
 * plain pivot) and a custom event that stops the fallback writing nothing; a
 * subclass never watched through its parent; and the package's own read model
 * never watched.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecordModelChange::class)]
#[CoversClass(ModelChangeDescriber::class)]
#[CoversClass(ModelWatcher::class)]
final class ModelChangesTest extends TestCase
{
    use CreatesWatchedModels;

    /** @var string A note the invoice hides from view. */
    private const string HIDDEN_NOTE = 'kept-from-view-note';

    /** @var string A token the invoice casts encrypted. */
    private const string TOKEN = 'token-cast-encrypted';

    /** @var \Tests\Fixtures\Privacy\RecordingExceptionHandler What the application's reporter is asked to report. */
    private RecordingExceptionHandler $reporter;

    /** @var list<\SineMacula\Laravel\AuditLog\Events\AuditCaptureFailed> Every `AuditCaptureFailed` heard. */
    private array $failures = [];

    /** @var list<string> What each watch refused while the application booted said. */
    private array $refusals = [];

    /**
     * Create the tagged invoices' tables, bind the reporter, and hear each
     * capture failure.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createTaggedInvoiceTables();

        $this->reporter = new RecordingExceptionHandler;

        $this->app?->instance(ExceptionHandler::class, $this->reporter);

        Event::listen(AuditCaptureFailed::class, function (AuditCaptureFailed $failure): void {
            $this->failures[] = $failure;
        });
    }

    /**
     * Each change writes one row under its code, naming the model as subject: a
     * creation, an update, a soft delete, a restore and a force delete.
     *
     * @return void
     */
    public function testEachChangeRecordsItsCode(): void
    {
        $invoice = WatchedInvoice::query()->create(['number' => 'INV-1', 'amount' => 1250]);

        $invoice->update(['amount' => 990]);
        $invoice->delete();

        self::restore($invoice);

        $invoice->forceDelete();

        $entries = $this->entries();

        self::assertSame(
            ['invoice.created', 'invoice.updated', 'invoice.deleted', 'invoice.restored', 'invoice.force_deleted'],
            array_map(static fn (AuditEntry $entry): string => $entry->event, $entries),
        );

        foreach ($entries as $entry) {
            self::assertSame([WatchedInvoice::class, (string) $invoice->id, 'change'], [$entry->subject_type, $entry->subject_id, $entry->category]);
        }

        self::assertSame(['amount' => 1250, 'number' => 'INV-1'], self::sorted($entries[0]->properties));
        self::assertSame(['changes' => ['amount' => ['after' => 990, 'before' => 1250]]], self::sorted($entries[1]->properties));
        self::assertSame([], $this->failures);
    }

    /**
     * A hidden field and encrypted ones, each watched with an explicit
     * handling, never show their values: a snapshot writes each as its handling
     * says, and an update writes an encrypted field's before and after so,
     * while a field whose name the redactor masks is omitted from the changes
     * as a whole, the omission naming it. A field this instance hides with no
     * handling refuses the capture, which is said once, and the change itself
     * goes on.
     *
     * @return void
     */
    public function testHiddenAndEncryptedValuesNeverAppear(): void
    {
        $invoice = WatchedInvoice::query()->create(['number' => 'INV-1', 'secret_note' => self::HIDDEN_NOTE, 'token' => self::TOKEN, 'meta' => ['n' => self::HIDDEN_NOTE]]);

        $invoice->update(['secret_note' => self::HIDDEN_NOTE . '-2', 'token' => self::TOKEN . '-2', 'meta' => ['n' => self::TOKEN]]);

        [$created, $updated] = $this->entries();

        self::assertSame(
            ['meta' => Redactor::MARKER, 'number' => 'INV-1', 'secret_note' => Redactor::MARKER, 'token' => Redactor::MARKER],
            self::sorted($created->properties),
        );
        self::assertSame(
            [
                '_audit'  => ['omitted' => ['count' => 2, 'paths' => ['changes.secret_note', 'changes.token']]],
                'changes' => ['meta' => ['after' => Redactor::MARKER, 'before' => Redactor::MARKER]],
            ],
            self::sorted($updated->properties),
        );

        $line = (new PlainLine)->makeHidden('description');

        $line->fill(['description' => self::HIDDEN_NOTE, 'quantity' => 2])->save();

        self::assertSame(1, PlainLine::query()->count());
        self::assertCount(2, $this->entries());
        self::assertSame([[PlainLine::class, RecordModelChange::class, \LogicException::class]], array_map(
            static fn (AuditCaptureFailed $failure): array => [$failure->eventClass, $failure->mapperClass, $failure->exceptionClass],
            $this->failures,
        ));

        $stored = (string) json_encode(array_map(static fn (AuditEntry $entry): array => $entry->getRawOriginal(), $this->entries()));
        $said   = (string) json_encode([array_map(static fn (\Throwable $report): string => $report->getMessage(), $this->reporter->reports()), $this->failures]);

        foreach ([self::HIDDEN_NOTE, self::TOKEN] as $value) {
            self::assertStringNotContainsString($value, $stored);
            self::assertStringNotContainsString($value, $said);
        }
    }

    /**
     * Rows of `[a change no model event announces]`: query-builder writes, a
     * quiet save, a save without events, a raw statement and a plain pivot's
     * attachment, each given the saved invoice, the tagged invoice and the tag.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \Closure(\Tests\Fixtures\Capture\Models\WatchedInvoice, \Tests\Fixtures\Capture\Models\TaggedInvoice, \Tests\Fixtures\Capture\Models\Tag): void}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideModelGaps(): iterable
    {
        yield from [
            'a query-builder update' => [static function (WatchedInvoice $invoice): void {
                WatchedInvoice::query()->whereKey($invoice->id)->update(['amount' => 2]);
            }],
            'a query-builder delete' => [static function (WatchedInvoice $invoice): void {
                WatchedInvoice::query()->whereKey($invoice->id)->delete();
            }],
            'a query-builder insert' => [static function (): void {
                WatchedInvoice::query()->insert(['number' => 'INV-9', 'amount' => 9]);
            }],
            'a query-builder upsert' => [static function (WatchedInvoice $invoice): void {
                WatchedInvoice::query()->upsert([['id' => $invoice->id, 'number' => 'INV-U', 'amount' => 3]], ['id'], ['number']);
            }],
            'a query-builder increment' => [static function (WatchedInvoice $invoice): void {
                WatchedInvoice::query()->whereKey($invoice->id)->increment('amount');
            }],
            'saveQuietly()' => [static function (WatchedInvoice $invoice): void {
                $invoice->fill(['amount' => 5])->saveQuietly();
            }],
            'withoutEvents()' => [static function (WatchedInvoice $invoice): void {
                WatchedInvoice::withoutEvents(static fn (): bool => $invoice->update(['amount' => 6]));
            }],
            'a raw statement' => [static function (WatchedInvoice $invoice): void {
                DB::statement('update ' . WatchedInvoice::TABLE . ' set amount = 7 where id = ?', [$invoice->id]);
            }],
            'a plain pivot attach()' => [static function (WatchedInvoice $invoice, TaggedInvoice $tagged, Tag $tag): void {
                $tagged->tags()->attach($tag->id);
            }],
        ];
    }

    /**
     * Each change no model event announces writes nothing, though the tables
     * change: a gap of model capture, which `bulk()` or an explicit record
     * covers.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Closure(\Tests\Fixtures\Capture\Models\WatchedInvoice, \Tests\Fixtures\Capture\Models\TaggedInvoice, \Tests\Fixtures\Capture\Models\Tag): void  $change
     * @return void
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    #[DataProvider('provideModelGaps')]
    public function testTheGapsRecordNothing(\Closure $change): void
    {
        $invoice = WatchedInvoice::query()->create(['number' => 'INV-1', 'amount' => 1250]);
        $tagged  = TaggedInvoice::query()->create(['number' => 'TAG-1']);
        $tag     = Tag::query()->create(['name' => 'urgent']);
        $written = count($this->entries());
        $before  = self::tables();

        $change($invoice, $tagged, $tag);

        self::assertNotSame($before, self::tables(), 'The change changed nothing.');
        self::assertCount($written, $this->entries());
        self::assertSame(3, $written);
        self::assertSame([], $this->failures);
    }

    /**
     * A model whose custom event answers in place of Eloquent's own writes
     * nothing for its creation, update or deletion: a gap of model capture.
     *
     * @return void
     */
    public function testACustomEventThatStopsTheFallbackRecordsNothing(): void
    {
        $invoice = HaltingInvoice::query()->create(['number' => 'INV-1']);

        $invoice->update(['number' => 'INV-2']);
        $invoice->delete();

        self::assertSame(0, HaltingInvoice::query()->count());
        self::assertSame([], $this->entries());
        self::assertSame([], $this->failures);
    }

    /**
     * The package's read model is never watched: watching it is refused while
     * the application boots, and writing an entry writes only that entry.
     *
     * @return void
     */
    public function testNoModelEverRecordsAnAuditEntry(): void
    {
        self::assertSame(['The package\'s own models are never watched.'], $this->refusals);
        self::assertNull(app(ModelWatcher::class)->watchFor(AuditEntry::class));

        AuditLog::record('invoice.approved');

        self::assertSame(['invoice.approved'], array_map(static fn (AuditEntry $entry): string => $entry->event, $this->entries()));
    }

    /**
     * A subclass of a watched model is not watched through its parent: its
     * changes write nothing, while its parent's are recorded.
     *
     * @return void
     */
    public function testASubclassIsNotWatchedThroughItsParent(): void
    {
        $revision = WatchedInvoiceRevision::query()->create(['number' => 'REV-1']);

        $revision->update(['number' => 'REV-2']);
        $revision->delete();

        self::assertSame([], $this->codesSince(0));

        WatchedInvoice::query()->create(['number' => 'INV-1']);

        self::assertSame(['invoice.created'], $this->codesSince(0));
    }

    /**
     * A restore writes one restored row and no update, and a force delete one
     * force-deleted row and no deletion.
     *
     * @return void
     */
    public function testARestoreAndAForceDeleteGiveOneRowEach(): void
    {
        $invoice = WatchedInvoice::query()->create(['number' => 'INV-1']);

        $invoice->delete();

        $written = count($this->entries());

        self::restore($invoice);

        self::assertSame(['invoice.restored'], $this->codesSince($written));

        $invoice->forceDelete();

        self::assertSame(['invoice.restored', 'invoice.force_deleted'], $this->codesSince($written));
    }

    /**
     * A change inside a transaction is written when it commits, and a change
     * rolled back is never written.
     *
     * @return void
     */
    public function testAChangeWaitsForItsCommit(): void
    {
        DB::connection(self::CONNECTION)->transaction(function (): void {
            WatchedInvoice::query()->create(['number' => 'INV-1']);

            self::assertSame([], $this->entries());
        });

        self::assertCount(1, $this->entries());

        DB::connection(self::CONNECTION)->beginTransaction();

        WatchedInvoice::query()->create(['number' => 'INV-2']);

        DB::connection(self::CONNECTION)->rollBack();

        self::assertCount(1, $this->entries());
    }

    /**
     * Watch the models while the application boots, as an application's
     * provider would, noting what refusing to watch the package's read model
     * says.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        app()->booting(function (Application $app): void {
            $redacted = ['secret_note' => FieldHandling::REDACT, 'token' => FieldHandling::REDACT, 'meta' => FieldHandling::REDACT];

            AuditLog::watch(WatchedInvoice::class, as: 'invoice', fields: ['number', 'status', 'amount', ...$redacted]);
            AuditLog::watch(PlainLine::class, as: 'line', fields: ['description', 'quantity']);
            AuditLog::watch(HaltingInvoice::class, as: 'halting_invoice', fields: ['number']);
            AuditLog::watch(TaggedInvoice::class, as: 'tagged_invoice', fields: ['number']);
            AuditLog::watch(Tag::class, as: 'tag', fields: ['name']);

            try {
                $app->make(Recorder::class)->watch(AuditEntry::class, as: 'audit_entry', fields: ['event']);
            } catch (\LogicException $exception) {
                $this->refusals[] = $exception->getMessage();
            }
        });
    }

    /**
     * Every row written, oldest first.
     *
     * @return list<\SineMacula\Laravel\AuditLog\Models\AuditEntry>
     */
    private function entries(): array
    {
        return array_values(AuditEntry::query()->orderBy('recorded_at')->orderBy('id')->get()->all());
    }

    /**
     * The codes of the rows written after the number given, oldest first.
     *
     * @param  int  $written
     * @return list<string>
     */
    private function codesSince(int $written): array
    {
        return array_map(static fn (AuditEntry $entry): string => $entry->event, array_slice($this->entries(), $written));
    }

    /**
     * Every row of the watched invoices' and the pivot's tables, as one string,
     * so any change to either shows.
     *
     * @return string
     */
    private static function tables(): string
    {
        $connection = DB::connection(self::CONNECTION);

        return serialize([
            $connection->table(WatchedInvoice::TABLE)->orderBy('id')->get()->all(),
            $connection->table(TaggedInvoice::PIVOT_TABLE)->get()->all(),
        ]);
    }

    /**
     * Restore the invoice, as Eloquent does.
     *
     * @param  \Tests\Fixtures\Capture\Models\WatchedInvoice  $invoice
     * @return void
     */
    private static function restore(WatchedInvoice $invoice): void
    {
        // Larastan's stub of the soft-delete trait declares its query-builder
        // restore, which is static, over the model's own instance method
        // @phpstan-ignore staticMethod.dynamicCall
        $invoice->restore();
    }

    /**
     * The map with its keys sorted, at every depth.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  ?array<array-key, mixed>  $map
     * @return array<array-key, mixed>
     */
    private static function sorted(?array $map): array
    {
        $map ??= [];

        ksort($map);

        return array_map(static fn (mixed $value): mixed => is_array($value) ? self::sorted($value) : $value, $map);
    }

    /**
     * Create the tagged invoices', the tags' and the pivot's tables on the
     * test's connection, and drop them before the application is destroyed.
     *
     * @return void
     */
    private function createTaggedInvoiceTables(): void
    {
        $this->dropTaggedInvoiceTables();

        $schema = Schema::connection(self::CONNECTION);

        $schema->create(TaggedInvoice::TABLE, static function (Blueprint $table): void {
            $table->increments('id');
            $table->string('number', 32)->nullable();
        });

        $schema->create(Tag::TABLE, static function (Blueprint $table): void {
            $table->increments('id');
            $table->string('name', 64)->nullable();
        });

        $schema->create(TaggedInvoice::PIVOT_TABLE, static function (Blueprint $table): void {
            $table->unsignedInteger('tagged_invoice_id');
            $table->unsignedInteger('tag_id');
            $table->primary(['tagged_invoice_id', 'tag_id']);
        });

        $this->beforeApplicationDestroyed(function (): void {
            $this->dropTaggedInvoiceTables();
        });
    }

    /**
     * Drop the pivot's, the tags' and the tagged invoices' tables from the
     * test's connection.
     *
     * @return void
     */
    private function dropTaggedInvoiceTables(): void
    {
        $schema = Schema::connection(self::CONNECTION);

        $schema->dropIfExists(TaggedInvoice::PIVOT_TABLE);
        $schema->dropIfExists(Tag::TABLE);
        $schema->dropIfExists(TaggedInvoice::TABLE);
    }
}
