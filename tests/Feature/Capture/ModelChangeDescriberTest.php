<?php

declare(strict_types = 1);

namespace Tests\Feature\Capture;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\Connection;
use Illuminate\Database\Eloquent\Casts\AsArrayObject;
use Illuminate\Database\Eloquent\Casts\AsEncryptedArrayObject;
use Illuminate\Database\Eloquent\Casts\AsEncryptedCollection;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Fluent;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Capture\CapturedEvents;
use SineMacula\Laravel\AuditLog\Capture\CaptureFailedException;
use SineMacula\Laravel\AuditLog\Capture\Enums\ModelEvent;
use SineMacula\Laravel\AuditLog\Capture\MapperRegistry;
use SineMacula\Laravel\AuditLog\Capture\ModelChangeDescriber;
use SineMacula\Laravel\AuditLog\Capture\ModelWatch;
use SineMacula\Laravel\AuditLog\Capture\ModelWatcher;
use SineMacula\Laravel\AuditLog\Contracts\FieldEncrypter;
use SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling;
use SineMacula\Laravel\AuditLog\Events\AuditCaptureFailed;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Listeners\RecordModelChange;
use SineMacula\Laravel\AuditLog\Privacy\Redactor;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\Enums\Timing;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Testing\FakeAuditStore;
use Tests\Concerns\CreatesWatchedModels;
use Tests\Fixtures\Capture\Models\PlainLine;
use Tests\Fixtures\Capture\Models\SealedLine;
use Tests\Fixtures\Capture\Models\WatchedInvoice;
use Tests\Fixtures\Capture\Models\WatchedInvoiceRevision;
use Tests\Fixtures\Definitions\Enums\InvoiceActivity;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Privacy\RecordingFieldEncrypter;
use Tests\TestCase;

/**
 * Feature tests for how a watched model's change is described through its
 * Eloquent events.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ModelChangeDescriber::class)]
final class ModelChangeDescriberTest extends TestCase
{
    use CreatesWatchedModels;

    /** @var string A connection the database manager makes with no name. */
    private const string NAMELESS = 'nameless';

    /** @var string The stored form of the issue time the tests set. */
    private const string ISSUED_AT = '2026-11-03 09:30:00';

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
     * The describer is a utility container and cannot be built.
     *
     * @SuppressWarnings("php:S3011")
     *
     * @return void
     */
    public function testConstructorIsPrivate(): void
    {
        $constructor = new \ReflectionMethod(ModelChangeDescriber::class, '__construct');

        self::assertTrue($constructor->isPrivate());

        $constructor->invoke((new \ReflectionClass(ModelChangeDescriber::class))->newInstanceWithoutConstructor());
    }

    /**
     * A creation keeps the watched fields it set, as set, and nothing else.
     *
     * @return void
     */
    public function testCreatingSnapshotsTheWatchedAttributes(): void
    {
        self::invoice(['secret_note' => 'kept from view', 'token' => 'tok-123']);

        $record = $this->onlyRecord('invoice.created');

        self::assertSame(['number' => 'INV-1', 'status' => 'invoice.approved', 'amount' => 1250], $record->properties);
        $this->assertNoFailure();
    }

    /**
     * A creation that sets none of a watched field leaves it out.
     *
     * @return void
     */
    public function testACreationKeepsOnlyTheFieldsItSet(): void
    {
        WatchedInvoice::query()->create(['number' => 'INV-9']);

        self::assertSame(['number' => 'INV-9'], $this->onlyRecord('invoice.created')->properties);
    }

    /**
     * An update keeps each changed watched field, before and after, in watch
     * order.
     *
     * @return void
     */
    public function testUpdatingRecordsBeforeAndAfterOfChangedFields(): void
    {
        $invoice = self::invoice();

        $this->fake->forget();

        $invoice->update(['amount' => 990, 'secret_note' => 'changed', 'number' => 'INV-2']);

        self::assertSame(['changes' => [
            'number' => ['before' => 'INV-1', 'after' => 'INV-2'],
            'amount' => ['before' => 1250, 'after' => 990],
        ]], $this->onlyRecord('invoice.updated')->properties);
    }

    /**
     * A field changed to or from `null` keeps `null` on that side.
     *
     * @return void
     */
    public function testAFieldClearedOrSetKeepsNullOnItsSide(): void
    {
        $invoice = self::invoice();

        $this->fake->forget();

        $invoice->update(['amount' => null, 'issued_at' => self::ISSUED_AT]);

        self::assertSame(['changes' => [
            'amount'    => ['before' => 1250, 'after' => null],
            'issued_at' => ['before' => null, 'after' => self::ISSUED_AT],
        ]], $this->onlyRecord('invoice.updated')->properties);
    }

    /**
     * An update that changed no watched field records nothing.
     *
     * @return void
     */
    public function testAnUpdateOfUnwatchedFieldsRecordsNothing(): void
    {
        $invoice = self::invoice();

        $this->fake->forget();

        $invoice->update(['secret_note' => 'changed', 'token' => 'tok-456']);

        self::assertSame(0, $this->fake->count());
        $this->assertNoFailure();
    }

    /**
     * A soft deletion keeps the watched fields as they are stored.
     *
     * @return void
     */
    public function testASoftDeleteSnapshotsThePersistedValues(): void
    {
        $invoice = self::invoice();

        $this->fake->forget();

        $invoice->delete();

        self::assertSame(['number' => 'INV-1', 'status' => 'invoice.approved', 'amount' => 1250], $this->onlyRecord('invoice.deleted')->properties);
        self::assertSoftDeleted($invoice);
    }

    /**
     * A deletion keeps the stored values, never unsaved ones.
     *
     * @return void
     */
    public function testADeleteNeverShowsUnsavedDirtyValues(): void
    {
        $invoice = self::invoice();
        $line    = PlainLine::query()->create(['description' => 'Widgets', 'quantity' => 3]);

        $this->fake->forget();

        $invoice->number = 'UNSAVED';
        $invoice->delete();

        $line->description = 'Unsaved';
        $line->delete();

        self::assertSame(['invoice.deleted', 'line.deleted'], $this->codes());
        self::assertSame('INV-1', $this->fake->recorded()[0]->properties['number'] ?? null);
        self::assertSame(['description' => 'Widgets', 'quantity' => 3], $this->fake->recorded()[1]->properties);
    }

    /**
     * A force deletion is one record under its own code.
     *
     * @return void
     */
    public function testAForceDeleteIsOneForceDeletedRecord(): void
    {
        $invoice = self::invoice();

        $this->fake->forget();

        $invoice->forceDelete();

        self::assertSame(['number' => 'INV-1', 'status' => 'invoice.approved', 'amount' => 1250], $this->onlyRecord('invoice.force_deleted')->properties);
        self::assertSame(0, WatchedInvoice::withTrashed()->count());
    }

    /**
     * The deletion a force deletion runs through records nothing.
     *
     * @return void
     */
    public function testTheDeletedEventOfAForceDeleteRecordsNothing(): void
    {
        $invoice = self::invoice();
        $heard   = 0;

        Event::listen('eloquent.deleted: ' . WatchedInvoice::class, static function () use (&$heard): void {
            $heard++;
        });

        $this->fake->forget();

        $invoice->forceDelete();

        self::assertSame(1, $heard);
        self::assertSame(['invoice.force_deleted'], $this->codes());
    }

    /**
     * A force deletion of an instance hiding a watched field is refused once.
     *
     * @return void
     */
    public function testAForceDeleteOfAnUnsafeInstanceFailsOnce(): void
    {
        $invoice = self::invoice();

        $this->fake->forget();

        $invoice->makeHidden('number')->forceDelete();

        $this->assertRefused();
        self::assertSame(0, WatchedInvoice::withTrashed()->count());
    }

    /**
     * A deletion names the row by its stored key, never an unsaved one.
     *
     * @return void
     */
    public function testADeletionNamesTheStoredKeyNotAnUnsavedOne(): void
    {
        $soft     = self::invoice();
        $force    = self::invoice(['number' => 'INV-2']);
        $softKey  = $soft->getKey();
        $forceKey = $force->getKey();

        self::assertIsInt($softKey);
        self::assertIsInt($forceKey);

        $this->fake->forget();

        $soft->setAttribute('id', 900);
        $soft->delete();

        $force->setAttribute('id', 901);
        $force->forceDelete();

        self::assertSame(
            [['invoice.deleted', (string) $softKey], ['invoice.force_deleted', (string) $forceKey]],
            array_map(static fn (AuditRecord $record): array => [$record->event, $record->subjectId], $this->fake->recorded()),
        );
        self::assertSoftDeleted(WatchedInvoice::class, ['id' => $softKey]);
        self::assertSame([$softKey], WatchedInvoice::withTrashed()->pluck('id')->all());
    }

    /**
     * A hard deletion seals encrypted fields under the stored row's key.
     *
     * @return void
     */
    public function testAHardDeletionSealsForTheStoredRow(): void
    {
        $encrypter = new RecordingFieldEncrypter;

        $this->app?->instance(FieldEncrypter::class, $encrypter);

        $line   = SealedLine::query()->create(['description' => 'Widgets', 'quantity' => 3]);
        $stored = $line->getKey();

        self::assertIsInt($stored);

        $key = (string) $stored;

        $this->fake->forget();

        $line->setAttribute('id', 900);
        $line->delete();

        $record = $this->onlyRecord('sealed_line.deleted');
        $calls  = $encrypter->calls();

        self::assertSame([SealedLine::class, $key], [$record->subjectType, $record->subjectId]);
        self::assertSame($key, end($calls)[0]->id);
        self::assertSame(0, SealedLine::query()->count());
    }

    /**
     * Force deleting a trashed model records its deletion and force deletion
     * once each.
     *
     * @return void
     */
    public function testForceDeletingATrashedModelRecordsItOnce(): void
    {
        $invoice = self::invoice();

        $invoice->delete();
        $invoice->forceDelete();

        self::assertSame(['invoice.created', 'invoice.deleted', 'invoice.force_deleted'], $this->codes());
    }

    /**
     * A restore is one record under its own code with its changes, and no
     * update.
     *
     * @return void
     */
    public function testARestoreIsOneRestoredRecordWithItsChanges(): void
    {
        $invoice = self::invoice();

        $invoice->delete();

        $this->fake->forget();

        $invoice->number = 'INV-2';
        self::restores($invoice);

        self::assertSame([
            'number'  => 'INV-2',
            'status'  => 'invoice.approved',
            'amount'  => 1250,
            'changes' => ['number' => ['before' => 'INV-1', 'after' => 'INV-2']],
        ], $this->onlyRecord('invoice.restored')->properties);
        self::assertNotSoftDeleted($invoice);
    }

    /**
     * The deleted-at a restore clears is a change only when watched.
     *
     * @return void
     */
    public function testTheRestoresDeletedAtIsAChangeOnlyWhenWatched(): void
    {
        $invoice  = self::invoice();
        $revision = WatchedInvoiceRevision::query()->create(['number' => 'REV-1']);

        $invoice->delete();
        $revision->delete();

        $deletedAt = $revision->getRawOriginal('deleted_at');

        $this->fake->forget();

        self::restores($invoice);
        self::restores($revision);

        self::assertSame(['invoice.restored', 'invoice_revision.restored'], $this->codes());
        self::assertSame(['number' => 'INV-1', 'status' => 'invoice.approved', 'amount' => 1250], $this->fake->recorded()[0]->properties);

        self::assertIsString($deletedAt);
        self::assertSame([
            'number'     => 'REV-1',
            'deleted_at' => null,
            'changes'    => ['deleted_at' => ['before' => $deletedAt, 'after' => null]],
        ], $this->fake->recorded()[1]->properties);
    }

    /**
     * A cancelled restore records nothing, now or later.
     *
     * @return void
     */
    public function testACancelledRestoreRecordsNothing(): void
    {
        $invoice = self::invoice();

        $invoice->delete();

        Event::listen('eloquent.restoring: ' . WatchedInvoice::class, static fn (): bool => false);

        $this->fake->forget();

        self::assertFalse(self::restores($invoice));
        self::assertSame(0, $this->fake->count());
        self::assertSoftDeleted($invoice);

        $invoice->update(['amount' => 990]);

        self::assertSame(['invoice.updated'], $this->codes());
    }

    /**
     * Restoring a model that is not deleted records nothing.
     *
     * @return void
     */
    public function testRestoringAModelThatIsNotDeletedRecordsNothing(): void
    {
        $invoice = self::invoice();

        $this->fake->forget();

        self::assertTrue(self::restores($invoice));
        self::assertSame(0, $this->fake->count());
    }

    /**
     * An update of a deleted model that leaves it deleted is an update.
     *
     * @return void
     */
    public function testAnUpdateOfADeletedModelIsAnUpdate(): void
    {
        $invoice = self::invoice();

        $invoice->delete();

        $this->fake->forget();

        $invoice->update(['amount' => 990]);

        self::assertSame(['invoice.updated'], $this->codes());
    }

    /**
     * A deletion its deleting listener cancels records nothing.
     *
     * @return void
     */
    public function testACancelledDeleteRecordsNothing(): void
    {
        $invoice = self::invoice();

        Event::listen('eloquent.deleting: ' . WatchedInvoice::class, static fn (): bool => false);

        $this->fake->forget();

        self::assertFalse($invoice->delete());
        self::assertSame(0, $this->fake->count());
        self::assertNotSoftDeleted($invoice);
    }

    /**
     * Deleting a hard-deleted model again records nothing.
     *
     * @return void
     */
    public function testDeletingAHardDeletedModelAgainRecordsNothing(): void
    {
        $line    = PlainLine::query()->create(['description' => 'Widgets']);
        $invoice = self::invoice();

        $line->delete();
        $invoice->forceDelete();

        $this->fake->forget();

        self::assertNull($line->delete());
        self::assertNull($invoice->delete());
        self::assertSame(0, $this->fake->count());
    }

    /**
     * Soft deleting a trashed model again is a second deletion.
     *
     * @return void
     */
    public function testSoftDeletingATrashedModelAgainIsASecondDeletion(): void
    {
        $invoice = self::invoice();

        $this->fake->forget();

        $invoice->delete();
        $invoice->delete();

        self::assertSame(['invoice.deleted', 'invoice.deleted'], $this->codes());
    }

    /**
     * Clearing a deleted-at column without soft deletes is an update.
     *
     * @return void
     */
    public function testADeletedAtColumnWithoutSoftDeletesIsAnUpdate(): void
    {
        $line = PlainLine::query()->create(['description' => 'Widgets', 'deleted_at' => '2026-01-01']);

        $this->fake->forget();

        $line->update(['deleted_at' => null]);

        self::assertSame(['changes' => ['deleted_at' => ['before' => '2026-01-01', 'after' => null]]], $this->onlyRecord('line.updated')->properties);
    }

    /**
     * Two saves are two records, each with the changes of its own save.
     *
     * @return void
     */
    public function testTwoSavesGiveTwoSnapshots(): void
    {
        $invoice = self::invoice();

        $this->fake->forget();

        $invoice->update(['amount' => 990]);
        $invoice->update(['amount' => 800]);

        self::assertSame(['invoice.updated', 'invoice.updated'], $this->codes());
        self::assertSame(['changes' => ['amount' => ['before' => 1250, 'after' => 990]]], $this->fake->recorded()[0]->properties);
        self::assertSame(['changes' => ['amount' => ['before' => 990, 'after' => 800]]], $this->fake->recorded()[1]->properties);
    }

    /**
     * A watched field the instance hides refuses the capture; the change goes
     * on.
     *
     * @return void
     */
    public function testAFieldTheInstanceHidesRefusesTheCapture(): void
    {
        $invoice = self::invoice();

        $this->fake->forget();

        $invoice->makeHidden('number')->update(['amount' => 990]);

        $this->assertRefused();
        self::assertSame(990, WatchedInvoice::query()->value('amount'));

        WatchedInvoice::query()->firstOrFail()->update(['amount' => 800]);

        self::assertSame(['invoice.updated'], $this->codes());
    }

    /**
     * A visible list that leaves out a watched field refuses the capture.
     *
     * @return void
     */
    public function testAVisibleListThatOmitsAFieldRefusesIt(): void
    {
        $invoice = self::invoice();

        $this->fake->forget();

        $invoice->setVisible(['id', 'number', 'status', 'issued_at'])->update(['number' => 'INV-2']);

        $this->assertRefused();

        $invoice->setVisible(['id', 'number', 'status', 'amount', 'issued_at'])->update(['number' => 'INV-3']);

        self::assertSame(['invoice.updated'], $this->codes());
    }

    /**
     * A field cast `encrypted` refuses the capture before it is described.
     *
     * @return void
     */
    public function testAnEncryptedCastRefusesTheCapture(): void
    {
        $this->assertDescriptionRefused('token');
    }

    /**
     * A field cast to an encrypted object refuses the capture.
     *
     * @return void
     */
    public function testAnEncryptedObjectCastRefusesTheCapture(): void
    {
        $this->assertDescriptionRefused('meta');
    }

    /**
     * An encrypted cast with arguments refuses the capture.
     *
     * @return void
     */
    public function testAnEncryptedCastWithArgumentsRefusesTheCapture(): void
    {
        $this->assertDescriptionRefused('lines');
    }

    /**
     * A field the class hides refuses the capture.
     *
     * @return void
     */
    public function testAFieldTheClassHidesRefusesTheCapture(): void
    {
        $this->assertDescriptionRefused('secret_note');
    }

    /**
     * Rows of `[cast, whether it encrypts]`.
     *
     * @return iterable<string, array{0: string, 1: bool}>
     */
    public static function provideCasts(): iterable
    {
        yield from [
            'encrypted'                        => ['encrypted', true],
            'encrypted as an array'            => ['encrypted:array', true],
            'encrypted as a collection'        => ['encrypted:collection', true],
            'encrypted in upper case'          => ['ENCRYPTED', true],
            'an encrypted object'              => [AsEncryptedArrayObject::class, true],
            'an encrypted collection'          => [AsEncryptedCollection::class, true],
            'an encrypted collection mapped'   => [AsEncryptedCollection::of(Fluent::class), true],
            'an application\'s encrypted cast' => ['App\Casts\AsEncryptedSecret:sha256', true],
            'a string'                         => ['string', false],
            'a date'                           => ['datetime:Y-m-d', false],
            'a plain object'                   => [AsArrayObject::class, false],
            'a cast whose class is not named'  => ['App\Casts\Encrypted', false],
            'an encrypted namespace'           => ['App\AsEncrypted\Plain', false],
            'an argument naming encryption'    => ['App\Casts\Hashed:AsEncrypted', false],
        ];
    }

    /**
     * A cast refuses a field exactly when it encrypts, read from the instance.
     *
     * @param  string  $cast
     * @param  bool  $encrypts
     * @return void
     */
    #[DataProvider('provideCasts')]
    public function testACastIsEncryptedOnlyByItsType(string $cast, bool $encrypts): void
    {
        $model = (new WatchedInvoice)->forceFill(['id' => 7])->mergeCasts(['number' => $cast]);

        $watch = ModelWatch::of(WatchedInvoice::class, 'invoice', ['number']);

        try {
            $described = ModelChangeDescriber::describe($watch, ModelEvent::FORCE_DELETED, $model, new PendingRecord);

            self::assertFalse($encrypts, 'Expected the encrypted cast to refuse the capture.');
            self::assertSame('invoice.force_deleted', $described?->snapshot()->code?->value);
        } catch (\LogicException $exception) {
            self::assertTrue($encrypts, $exception->getMessage());
        }
    }

    /**
     * An explicit handling lets a hidden or encrypted field be watched.
     *
     * @return void
     */
    public function testAnExplicitHandlingAllowsAHiddenField(): void
    {
        WatchedInvoiceRevision::query()->create(['number' => 'REV-1', 'secret_note' => 'kept from view', 'token' => 'tok-123']);

        self::assertSame(
            ['number' => 'REV-1', 'secret_note' => Redactor::MARKER, 'token' => Redactor::MARKER],
            $this->onlyRecord('invoice_revision.created')->properties,
        );
        $this->assertNoFailure();
    }

    /**
     * No accessor or appended attribute is read by a capture.
     *
     * @return void
     */
    public function testNoAccessorOrAppendIsRead(): void
    {
        $invoice = self::invoice();

        $invoice->update(['number' => 'INV-2']);
        $invoice->delete();

        self::assertSame(['invoice.created', 'invoice.updated', 'invoice.deleted'], $this->codes());
        self::assertSame('INV-2', $this->fake->recorded()[2]->properties['number'] ?? null);
        $this->assertNoFailure();

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(WatchedInvoice::READ);

        $invoice->toArray();
    }

    /**
     * Values are kept as stored, never cast or normalised.
     *
     * @return void
     */
    public function testValuesAreReadRaw(): void
    {
        $invoice = self::invoice(['issued_at' => Carbon::parse(self::ISSUED_AT)]);

        self::assertInstanceOf(InvoiceActivity::class, $invoice->status);
        self::assertSame(
            ['number' => 'INV-1', 'status' => 'invoice.approved', 'amount' => 1250, 'issued_at' => self::ISSUED_AT],
            $this->onlyRecord('invoice.created')->properties,
        );
    }

    /**
     * The subject of every change is the model, by its class and key.
     *
     * @return void
     */
    public function testTheSubjectIsTheModel(): void
    {
        $invoice = self::invoice();

        $invoice->forceDelete();

        $key = $invoice->getKey();

        self::assertIsInt($key);

        foreach ($this->fake->recorded() as $record) {
            self::assertSame([WatchedInvoice::class, (string) $key], [$record->subjectType, $record->subjectId], $record->event);
        }

        self::assertSame(2, $this->fake->count());
    }

    /**
     * A change waits for its own model's connection to commit.
     *
     * @return void
     */
    public function testTheDeliveryWaitsForTheModelsConnection(): void
    {
        $this->useSecondModelConnection();

        $connection = DB::connection(self::CONNECTION);

        $connection->beginTransaction();

        self::invoice();

        self::assertSame(0, $this->fake->count());

        $connection->commit();

        self::assertSame(['invoice.created'], $this->codes());

        DB::connection(self::MODELS_CONNECTION)->beginTransaction();

        self::invoice(['number' => 'INV-2']);

        self::assertSame(['invoice.created', 'invoice.created'], $this->codes());
    }

    /**
     * The builder waits for the model's connection by name, the default if
     * none.
     *
     * @return void
     */
    public function testTheBuilderWaitsForTheConnectionByName(): void
    {
        $this->useSecondModelConnection();

        $watch = ModelWatch::of(WatchedInvoice::class, 'invoice', ['number']);
        $model = (new WatchedInvoice)->forceFill(['id' => 7]);

        $default = ModelChangeDescriber::describe($watch, ModelEvent::CREATED, $model, new PendingRecord)?->snapshot();
        $other   = ModelChangeDescriber::describe($watch, ModelEvent::CREATED, $model->setConnection(self::MODELS_CONNECTION), new PendingRecord)?->snapshot();

        self::assertSame([Timing::AFTER_COMMIT, self::CONNECTION], [$default?->timing, $default?->connection]);
        self::assertSame([Timing::AFTER_COMMIT, self::MODELS_CONNECTION], [$other?->timing, $other?->connection]);
    }

    /**
     * A model whose connection has no name is refused.
     *
     * @return void
     */
    public function testAConnectionWithoutANameIsRefused(): void
    {
        app(ConfigRepository::class)->set('database.connections.' . self::NAMELESS, ['driver' => 'sqlite', 'database' => ':memory:']);

        DB::extend(self::NAMELESS, static fn (): Connection => new Connection(new \PDO('sqlite::memory:')));

        $model = (new WatchedInvoice)->setConnection(self::NAMELESS);

        self::assertNull($model->getConnection()->getName());

        // A connection without a name cannot be tracked by the transactions
        // manager, which keys its transactions by name, so it is left out
        $model->getConnection()->unsetTransactionManager();

        $watch = ModelWatch::of(WatchedInvoice::class, 'invoice', ['number']);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('The connection of `' . WatchedInvoice::class . '` has no name, so its change cannot wait for its commit.');

        ModelChangeDescriber::describe($watch, ModelEvent::CREATED, $model->forceFill(['id' => 7]), new PendingRecord);
    }

    /**
     * An update and a restore are told apart from the update itself.
     *
     * @return void
     */
    public function testARestoreIsToldFromTheUpdateWhicheverIsAsked(): void
    {
        $watch   = ModelWatch::of(WatchedInvoice::class, 'invoice', ['number']);
        $invoice = self::invoice();

        $invoice->update(['number' => 'INV-2']);

        self::assertSame('invoice.updated', ModelChangeDescriber::describe($watch, ModelEvent::RESTORED, $invoice, new PendingRecord)?->snapshot()->code?->value);

        $invoice->delete();
        self::restores($invoice);

        self::assertSame('invoice.restored', ModelChangeDescriber::describe($watch, ModelEvent::UPDATED, $invoice, new PendingRecord)?->snapshot()->code?->value);
    }

    /**
     * Bind the watcher and capture state as the provider does and watch the
     * models.
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

            $watcher->watch(WatchedInvoice::class, 'invoice', ['number', 'status', 'amount', 'issued_at']);
            $watcher->watch(WatchedInvoiceRevision::class, 'invoice_revision', ['number', 'deleted_at', 'secret_note' => FieldHandling::REDACT, 'token' => FieldHandling::REDACT]);
            $watcher->watch(PlainLine::class, 'line', ['description', 'quantity', 'deleted_at']);
            $watcher->watch(SealedLine::class, 'sealed_line', ['description' => FieldHandling::ENCRYPT, 'quantity']);
        });
    }

    /**
     * Assert describing the invoice's creation with the field watched is
     * refused.
     *
     * @param  string  $field
     * @return void
     */
    private function assertDescriptionRefused(string $field): void
    {
        $model   = (new WatchedInvoice)->forceFill(['id' => 7]);
        $pending = new PendingRecord;
        $watch   = ModelWatch::of(WatchedInvoice::class, 'invoice', ['number', $field]);

        try {
            ModelChangeDescriber::describe($watch, ModelEvent::CREATED, $model, $pending);
            self::fail('Expected the field to refuse the capture.');
        } catch (\LogicException $exception) {
            $message = 'The field `' . $field . '` of `' . WatchedInvoice::class . '` is hidden or encrypted on this instance, so it needs an explicit handling to be watched.';

            self::assertSame($message, $exception->getMessage());
        }

        self::assertNull($pending->snapshot()->code);
        self::assertSame([], $pending->snapshot()->properties ?? []);
    }

    /**
     * Assert the change was refused and contained, naming the model and
     * listener.
     *
     * @return void
     */
    private function assertRefused(): void
    {
        $expected = [WatchedInvoice::class, RecordModelChange::class, \LogicException::class];

        self::assertSame(0, $this->fake->count());
        self::assertCount(1, $this->reporter->reports());

        $report = $this->reporter->reports()[0];

        self::assertInstanceOf(CaptureFailedException::class, $report);
        self::assertSame($expected, [$report->eventClass, $report->mapperClass, $report->exceptionClass]);
        self::assertCount(1, $this->failures);
        self::assertSame($expected, [$this->failures[0]->eventClass, $this->failures[0]->mapperClass, $this->failures[0]->exceptionClass]);
    }

    /**
     * Assert no capture failed.
     *
     * @return void
     */
    private function assertNoFailure(): void
    {
        self::assertSame([], $this->failures);
        self::assertSame([], $this->reporter->reports());
    }

    /**
     * The one record written, asserting it is the only one and has the code.
     *
     * @param  string  $code
     * @return \SineMacula\Laravel\AuditLog\Records\AuditRecord
     */
    private function onlyRecord(string $code): AuditRecord
    {
        self::assertSame([$code], $this->codes());

        return $this->fake->recorded()[0];
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
     * A saved invoice with the attributes given.
     *
     * @param  array<string, \DateTimeInterface|scalar|null>  $attributes
     * @return \Tests\Fixtures\Capture\Models\WatchedInvoice
     */
    private static function invoice(array $attributes = []): WatchedInvoice
    {
        return WatchedInvoice::query()->create([
            'number' => 'INV-1',
            'status' => InvoiceActivity::APPROVED,
            'amount' => 1250,
            ...$attributes,
        ]);
    }

    /**
     * Whether restoring the invoice, as Eloquent does, restored it.
     *
     * @param  \Tests\Fixtures\Capture\Models\WatchedInvoice  $invoice
     * @return bool
     */
    private static function restores(WatchedInvoice $invoice): bool
    {
        // Larastan's stub of the soft-delete trait declares its query-builder
        // restore, which is static, over the model's own instance method
        // @phpstan-ignore staticMethod.dynamicCall
        return $invoice->restore();
    }
}
