<?php

declare(strict_types = 1);

namespace Tests\Feature\Recording;

use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Route;
use Orchestra\Testbench\Attributes\DefineEnvironment;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Models\AuditEntry;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException;
use SineMacula\Laravel\AuditLog\Testing\FakeAuditStore;
use Symfony\Component\HttpFoundation\StreamedResponse;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Fixtures\Definitions\Enums\DisclosureActivity;
use Tests\TestCase;
use Tests\Unit\Stubs\StubAuthUser;
use Tests\Unit\Stubs\StubDocument;

/**
 * End-to-end tests for recording disclosures and denied access.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Recorder::class)]
final class AccessRecordsTest extends TestCase
{
    use InteractsWithAuditStore;

    /** @var string The code of a completed disclosure. */
    private const string CODE = 'document.downloaded';

    /** @var string The purpose a disclosure states. */
    private const string PURPOSE = 'legal_hold';

    /** @var string The channel a disclosure went through. */
    private const string CHANNEL = 'portal';

    /**
     * Surface a failure inside a route.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->withoutExceptionHandling();
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
     * A read served from a cache is still recorded on every request.
     *
     * @return void
     */
    public function testACachedReadIsRecorded(): void
    {
        $reads = 0;

        Route::get('/documents/1', static function () use (&$reads): string {
            $body = Cache::store('array')->remember('document-1', 60, static function () use (&$reads): string {
                $reads++;

                return 'the document';
            });

            AuditLog::accessed(self::CODE, subject: self::document(), purpose: self::PURPOSE, channel: self::CHANNEL)->record();

            return $body;
        });

        $this->get('/documents/1')->assertOk();
        $this->get('/documents/1')->assertOk();

        self::assertSame(1, $reads);
        self::assertSame(2, AuditEntry::query()->where('event', self::CODE)->count());
    }

    /**
     * A download records its subject, outcome, purpose and channel.
     *
     * @return void
     */
    public function testADownloadIsRecorded(): void
    {
        Route::get('/documents/1/download', static function (): StreamedResponse {
            AuditLog::accessed(self::CODE, subject: self::document(), purpose: self::PURPOSE, channel: self::CHANNEL)->record();

            return response()->streamDownload(static function (): void {
                echo 'the document';
            }, 'document.txt');
        })->name('documents.download');

        $this->get('/documents/1/download')->assertDownload('document.txt');

        $entry = AuditEntry::query()->where('event', self::CODE)->sole();

        self::assertSame('document', $entry->subject_type);
        self::assertSame('document-1', $entry->subject_id);
        self::assertSame('success', $entry->outcome);
        self::assertSame(['purpose' => self::PURPOSE], $entry->properties);
        self::assertEquals(['channel' => self::CHANNEL, 'method' => 'GET', 'route' => 'documents.download'], $entry->context);
    }

    /**
     * A list result is one disclosure with its row count, not its rows.
     *
     * @return void
     */
    public function testAListResultIsRecorded(): void
    {
        Route::get('/documents', static function (): array {
            $rows = ['first private row', 'second private row'];

            AuditLog::accessed('document.listed', subject: Reference::of('document_list', 'overdue'), purpose: self::PURPOSE, channel: self::CHANNEL)
                ->withProperties(['rows' => count($rows)])
                ->record();

            return $rows;
        });

        $this->get('/documents')->assertOk()->assertJsonCount(2);

        $entry = AuditEntry::query()->where('event', 'document.listed')->sole();

        self::assertEquals(['purpose' => self::PURPOSE, 'rows' => 2], $entry->properties);
        self::assertSame('document_list', $entry->subject_type);
        self::assertStringNotContainsString('private row', json_encode($entry->getAttributes(), JSON_THROW_ON_ERROR));
    }

    /**
     * A denied attempt has its own code, outcome and reason through `event()`.
     *
     * @return void
     */
    public function testADeniedAccessUsesItsOwnCodeThroughEvent(): void
    {
        AuditLog::event('document.download_denied')->on(self::document())->denied('not_permitted')->record();

        $entry = AuditEntry::query()->sole();

        self::assertSame('document.download_denied', $entry->event);
        self::assertSame('denied', $entry->outcome);
        self::assertSame('not_permitted', $entry->reason);
        self::assertSame('document-1', $entry->subject_id);
    }

    /**
     * Hydrating a model, which fires `retrieved`, writes nothing.
     *
     * @return void
     */
    public function testHydratingModelsWritesNothing(): void
    {
        $retrieved = 0;

        StubDocument::retrieved(static function () use (&$retrieved): void {
            $retrieved++;
        });

        $models = StubDocument::hydrate([['id' => 'document-1'], ['id' => 'document-2']]);

        self::assertCount(2, $models);
        self::assertSame(2, $retrieved);
        self::assertSame(0, $this->entryCount());
    }

    /**
     * A successful authorisation check writes nothing.
     *
     * @return void
     */
    public function testASuccessfulAuthorisationCheckWritesNothing(): void
    {
        Gate::define('view-document', static fn (): bool => true);

        self::assertTrue(Gate::forUser((new StubAuthUser)->forceFill(['id' => 42]))->allows('view-document'));
        self::assertSame(0, $this->entryCount());
    }

    /**
     * The content disclosed reaches the client and appears nowhere in the row.
     *
     * @return void
     */
    public function testNoDisclosedContentIsStored(): void
    {
        Route::get('/documents/1', static function (): string {
            AuditLog::accessed(self::CODE, subject: self::document(), purpose: self::PURPOSE, channel: self::CHANNEL)->record();

            return 'disclosed-content-sentinel';
        });

        $this->get('/documents/1')->assertOk()->assertSee('disclosed-content-sentinel');

        $row = json_encode(AuditEntry::query()->sole()->getAttributes(), JSON_THROW_ON_ERROR);

        self::assertStringNotContainsString('disclosed-content-sentinel', $row);
    }

    /**
     * A registered definition retaining the purpose stores it and its category.
     *
     * @return void
     */
    #[DefineEnvironment('registerTheDisclosures')]
    public function testAPurposeOfARegisteredDefinitionIsStored(): void
    {
        AuditLog::accessed(DisclosureActivity::DOCUMENT_DOWNLOADED, subject: self::document(), purpose: self::PURPOSE, channel: self::CHANNEL)->record();

        $entry = AuditEntry::query()->sole();

        self::assertSame('disclosure', $entry->category);
        self::assertSame(['purpose' => self::PURPOSE], $entry->properties);
        self::assertEquals(['channel' => self::CHANNEL], $entry->context);
    }

    /**
     * An access record can be fail closed, written at once in a transaction.
     *
     * @return void
     */
    public function testAnAccessRecordCanBeFailClosed(): void
    {
        DB::connection(self::CONNECTION)->beginTransaction();

        AuditLog::accessed(self::CODE, subject: self::document(), purpose: self::PURPOSE, channel: self::CHANNEL)->failClosed()->record();

        self::assertSame(1, $this->entryCount());

        DB::connection(self::CONNECTION)->commit();
    }

    /**
     * A failed fail-closed write throws at the call, before the disclosure.
     *
     * @return void
     */
    public function testAFailedFailClosedWriteStopsTheDisclosureAtTheCall(): void
    {
        FakeAuditStore::failing(new \RuntimeException('The store is down.'));

        DB::connection(self::CONNECTION)->beginTransaction();

        try {
            AuditLog::accessed(self::CODE, subject: self::document(), purpose: self::PURPOSE, channel: self::CHANNEL)->failClosed()->record();

            self::fail('Expected the failed write to reach the caller at the call.');
        } catch (AuditWriteFailedException $exception) {
            self::assertSame(\RuntimeException::class, $exception->exceptionClass);
        }

        self::assertSame(1, DB::connection(self::CONNECTION)->transactionLevel());

        DB::connection(self::CONNECTION)->rollBack();
    }

    /**
     * Register the disclosure activity as a provider would, while booting.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    protected function registerTheDisclosures(Application $app): void
    {
        $app->booting(static function (Application $app): void {
            $app->make(Recorder::class)->define(DisclosureActivity::class);
        });
    }

    /**
     * The document disclosed.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\Reference
     */
    private static function document(): Reference
    {
        return Reference::of('document', 'document-1');
    }
}
