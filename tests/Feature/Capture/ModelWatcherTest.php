<?php

declare(strict_types = 1);

namespace Tests\Feature\Capture;

use Illuminate\Events\Dispatcher;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Capture\Enums\ModelEvent;
use SineMacula\Laravel\AuditLog\Capture\ModelWatch;
use SineMacula\Laravel\AuditLog\Capture\ModelWatcher;
use SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Listeners\RecordModelChange;
use SineMacula\Laravel\AuditLog\Records\EventCode;
use Tests\Fixtures\Capture\Models\CountedModel;
use Tests\Fixtures\Capture\Models\PlainLine;
use Tests\Fixtures\Capture\Models\WatchedInvoice;
use Tests\Fixtures\Capture\Models\WatchedInvoiceRevision;
use Tests\TestCase;

/**
 * Feature tests for the model watcher: a watch registers its five definitions
 * and listens for its four Eloquent events by the exact class's names, every
 * check runs before anything is registered, an identical watch changes nothing,
 * a different one, a segment taken and a definition registered differently are
 * refused, nothing is watched once the watcher is frozen, and no model is
 * built.
 *
 * Each test makes a watcher of its own, on a catalogue and a dispatcher of its
 * own, so what it registers can be read back exactly.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ModelWatcher::class)]
final class ModelWatcherTest extends TestCase
{
    /** @var array<array-key, \SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling|string> The fields the tests watch. */
    private const array FIELDS = ['number', 'amount' => FieldHandling::REDACT];

    /** @var list<string> The Eloquent events a watch listens for, in the order it registers them. */
    private const array EVENTS = ['created', 'updated', 'deleted', 'forceDeleted'];

    /** @var \SineMacula\Laravel\AuditLog\Definitions\EventCatalogue The catalogue the watcher registers in. */
    private EventCatalogue $catalogue;

    /** @var \Illuminate\Events\Dispatcher The dispatcher the watcher listens with. */
    private Dispatcher $events;

    /** @var \SineMacula\Laravel\AuditLog\Capture\ModelWatcher The watcher under test. */
    private ModelWatcher $watcher;

    /**
     * Make a watcher on a catalogue and a dispatcher of the test's own.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->catalogue = new EventCatalogue;
        $this->events    = new Dispatcher;
        $this->watcher   = new ModelWatcher($this->catalogue, $this->events);
    }

    /**
     * A watch registers the definition of each of the five changes, exactly as
     * the watch defines it, and the watch is found by its class.
     *
     * @return void
     */
    public function testWatchRegistersTheFiveDefinitions(): void
    {
        $this->watcher->watch(WatchedInvoice::class, 'invoice', self::FIELDS);

        $expected = ModelWatch::of(WatchedInvoice::class, 'invoice', self::FIELDS);

        foreach ($expected->definitions() as $change => $definition) {
            $code = EventCode::of('invoice.' . $change);

            self::assertTrue($this->catalogue->isRegistered($code), $change);
            self::assertTrue($this->catalogue->definitionFor($code)->equals($definition), $change);
        }

        self::assertTrue($this->watcher->watchFor(WatchedInvoice::class)?->equals($expected));
    }

    /**
     * A watch listens for the four Eloquent events by the names Eloquent
     * dispatches them under for exactly the class, each to the listener's
     * method of the same name, and for nothing of a subclass or a restore.
     *
     * @return void
     */
    public function testWatchListensOnTheExactClass(): void
    {
        $this->watcher->watch(WatchedInvoice::class, 'invoice', self::FIELDS);

        $expected = [];

        foreach (self::EVENTS as $event) {
            $expected['eloquent.' . $event . ': ' . WatchedInvoice::class] = [[RecordModelChange::class, $event]];
        }

        self::assertSame($expected, $this->events->getRawListeners());
        self::assertFalse($this->events->hasListeners('eloquent.created: ' . WatchedInvoiceRevision::class));
        self::assertFalse($this->events->hasListeners('eloquent.restored: ' . WatchedInvoice::class));
        self::assertNull($this->watcher->watchFor(WatchedInvoiceRevision::class));
    }

    /**
     * A class named in another case is watched, and listened for, as PHP
     * declares it.
     *
     * @return void
     */
    public function testAClassIsWatchedAsDeclared(): void
    {
        $this->watcher->watch(strtolower(WatchedInvoice::class), 'invoice', self::FIELDS);

        self::assertNotNull($this->watcher->watchFor(WatchedInvoice::class));
        self::assertTrue($this->events->hasListeners('eloquent.created: ' . WatchedInvoice::class));
    }

    /**
     * Watching a class again as it is watched, its fields in another order,
     * changes nothing: one listener for each event, and the same definitions.
     *
     * @return void
     */
    public function testIdenticalWatchChangesNothing(): void
    {
        $this->watcher->watch(WatchedInvoice::class, 'invoice', self::FIELDS);
        $this->watcher->watch(WatchedInvoice::class, 'invoice', ['amount' => FieldHandling::REDACT, 'number']);

        foreach (self::EVENTS as $event) {
            self::assertCount(1, self::listenersFor($this->events->getRawListeners(), 'eloquent.' . $event . ': ' . WatchedInvoice::class), $event);
        }

        self::assertSame(['number', 'amount'], array_keys($this->watcher->watchFor(WatchedInvoice::class)->fields ?? []));
    }

    /**
     * Watching a class another way is refused, and the first watch stands.
     *
     * @return void
     */
    public function testAConflictingWatchIsRefused(): void
    {
        $this->watcher->watch(WatchedInvoice::class, 'invoice', self::FIELDS);

        try {
            $this->watcher->watch(WatchedInvoice::class, 'invoice', ['number']);
            self::fail('Expected the second watch to be refused.');
        } catch (\LogicException $exception) {
            self::assertSame('`' . WatchedInvoice::class . '` is already watched differently; a model has one watch.', $exception->getMessage());
        }

        self::assertSame(self::FIELDS['amount'], $this->watcher->watchFor(WatchedInvoice::class)?->handlingOf('amount'));
        self::assertCount(1, self::listenersFor($this->events->getRawListeners(), 'eloquent.created: ' . WatchedInvoice::class));
    }

    /**
     * Watching another class under a segment a watched class's changes are
     * stored under is refused, even a subclass, and registers nothing for it.
     *
     * @return void
     */
    public function testAPrefixOfAnotherModelIsRefused(): void
    {
        $this->watcher->watch(WatchedInvoice::class, 'invoice', self::FIELDS);

        try {
            $this->watcher->watch(WatchedInvoiceRevision::class, 'invoice', self::FIELDS);
            self::fail('Expected the taken segment to be refused.');
        } catch (\LogicException $exception) {
            $message = 'The segment `invoice` already names the changes of `' . WatchedInvoice::class . '`; each watched model has its own.';

            self::assertSame($message, $exception->getMessage());
        }

        self::assertNull($this->watcher->watchFor(WatchedInvoiceRevision::class));
        self::assertFalse($this->events->hasListeners('eloquent.created: ' . WatchedInvoiceRevision::class));
    }

    /**
     * A watch whose definition the catalogue holds differently is refused
     * before any definition is registered, so none of the five is, nothing is
     * listened for, and the class is not watched.
     *
     * @return void
     */
    public function testADefinitionConflictRegistersNothing(): void
    {
        $this->catalogue->define(EventDefinition::for('invoice.deleted')->category('billing'));

        try {
            $this->watcher->watch(WatchedInvoice::class, 'invoice', self::FIELDS);
            self::fail('Expected the conflicting definition to be refused.');
        } catch (\LogicException $exception) {
            self::assertSame('The event code `invoice.deleted` is already defined differently; a code has one definition.', $exception->getMessage());
        }

        foreach (['created', 'updated', 'restored', 'force_deleted'] as $change) {
            self::assertFalse($this->catalogue->isRegistered(EventCode::of('invoice.' . $change)), $change);
        }

        $this->assertNothingWatched();
    }

    /**
     * A definition the catalogue already holds exactly as the watch defines it
     * is no conflict.
     *
     * @return void
     */
    public function testAnIdenticalDefinitionAlreadyRegisteredIsAccepted(): void
    {
        $watch = ModelWatch::of(WatchedInvoice::class, 'invoice', self::FIELDS);

        $this->catalogue->define($watch->definitions()[ModelEvent::UPDATED->value]);

        $this->watcher->watch(WatchedInvoice::class, 'invoice', self::FIELDS);

        self::assertNotNull($this->watcher->watchFor(WatchedInvoice::class));
        self::assertTrue($this->catalogue->isRegistered(EventCode::of('invoice.force_deleted')));
    }

    /**
     * A watch the model watch refuses registers nothing.
     *
     * @return void
     */
    public function testARefusedWatchRegistersNothing(): void
    {
        try {
            $this->watcher->watch(WatchedInvoice::class, 'authentication', self::FIELDS);
            self::fail('Expected the reserved segment to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('The segment `authentication` is reserved for the package\'s own codes.', $exception->getMessage());
        }

        $this->assertNothingWatched();
    }

    /**
     * Once frozen the watcher refuses any watch and registers nothing; freezing
     * again changes nothing.
     *
     * @return void
     */
    public function testWatchAfterFreezeIsRefused(): void
    {
        self::assertFalse($this->watcher->isFrozen());

        $this->watcher->freeze();
        $this->watcher->freeze();

        self::assertTrue($this->watcher->isFrozen());

        try {
            $this->watcher->watch(WatchedInvoice::class, 'invoice', self::FIELDS);
            self::fail('Expected the watch to be refused.');
        } catch (\LogicException $exception) {
            self::assertSame('Models are watched while the application boots, and it has already booted.', $exception->getMessage());
        }

        self::assertFalse($this->catalogue->isRegistered(EventCode::of('invoice.created')));
        $this->assertNothingWatched();
    }

    /**
     * A catalogue frozen first refuses the first definition, so a watch then
     * registers nothing either.
     *
     * @return void
     */
    public function testAFrozenCatalogueRegistersNothing(): void
    {
        $this->catalogue->freeze();

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Event definitions are registered while the application boots, and it has already booted.');

        try {
            $this->watcher->watch(WatchedInvoice::class, 'invoice', self::FIELDS);
        } finally {
            $this->assertNothingWatched();
        }
    }

    /**
     * Several models are watched side by side, each under its own segment.
     *
     * @return void
     */
    public function testModelsAreWatchedSideBySide(): void
    {
        $this->watcher->watch(WatchedInvoice::class, 'invoice', self::FIELDS);
        $this->watcher->watch(WatchedInvoiceRevision::class, 'invoice_revision', self::FIELDS);
        $this->watcher->watch(PlainLine::class, 'line', ['description']);

        self::assertSame('invoice_revision', $this->watcher->watchFor(WatchedInvoiceRevision::class)?->as);
        self::assertSame('line', $this->watcher->watchFor(PlainLine::class)?->as);
        self::assertCount(12, $this->events->getRawListeners());
    }

    /**
     * Watching a model builds none: the class alone is read, so the class does
     * not boot until a model of it is built.
     *
     * @return void
     */
    public function testNoModelIsBuiltAtRegistration(): void
    {
        CountedModel::$boots = 0;

        $this->watcher->watch(CountedModel::class, 'counted', ['description']);

        self::assertSame(0, CountedModel::$boots);
        self::assertNotNull($this->watcher->watchFor(CountedModel::class));

        new CountedModel;

        self::assertSame(1, CountedModel::$boots);
    }

    /**
     * Assert the invoices are not watched: no watch, no listener and none of
     * their definitions.
     *
     * @return void
     */
    private function assertNothingWatched(): void
    {
        self::assertNull($this->watcher->watchFor(WatchedInvoice::class));
        self::assertSame([], $this->events->getRawListeners());
        self::assertFalse($this->catalogue->isRegistered(EventCode::of('invoice.created')));
    }
}
