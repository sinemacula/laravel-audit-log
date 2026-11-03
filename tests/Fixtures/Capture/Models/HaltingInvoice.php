<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Capture\Models;

use Illuminate\Database\Eloquent\Model;

/**
 * An invoice whose created, updated and deleted events are dispatched as a
 * custom event, which a listener answers: Eloquent then never dispatches its
 * own events for them, so nothing listening for those hears the change.
 *
 * Any class whose constructor takes the model would do as the custom event; a
 * standard one keeps the fixture to one class. The answering listener is
 * registered when the model boots, on the application's dispatcher.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @property int $id
 * @property ?string $number
 */
final class HaltingInvoice extends Model
{
    /** @var class-string The custom event each change is dispatched as. */
    public const string CUSTOM_EVENT = \ArrayObject::class;

    /** @var ?string The table the invoices are kept in: the watched invoices'. */
    protected $table = WatchedInvoice::TABLE;

    /** @var array<string> The attributes that are not mass assignable: none. */
    protected $guarded = [];

    /** @var array<string, class-string> The custom event each change is dispatched as. */
    protected $dispatchesEvents = [
        'created' => self::CUSTOM_EVENT,
        'updated' => self::CUSTOM_EVENT,
        'deleted' => self::CUSTOM_EVENT,
    ];

    /**
     * Answer the custom event, so Eloquent's own is never dispatched.
     *
     * @return void
     */
    #[\Override]
    protected static function booted(): void
    {
        self::getEventDispatcher()?->listen(self::CUSTOM_EVENT, static fn (): bool => true);
    }
}
