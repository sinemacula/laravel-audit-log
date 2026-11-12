<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Capture\Models;

use Illuminate\Database\Eloquent\Casts\AsEncryptedArrayObject;
use Illuminate\Database\Eloquent\Casts\AsEncryptedCollection;
use Illuminate\Database\Eloquent\Casts\Attribute;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Support\Fluent;
use Tests\Fixtures\Definitions\Enums\InvoiceActivity;

/**
 * An invoice an application watches: soft deletes, a hidden note, encrypted and
 * enum casts, and an accessor and appended attribute that refuse to be read, so
 * a capture that read either would fail.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @inheritable
 *
 * @property int $id
 * @property ?string $number
 * @property ?int $amount
 * @property ?string $secret_note
 * @property ?string $token
 * @property ?\Tests\Fixtures\Definitions\Enums\InvoiceActivity $status
 * @property ?\Illuminate\Support\Carbon $issued_at
 * @property ?\Illuminate\Support\Carbon $deleted_at
 */
class WatchedInvoice extends Model
{
    use SoftDeletes;

    /** @var string The table the invoices are kept in. */
    public const string TABLE = 'watched_invoices';

    /** @var string Why reading the accessor or the appended attribute fails. */
    public const string READ = 'An accessor or an appended attribute of a watched invoice was read.';

    /** @var ?string The table the invoices are kept in. */
    protected $table = self::TABLE;

    /** @var array<string> The attributes that are not mass assignable: none. */
    protected $guarded = [];

    /** @var list<string> The attributes kept from view. */
    protected $hidden = ['secret_note'];

    /** @var list<string> The attributes appended to the model's array. */
    protected $appends = ['label'];

    /**
     * The attributes that are cast: the token, the map and the lines encrypted,
     * the status to its enum and the issue time to a date.
     *
     * @return array<string, string>
     */
    #[\Override]
    protected function casts(): array
    {
        return [
            'token'     => 'encrypted',
            'meta'      => AsEncryptedArrayObject::class,
            'lines'     => AsEncryptedCollection::of(Fluent::class),
            'status'    => InvoiceActivity::class,
            'issued_at' => 'datetime',
        ];
    }

    /**
     * The number's accessor, which refuses to be read.
     *
     * @return \Illuminate\Database\Eloquent\Casts\Attribute<string, string>
     */
    protected function number(): Attribute
    {
        return self::unreadable();
    }

    /**
     * The invoice's appended label, which refuses to be read.
     *
     * @return \Illuminate\Database\Eloquent\Casts\Attribute<string, string>
     */
    protected function label(): Attribute
    {
        return self::unreadable();
    }

    /**
     * An accessor that refuses to be read.
     *
     * @return \Illuminate\Database\Eloquent\Casts\Attribute<string, string>
     */
    private static function unreadable(): Attribute
    {
        return Attribute::get(static function (): never {
            throw new \LogicException(self::READ);
        });
    }
}
