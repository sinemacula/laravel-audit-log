<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Capture\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;

/**
 * An invoice that belongs to many tags through a plain pivot table with no
 * `using()` model, so attaching a tag dispatches no model event.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @property int $id
 * @property ?string $number
 * @property \Illuminate\Database\Eloquent\Collection<int, \Tests\Fixtures\Capture\Models\Tag> $tags
 */
final class TaggedInvoice extends Model
{
    /** @var string The table the invoices are kept in. */
    public const string TABLE = 'tagged_invoices';

    /** @var string The pivot table that attaches the invoices to their tags. */
    public const string PIVOT_TABLE = 'tagged_invoice_tag';

    /** @var bool Whether the invoice has created and updated times: it has neither. */
    public $timestamps = false;

    /** @var ?string The table the invoices are kept in. */
    protected $table = self::TABLE;

    /** @var array<string> The attributes that are not mass assignable: none. */
    protected $guarded = [];

    /**
     * The tags the invoice is attached to, through the plain pivot table.
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsToMany<\Tests\Fixtures\Capture\Models\Tag, $this>
     */
    public function tags(): BelongsToMany
    {
        return $this->belongsToMany(Tag::class, self::PIVOT_TABLE);
    }
}
