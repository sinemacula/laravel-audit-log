<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Capture\Models;

use Illuminate\Database\Eloquent\Relations\Pivot;

/**
 * A custom pivot model with Eloquent's defaults: no key of its own, its rows
 * told apart only by the two foreign keys.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @property int $tagged_invoice_id
 * @property int $tag_id
 */
final class KeylessTagLink extends Pivot
{
    /** @var ?string The table the links are kept in. */
    protected $table = TaggedInvoice::PIVOT_TABLE;
}
