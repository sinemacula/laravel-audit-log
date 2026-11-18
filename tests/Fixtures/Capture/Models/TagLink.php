<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Capture\Models;

use Illuminate\Database\Eloquent\Relations\Pivot;

/**
 * A custom pivot model that attaches tagged invoices to tags, keyed by an
 * incrementing id of its own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @property int $id
 * @property int $tagged_invoice_id
 * @property int $tag_id
 */
final class TagLink extends Pivot
{
    /** @var string The table the links are kept in. */
    public const string TABLE = 'tagged_invoice_tag_links';

    /** @var bool Whether the id is incrementing: it is. */
    public $incrementing = true;

    /** @var ?string The table the links are kept in. */
    protected $table = self::TABLE;
}
