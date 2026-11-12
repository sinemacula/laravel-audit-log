<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Capture\Models;

use Illuminate\Database\Eloquent\Model;

/**
 * A tag a tagged invoice is attached to through a plain pivot table, with no
 * model of its own, so an attachment writes only the pivot's row.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @property int $id
 * @property ?string $name
 */
final class Tag extends Model
{
    /** @var string The table the tags are kept in. */
    public const string TABLE = 'capture_tags';

    /** @var bool Whether the tag has created and updated times: it has neither. */
    public $timestamps = false;

    /** @var ?string The table the tags are kept in. */
    protected $table = self::TABLE;

    /** @var array<string> The attributes that are not mass assignable: none. */
    protected $guarded = [];
}
