<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Capture\Models;

use Illuminate\Database\Eloquent\Model;

/**
 * A line with no soft deletes, no casts and no times, whose table has a
 * `deleted_at` column all the same: an ordinary field, which clearing is an
 * update and never a restore.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @property int $id
 * @property ?string $description
 * @property ?int $quantity
 * @property ?string $deleted_at
 */
final class PlainLine extends Model
{
    /** @var string The table the lines are kept in. */
    public const string TABLE = 'plain_lines';

    /** @var bool Whether the line has created and updated times: it has neither. */
    public $timestamps = false;

    /** @var ?string The table the lines are kept in. */
    protected $table = self::TABLE;

    /** @var array<string> The attributes that are not mass assignable: none. */
    protected $guarded = [];
}
