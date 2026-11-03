<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Capture\Models;

use Illuminate\Database\Eloquent\Model;

/**
 * A line kept in the plain lines' table under a class of its own, so a test can
 * watch it with a field encrypted for its subject while the plain lines keep
 * their own watch.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @property int $id
 * @property ?string $description
 * @property ?int $quantity
 */
final class SealedLine extends Model
{
    /** @var bool Whether the line has created and updated times: it has neither. */
    public $timestamps = false;

    /** @var ?string The table the lines are kept in. */
    protected $table = PlainLine::TABLE;

    /** @var array<string> The attributes that are not mass assignable: none. */
    protected $guarded = [];
}
