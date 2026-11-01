<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs;

use Illuminate\Database\Eloquent\Model;

/**
 * Eloquent stub with an incrementing integer key, standing in for a user that a
 * record refers to; tests set its attributes with `forceFill()` and never save
 * it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class StubUser extends Model
{
    /** @var array<string> Mass-assignment guard list. */
    protected $guarded = [];
}
