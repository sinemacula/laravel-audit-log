<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs;

use Illuminate\Database\Eloquent\Model;

/**
 * A model with a non-incrementing string key that is never cast, standing in
 * for one keyed by a UUID, a ULID or any other string.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class StubDocument extends Model
{
    /** @var bool Indicates whether the IDs are auto-incrementing. */
    public $incrementing = false;

    /** @var string The "type" of the primary key ID. */
    protected $keyType = 'string';

    /** @var array<string> Mass-assignment guard list. */
    protected $guarded = [];
}
