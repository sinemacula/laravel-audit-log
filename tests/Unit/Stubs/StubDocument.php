<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs;

use Illuminate\Database\Eloquent\Model;

/**
 * Eloquent stub with a string key that does not increment, standing in for a
 * model keyed by a UUID, a ULID or any other string; its key is never cast, so
 * a test can give it any key.
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
