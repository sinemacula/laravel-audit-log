<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Capture\Models;

use Illuminate\Database\Eloquent\Model;

/**
 * A model that counts how many times it boots, which Eloquent does when the
 * first model of the class is built in an application, so a test can show that
 * watching it built none. It is kept in the plain lines' table.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CountedModel extends Model
{
    /** @var int How many times the class has booted in this process. */
    public static int $boots = 0;

    /** @var bool Whether the model has created and updated times: it has neither. */
    public $timestamps = false;

    /** @var ?string The table the models are kept in: the plain lines'. */
    protected $table = PlainLine::TABLE;

    /** @var array<string> The attributes that are not mass assignable: none. */
    protected $guarded = [];

    /**
     * Count the boot.
     *
     * @return void
     */
    #[\Override]
    protected static function booted(): void
    {
        self::$boots++;
    }
}
