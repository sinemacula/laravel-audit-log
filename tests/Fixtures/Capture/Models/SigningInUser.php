<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Capture\Models;

use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Foundation\Auth\User;

/**
 * A user who signs in through a guard for real, with an email, a password
 * hashed when set and a remember token; its table belongs to the tests that use
 * it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @property int $id
 * @property string $email
 * @property string $password
 * @property ?string $remember_token
 */
final class SigningInUser extends User implements MustVerifyEmail
{
    /** @var string The table the users are kept in. */
    public const string TABLE = 'signing_in_users';

    /** @var string The password every user is made with. */
    public const string PASSWORD = 'correct-horse-battery-staple';

    /** @var bool Whether the user has created and updated times: they have neither. */
    public $timestamps = false;

    /** @var ?string The table the users are kept in. */
    protected $table = self::TABLE;

    /** @var array<string> The attributes that are not mass assignable: none. */
    protected $guarded = [];

    /** @var list<string> The attributes kept from view. */
    protected $hidden = ['password', 'remember_token'];

    /**
     * The attributes that are cast: the password hashed when it is set.
     *
     * @return array<string, string>
     */
    #[\Override]
    protected function casts(): array
    {
        return ['password' => 'hashed'];
    }
}
