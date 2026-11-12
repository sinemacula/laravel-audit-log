<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Tests\Fixtures\Capture\Models\SigningInUser;

/**
 * Creates the signing-in users' table on the test's connection and saves users
 * to it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait CreatesSigningInUsers
{
    /**
     * Create the users' table, dropped before the application is destroyed.
     *
     * @return void
     */
    private function createUsersTable(): void
    {
        $schema = Schema::connection(self::CONNECTION);

        $schema->dropIfExists(SigningInUser::TABLE);
        $schema->create(SigningInUser::TABLE, static function (Blueprint $table): void {
            $table->increments('id');
            $table->string('email', 191)->unique();
            $table->string('password', 191);
            $table->rememberToken();
        });

        $this->beforeApplicationDestroyed(static function (): void {
            Schema::connection(self::CONNECTION)->dropIfExists(SigningInUser::TABLE);
        });
    }

    /**
     * A saved user of the email, with the shared password and the remember
     * token.
     *
     * @param  string  $email
     * @param  ?string  $rememberToken
     * @return \Tests\Fixtures\Capture\Models\SigningInUser
     */
    private static function newUser(string $email, #[\SensitiveParameter] ?string $rememberToken = null): SigningInUser
    {
        return SigningInUser::query()->create(['email' => $email, 'password' => SigningInUser::PASSWORD, 'remember_token' => $rememberToken]);
    }
}
