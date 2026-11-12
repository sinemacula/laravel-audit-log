<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Tests\Fixtures\Capture\Models\PlainLine;
use Tests\Fixtures\Capture\Models\WatchedInvoice;

/**
 * Creates the watched models' tables on the test's connection, and on a second
 * connection when a test asks, and drops them before the application is
 * destroyed.
 *
 * The second connection has its own table prefix, so it is another session on
 * MySQL and PostgreSQL and another database on in-memory SQLite.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait CreatesWatchedModels
{
    /** @var string The second connection a test may keep watched models on. */
    protected const string MODELS_CONNECTION = 'watched_models';

    /** @var string The prefix of the second connection's tables. */
    private const string MODELS_PREFIX = 'other_';

    /** @var list<string> The connections the watched models' tables are on. */
    private array $modelConnections = [];

    /**
     * Create the tables on the test's connection, and drop them on every
     * connection they were created on before the application is destroyed.
     *
     * @return void
     */
    protected function setUpCreatesWatchedModels(): void
    {
        $this->createWatchedModelTables(self::CONNECTION);

        $this->beforeApplicationDestroyed(function (): void {
            $this->dropWatchedModelTables();
        });
    }

    /**
     * Configure the second connection and create the tables on it.
     *
     * @return void
     */
    protected function useSecondModelConnection(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('database.connections.' . self::MODELS_CONNECTION, [
            ...$config->array('database.connections.' . self::CONNECTION),
            'prefix' => self::MODELS_PREFIX,
        ]);

        $this->createWatchedModelTables(self::MODELS_CONNECTION);
    }

    /**
     * Create the watched invoices' and the plain lines' tables on the
     * connection, dropping any a failed run left.
     *
     * @param  string  $connection
     * @return void
     */
    private function createWatchedModelTables(string $connection): void
    {
        $schema = Schema::connection($connection);

        $schema->dropIfExists(WatchedInvoice::TABLE);
        $schema->dropIfExists(PlainLine::TABLE);

        $schema->create(WatchedInvoice::TABLE, static function (Blueprint $table): void {
            $table->increments('id');
            $table->string('number', 32)->nullable();
            $table->string('status', 64)->nullable();
            $table->integer('amount')->nullable();
            $table->string('secret_note', 64)->nullable();
            $table->text('token')->nullable();
            $table->text('meta')->nullable();
            $table->text('lines')->nullable();
            $table->dateTime('issued_at')->nullable();
            $table->timestamps();
            $table->softDeletes();
        });

        $schema->create(PlainLine::TABLE, static function (Blueprint $table): void {
            $table->increments('id');
            $table->string('description', 64)->nullable();
            $table->integer('quantity')->nullable();
            $table->string('deleted_at', 32)->nullable();
        });

        $this->modelConnections[] = $connection;
    }

    /**
     * Roll back what a test left open, then drop the tables from every
     * connection they were created on.
     *
     * @return void
     */
    private function dropWatchedModelTables(): void
    {
        foreach (array_unique($this->modelConnections) as $connection) {
            $database = DB::connection($connection);

            while ($database->transactionLevel() > 0) {
                $database->rollBack();
            }

            $database->getSchemaBuilder()->dropIfExists(WatchedInvoice::TABLE);
            $database->getSchemaBuilder()->dropIfExists(PlainLine::TABLE);
        }

        $this->modelConnections = [];
    }
}
