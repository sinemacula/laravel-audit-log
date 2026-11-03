<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseTransactionsManager;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Events\TransactionBeginning;
use Illuminate\Database\Events\TransactionCommitted;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\AuditLog\Database\DeliveryTables;

/**
 * Runs work in real child processes that end the way a killed worker ends: by
 * `SIGKILL`, at a chosen statement or when the work is done, so nothing runs a
 * destructor, a shutdown function, a rollback or a commit callback. What the
 * child left is what the database and the files hold when it is gone: SQLite
 * rolls a hot journal back when the file is next opened, and MySQL and
 * PostgreSQL roll back server-side when the socket closes.
 *
 * A kill point is a regular expression matched against each statement with its
 * bindings in place, so a kill can name a row or a destination. Before the
 * statement runs, or after it has; after one, the word `commit` is also matched
 * straight after an outermost commit, from the first of its callbacks, so
 * before any other callback has run, and the words `after callbacks` once they
 * all have. The tests run on Laravel's own transactions manager and no test
 * wrapper transaction, so a commit is a commit.
 *
 * In-memory SQLite cannot be shared across a fork, so a class calls
 * `useFileDatabaseOnSqlite()` from `defineEnvironment()`, and
 * `removeChildren()` from its `tearDown()`, after `parent::tearDown()` has
 * rolled its migrations back. The files a child and its parent share, gates
 * included, live in a directory of the test's own, which that call removes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait RunsKilledChildren
{
    /** @var int How long SQLite waits on another process's lock, in milliseconds. */
    private const int BUSY_TIMEOUT_MILLISECONDS = 60000;

    /** @var int How long a gate is waited on before the wait is called a failure, in seconds. */
    private const int GATE_TIMEOUT_SECONDS = 60;

    /** @var int How long a gate's wait sleeps between looks, in microseconds. */
    private const int GATE_POLL_MICROSECONDS = 1000;

    /** @var ?string The directory of the files this test's processes share. */
    private ?string $childDirectory = null;

    /** @var list<int> The children started and not yet waited for. */
    private array $runningChildren = [];

    /**
     * Put the default connection on a temporary file when it is SQLite, with a
     * lock wait long enough for two processes to take turns, because an
     * in-memory database cannot be shared across a fork.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $app
     * @return void
     */
    protected function useFileDatabaseOnSqlite(mixed $app): void
    {
        assert($app instanceof Application);

        $config = $app->make(ConfigRepository::class);
        $key    = 'database.connections.' . $config->string('database.default');

        if ($config->get($key . '.driver') !== 'sqlite') {
            return;
        }

        $path = $this->childFile('database.sqlite');

        touch($path);

        $config->set($key . '.database', $path);
        $config->set($key . '.busy_timeout', self::BUSY_TIMEOUT_MILLISECONDS);
    }

    /**
     * Run the work in a child process, wait for it to die, and return the
     * signal that ended it.
     *
     * @param  \Closure(): void  $work
     * @param  ?string  $killBefore
     * @param  ?string  $killAfter
     * @return int
     */
    protected function runChild(\Closure $work, ?string $killBefore = null, ?string $killAfter = null): int
    {
        return $this->waitForChild($this->startChild($work, $killBefore, $killAfter));
    }

    /**
     * Start the work in a child process and return its process id, leaving this
     * process to race it.
     *
     * Every connection is closed first, so the child shares no socket or file
     * lock with this process, which reconnects when it next needs to.
     *
     * @param  \Closure(): void  $work
     * @param  ?string  $killBefore
     * @param  ?string  $killAfter
     * @return int
     */
    protected function startChild(\Closure $work, ?string $killBefore = null, ?string $killAfter = null): int
    {
        if (!function_exists('pcntl_fork')) {
            self::markTestSkipped('Killed child processes need pcntl.');
        }

        self::assertSame(DatabaseTransactionsManager::class, get_debug_type(app('db.transactions')), 'A child must run on the production transactions manager.');

        foreach (array_keys(DB::getConnections()) as $name) {
            DB::disconnect($name);
        }

        // The directory is named once, here, or each side would make its own
        $this->childFile('');

        $pid = pcntl_fork();

        self::assertNotSame(-1, $pid, 'The process could not be forked.');

        if ($pid === 0) {
            $this->runInChild($work, $killBefore, $killAfter);
        }

        $this->runningChildren[] = $pid;

        return $pid;
    }

    /**
     * Wait for the child to die and return the signal that ended it, or `0`
     * when it exited instead. A child whose work threw fails the test here,
     * naming what it threw.
     *
     * @param  int  $pid
     * @return int
     */
    protected function waitForChild(int $pid): int
    {
        pcntl_waitpid($pid, $status);

        $this->runningChildren = array_values(array_diff($this->runningChildren, [$pid]));

        $failure = $this->childFile("failure-{$pid}");

        if (is_file($failure)) {
            self::fail('The child failed: ' . file_get_contents($failure));
        }

        return pcntl_wifsignaled($status) ? pcntl_wtermsig($status) : 0;
    }

    /**
     * Assert the child died of `SIGKILL`.
     *
     * @param  int  $signal
     * @return void
     */
    protected function assertKilled(int $signal): void
    {
        self::assertSame(SIGKILL, $signal, 'The child was not ended by SIGKILL.');
    }

    /**
     * The path of a file this test's processes share, by its name.
     *
     * @param  string  $name
     * @return string
     */
    protected function childFile(string $name): string
    {
        if ($this->childDirectory === null) {
            $this->childDirectory = sys_get_temp_dir() . '/audit-killed-children-' . bin2hex(random_bytes(8));

            mkdir($this->childDirectory);
        }

        return $this->childDirectory . '/' . $name;
    }

    /**
     * Append one line to a file the test's processes share, whole and at once,
     * so a kill that follows cannot lose it.
     *
     * @param  string  $name
     * @param  string  $line
     * @return void
     */
    protected function appendToChildFile(string $name, string $line): void
    {
        file_put_contents($this->childFile($name), $line . "\n", FILE_APPEND | LOCK_EX);
    }

    /**
     * The lines of a file the test's processes share, oldest first, none when
     * nothing was written.
     *
     * @param  string  $name
     * @return list<string>
     */
    protected function childFileLines(string $name): array
    {
        $path = $this->childFile($name);

        return is_file($path) ? (file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: []) : [];
    }

    /**
     * Open the gate, for whichever process waits on it.
     *
     * @param  string  $name
     * @return void
     */
    protected function openGate(string $name): void
    {
        touch($this->childFile("gate-{$name}"));
    }

    /**
     * Wait for the gate to open, and throw when it never does, so a process
     * that lost its partner fails rather than hangs.
     *
     * @param  string  $name
     * @return void
     *
     * @throws \RuntimeException
     */
    protected function awaitGate(string $name): void
    {
        $path     = $this->childFile("gate-{$name}");
        $deadline = microtime(true) + self::GATE_TIMEOUT_SECONDS;

        while (!is_file($path)) {
            $failures = glob($this->childFile('failure-*')) ?: [];

            if ($failures !== []) {
                throw new \RuntimeException('A child failed: ' . file_get_contents($failures[0]));
            }

            if (microtime(true) > $deadline) {
                throw new \RuntimeException("The gate [{$name}] never opened.");
            }

            usleep(self::GATE_POLL_MICROSECONDS);

            clearstatcache(true, $path);
        }
    }

    /**
     * Kill any child a failed test left running, then remove the files the
     * test's processes shared.
     *
     * @return void
     */
    protected function removeChildren(): void
    {
        foreach ($this->runningChildren as $pid) {
            posix_kill($pid, SIGKILL);
            pcntl_waitpid($pid, $status);
        }

        $this->runningChildren = [];

        if ($this->childDirectory === null) {
            return;
        }

        foreach (glob($this->childDirectory . '/*') ?: [] as $file) {
            unlink($file);
        }

        rmdir($this->childDirectory);

        $this->childDirectory = null;
    }

    /**
     * In the forked process: drop the parent's connections, arm the kill
     * points, run the work, and die by `SIGKILL` however it went. What the work
     * threw is left for the parent to fail on.
     *
     * @param  \Closure(): void  $work
     * @param  ?string  $killBefore
     * @param  ?string  $killAfter
     * @return never
     */
    private function runInChild(\Closure $work, ?string $killBefore, ?string $killAfter): never
    {
        try {
            foreach (array_keys(DB::getConnections()) as $name) {
                DB::purge($name);
            }

            $this->armKillPoints($killBefore, $killAfter);

            $work();
        } catch (\Throwable $exception) {
            file_put_contents($this->childFile('failure-' . posix_getpid()), get_debug_type($exception) . ': ' . $exception->getMessage());
        }

        self::killThisProcess();
    }

    /**
     * Kill this process before each statement matching the first pattern, on
     * the default and the outbox connection, and after each statement or commit
     * matching the second. Laravel runs commit callbacks before it dispatches
     * `TransactionCommitted`, so the gap between a commit and its callbacks is
     * reached from a callback of its own, registered as the outermost
     * transaction begins, which makes it the first to run.
     *
     * @param  ?string  $killBefore
     * @param  ?string  $killAfter
     * @return void
     */
    private function armKillPoints(?string $killBefore, ?string $killAfter): void
    {
        if ($killBefore !== null) {
            foreach (array_unique([DB::getDefaultConnection(), DeliveryTables::resolvedOutboxConnection()]) as $name) {
                DB::connection($name)->beforeExecuting(static function (string $query, array $bindings, Connection $connection) use ($killBefore): void {
                    self::killOnMatch($killBefore, $connection->query()->getGrammar()->substituteBindingsIntoRawSql($query, $connection->prepareBindings($bindings)));
                });
            }
        }

        if ($killAfter === null) {
            return;
        }

        DB::listen(static function (QueryExecuted $event) use ($killAfter): void {
            self::killOnMatch($killAfter, $event->toRawSql());
        });

        Event::listen(TransactionBeginning::class, static function (TransactionBeginning $event) use ($killAfter): void {
            if ($event->connection->transactionLevel() !== 1) {
                return;
            }

            app('db.transactions')->addCallback(static function () use ($killAfter): void {
                self::killOnMatch($killAfter, 'commit');
            });
        });

        // A savepoint's success fires the same event, so only a commit that
        // leaves no transaction open is a commit
        Event::listen(TransactionCommitted::class, static function (TransactionCommitted $event) use ($killAfter): void {
            if ($event->connection->transactionLevel() > 0) {
                return;
            }

            self::killOnMatch($killAfter, 'after callbacks');
        });
    }

    /**
     * Kill this process when the pattern matches the statement.
     *
     * @param  string  $pattern
     * @param  string  $statement
     * @return void
     */
    private static function killOnMatch(string $pattern, string $statement): void
    {
        if (preg_match($pattern, $statement) !== 1) {
            return;
        }

        self::killThisProcess();
    }

    /**
     * End this process by `SIGKILL`, which nothing can handle or delay.
     *
     * @return never
     */
    private static function killThisProcess(): never
    {
        posix_kill(posix_getpid(), SIGKILL);

        exit(1);
    }
}
