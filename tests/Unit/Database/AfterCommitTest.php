<?php

declare(strict_types = 1);

namespace Tests\Unit\Database;

use Illuminate\Database\DatabaseTransactionsManager;
use Illuminate\Foundation\Testing\DatabaseTransactionsManager as TestingTransactionsManager;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Database\AfterCommit;

/**
 * Unit tests for the after-commit adapter, driven directly against Laravel's
 * transaction manager and the one its testing traits install: which transaction
 * it selects, that it resolves the manager on every call, and that it catches
 * nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AfterCommit::class)]
final class AfterCommitTest extends TestCase
{
    /** @var int How many times the callback has run. */
    private int $runs = 0;

    /**
     * With no manager, or with something that is not one, the callback runs at
     * once.
     *
     * @return void
     */
    public function testRunsNowWithNoManager(): void
    {
        (new AfterCommit(static fn (): mixed => null))->run(null, $this->counted());

        self::assertSame(1, $this->runs);

        (new AfterCommit(static fn (): mixed => new \stdClass))->run('main', $this->counted());

        self::assertSame(2, $this->runs);
    }

    /**
     * With a manager and no pending transaction, the callback runs at once.
     *
     * @return void
     */
    public function testRunsNowWithNoPendingTransaction(): void
    {
        $this->adapter(new DatabaseTransactionsManager)->run(null, $this->counted());

        self::assertSame(1, $this->runs);
    }

    /**
     * With no name it attaches to the innermost transaction on any connection:
     * the other connection's commit does not run it, and its own does.
     *
     * @return void
     */
    public function testAttachesToTheInnermostOnAnyConnection(): void
    {
        $manager = new DatabaseTransactionsManager;

        $manager->begin('main', 1);
        $manager->begin('other', 1);

        $this->adapter($manager)->run(null, $this->counted());

        self::assertSame(0, $this->runs);

        $manager->commit('main', 1, 0);

        self::assertSame(0, $this->runs);

        $manager->commit('other', 1, 0);

        self::assertSame(1, $this->runs);
    }

    /**
     * With a name it attaches to that connection's innermost transaction, not
     * to a later one elsewhere or the same connection's outer one, so a
     * rollback of the inner transaction drops it.
     *
     * @return void
     */
    public function testAPinnedNameSelectsItsOwnInnermost(): void
    {
        $manager = new DatabaseTransactionsManager;

        $manager->begin('main', 1);
        $manager->begin('main', 2);
        $manager->begin('other', 1);

        $this->adapter($manager)->run('main', $this->counted());

        $manager->commit('other', 1, 0);

        self::assertSame(0, $this->runs);

        $manager->rollback('main', 1);
        $manager->commit('main', 1, 0);

        self::assertSame(0, $this->runs);
    }

    /**
     * A callback pinned to the inner transaction survives its inner commit and
     * runs at the outer commit.
     *
     * @return void
     */
    public function testAPinnedCallbackRunsAtTheOuterCommit(): void
    {
        $manager = new DatabaseTransactionsManager;

        $manager->begin('main', 1);
        $manager->begin('main', 2);

        $this->adapter($manager)->run('main', $this->counted());

        $manager->commit('main', 2, 1);

        self::assertSame(0, $this->runs);

        $manager->commit('main', 1, 0);

        self::assertSame(1, $this->runs);
    }

    /**
     * A transaction on another connection neither delays nor cancels work
     * pinned to a connection with none.
     *
     * @return void
     */
    public function testAPinnedNameIgnoresOtherConnections(): void
    {
        $manager = new DatabaseTransactionsManager;

        $manager->begin('other', 1);

        $this->adapter($manager)->run('main', $this->counted());

        self::assertSame(1, $this->runs);
    }

    /**
     * Every call resolves the manager afresh, so one swapped in after the
     * adapter was made is the one consulted.
     *
     * @return void
     */
    public function testResolvesTheManagerOnEveryCall(): void
    {
        $first  = new DatabaseTransactionsManager;
        $second = new DatabaseTransactionsManager;
        $calls  = 0;

        $first->begin('main', 1);
        $second->begin('main', 1);

        $adapter = new AfterCommit(static function () use (&$calls, $first, $second): DatabaseTransactionsManager {
            return ++$calls === 1 ? $first : $second;
        });

        $adapter->run(null, $this->counted());
        $adapter->run(null, $this->counted());

        self::assertSame(2, $calls);
        self::assertSame(0, $this->runs);

        $first->commit('main', 1, 0);

        self::assertSame(1, $this->runs);

        $second->commit('main', 1, 0);

        self::assertSame(2, $this->runs);
    }

    /**
     * The testing manager's wrapping transaction is never selected, with or
     * without a name, so a test wrapped in a transaction sees the callback run
     * at once, as an application with no transaction would.
     *
     * @return void
     */
    public function testTheTestingManagersWrapperIsNotSelected(): void
    {
        $manager = new TestingTransactionsManager(['main']);

        $manager->begin('main', 1);

        $this->adapter($manager)->run(null, $this->counted());

        self::assertSame(1, $this->runs);

        $this->adapter($manager)->run('main', $this->counted());

        self::assertSame(2, $this->runs);
    }

    /**
     * A transaction opened inside the testing wrapper is selected, and its
     * commit runs the callback though the wrapper stays open.
     *
     * @return void
     */
    public function testATransactionInsideTheTestingWrapperIsSelected(): void
    {
        $manager = new TestingTransactionsManager(['main']);

        $manager->begin('main', 1);
        $manager->begin('main', 2);

        $this->adapter($manager)->run('main', $this->counted());

        self::assertSame(0, $this->runs);

        $manager->commit('main', 2, 1);

        self::assertSame(1, $this->runs);
    }

    /**
     * An exception from a callback run at once reaches the caller.
     *
     * @return void
     */
    public function testAnExceptionFromTheCallbackPropagates(): void
    {
        $exception = new \RuntimeException('The write failed.');

        $this->expectExceptionObject($exception);

        (new AfterCommit(static fn (): mixed => null))->run(null, static function () use ($exception): void {
            throw $exception;
        });
    }

    /**
     * An exception from a deferred callback reaches the code that commits.
     *
     * @return void
     */
    public function testAnExceptionFromADeferredCallbackReachesTheCommit(): void
    {
        $manager   = new DatabaseTransactionsManager;
        $exception = new \RuntimeException('The write failed.');

        $manager->begin('main', 1);

        $this->adapter($manager)->run(null, static function () use ($exception): void {
            throw $exception;
        });

        $this->expectExceptionObject($exception);

        $manager->commit('main', 1, 0);
    }

    /**
     * An adapter whose manager is the one given.
     *
     * @param  \Illuminate\Database\DatabaseTransactionsManager  $manager
     * @return \SineMacula\Laravel\AuditLog\Database\AfterCommit
     */
    private function adapter(DatabaseTransactionsManager $manager): AfterCommit
    {
        return new AfterCommit(static fn (): DatabaseTransactionsManager => $manager);
    }

    /**
     * A callback that counts its runs.
     *
     * @return \Closure(): void
     */
    private function counted(): \Closure
    {
        return function (): void {
            $this->runs++;
        };
    }
}
