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
    /**
     * With no name the innermost pending transaction is selected, whichever
     * connection it is on.
     *
     * @return void
     */
    public function testSelectedIsTheInnermostOnAnyConnection(): void
    {
        $manager = new DatabaseTransactionsManager;

        $manager->begin('main', 1);
        $manager->begin('other', 1);

        $selected = $this->adapter($manager)->selected(null);

        self::assertNotNull($selected);
        self::assertSame('other', $selected->connection);
        self::assertSame(1, $selected->level);

        $manager->begin('main', 2);

        $selected = $this->adapter($manager)->selected(null);

        self::assertNotNull($selected);
        self::assertSame('main', $selected->connection);
        self::assertSame(2, $selected->level);
    }

    /**
     * With a name the selection is that connection's innermost, though a later
     * transaction is open elsewhere, and `null` on a connection with none.
     *
     * @return void
     */
    public function testSelectedPinsAConnection(): void
    {
        $manager = new DatabaseTransactionsManager;

        $manager->begin('main', 1);
        $manager->begin('main', 2);
        $manager->begin('other', 1);

        $selected = $this->adapter($manager)->selected('main');

        self::assertNotNull($selected);
        self::assertSame('main', $selected->connection);
        self::assertSame(2, $selected->level);
        self::assertNull($this->adapter($manager)->selected('third'));
    }

    /**
     * With a manager and nothing pending there is nothing to select, by name or
     * without one.
     *
     * @return void
     */
    public function testSelectedIsNullWithNoneOpen(): void
    {
        $manager = new DatabaseTransactionsManager;

        self::assertNull($this->adapter($manager)->selected(null));
        self::assertNull($this->adapter($manager)->selected('main'));

        $manager->begin('main', 1);
        $manager->commit('main', 1, 0);

        self::assertNull($this->adapter($manager)->selected(null));

        $manager->begin('main', 1);
        $manager->rollback('main', 0);

        self::assertNull($this->adapter($manager)->selected('main'));
    }

    /**
     * The testing manager's wrapper is never selected, though the connection is
     * at level 1, and the transaction opened inside it is.
     *
     * @return void
     */
    public function testSelectedLeavesOutTheTestingWrapper(): void
    {
        $manager = new TestingTransactionsManager(['main']);

        $manager->begin('main', 1);

        self::assertNull($this->adapter($manager)->selected(null));
        self::assertNull($this->adapter($manager)->selected('main'));

        $manager->begin('main', 2);

        $selected = $this->adapter($manager)->selected('main');

        self::assertNotNull($selected);
        self::assertSame(2, $selected->level);
    }

    /**
     * With no manager, or with something that is not one, nothing is selected.
     *
     * @return void
     */
    public function testSelectedIsNullWithNoManager(): void
    {
        self::assertNull((new AfterCommit(static fn (): mixed => null))->selected(null));
        self::assertNull((new AfterCommit(static fn (): mixed => new \stdClass))->selected('main'));
    }

    /**
     * Selecting resolves the manager on every call, so one swapped in after the
     * adapter was made is the one consulted.
     *
     * @return void
     */
    public function testSelectedResolvesTheManagerOnEveryCall(): void
    {
        $first  = new DatabaseTransactionsManager;
        $second = new DatabaseTransactionsManager;
        $calls  = 0;

        $second->begin('main', 1);

        $adapter = new AfterCommit(static function () use (&$calls, $first, $second): DatabaseTransactionsManager {
            return ++$calls === 1 ? $first : $second;
        });

        self::assertNull($adapter->selected(null));
        self::assertNotNull($adapter->selected(null));
        self::assertSame(2, $calls);
    }

    /**
     * The closure the adapter takes is marked sensitive, so no frame shows what
     * it holds.
     *
     * @return void
     */
    public function testTheManagerResolverIsMarkedSensitive(): void
    {
        $transactions = new \ReflectionParameter([AfterCommit::class, '__construct'], 'transactions');

        self::assertNotSame([], $transactions->getAttributes(\SensitiveParameter::class));
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
}
