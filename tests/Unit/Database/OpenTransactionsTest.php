<?php

declare(strict_types = 1);

namespace Tests\Unit\Database;

use Illuminate\Database\Connection;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\DatabaseManager;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Database\OpenTransactions;

/**
 * Unit tests for the read of which connections have a transaction open: every
 * connection a manager holds, by its own name, without opening one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OpenTransactions::class)]
final class OpenTransactionsTest extends TestCase
{
    /**
     * Only a connection with a transaction open is named, once, by its own name
     * or else the manager's key.
     *
     * @return void
     */
    public function testNamesEachConnectionWithATransactionOpen(): void
    {
        $manager = \Mockery::mock(DatabaseManager::class);

        $manager->allows('getConnections')->andReturn([
            'main'           => self::connection('main', 1),
            'main::write'    => self::connection('main', 2),
            'idle'           => self::connection('idle', 0),
            'selector::read' => self::connection(null, 1),
        ]);

        self::assertSame(['main', 'selector::read'], (new OpenTransactions($manager))->names());
    }

    /**
     * A resolver that does not say which connections it holds names none.
     *
     * @return void
     */
    public function testAnyOtherResolverNamesNone(): void
    {
        self::assertSame([], (new OpenTransactions(\Mockery::mock(ConnectionResolverInterface::class)))->names());
    }

    /**
     * A connection with the name and the transaction level.
     *
     * @param  ?string  $name
     * @param  int  $level
     * @return \Illuminate\Database\Connection
     */
    private static function connection(?string $name, int $level): Connection
    {
        $connection = \Mockery::mock(Connection::class);

        $connection->allows('getName')->andReturn($name);
        $connection->allows('transactionLevel')->andReturn($level);

        return $connection;
    }
}
