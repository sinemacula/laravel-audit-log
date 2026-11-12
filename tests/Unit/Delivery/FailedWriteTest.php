<?php

declare(strict_types = 1);

namespace Tests\Unit\Delivery;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Delivery\FailedWrite;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Stores\Enums\FailedOperation;
use Tests\Fixtures\Records\RecordFactory;

/**
 * Unit tests for a failed write: the fields it keeps and the values it hides
 * from stack frames.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FailedWrite::class)]
final class FailedWriteTest extends TestCase
{
    /**
     * A failed write keeps each field as given.
     *
     * @return void
     */
    public function testKeepsItsFields(): void
    {
        $record    = RecordFactory::captured();
        $finalised = new FinalisedRecord($record, '2026-11-01T12:00:00.200000Z', 1, 'k1', str_repeat('a', 64));
        $failure   = new \RuntimeException('The store is unreachable.');

        $failed = new FailedWrite($record, $finalised, $failure, FailedOperation::STORE, 'Tests\Fixtures\Stores\PlainStore', 'testing', true);

        self::assertSame($record, $failed->record);
        self::assertSame($finalised, $failed->finalised);
        self::assertSame($failure, $failed->failure);
        self::assertSame(FailedOperation::STORE, $failed->operation);
        self::assertSame('Tests\Fixtures\Stores\PlainStore', $failed->store);
        self::assertSame('testing', $failed->connection);
        self::assertTrue($failed->hostOpen);
    }

    /**
     * A write that failed before it was finalised, on no connection and with no
     * transaction open, keeps `null` and `false` as given.
     *
     * @return void
     */
    public function testKeepsAnUnfinalisedWriteOnNoConnection(): void
    {
        $failed = new FailedWrite(RecordFactory::captured(), null, new \LogicException('No key.'), FailedOperation::FINALISE, 'store', null, false);

        self::assertNull($failed->finalised);
        self::assertNull($failed->connection);
        self::assertFalse($failed->hostOpen);
    }

    /**
     * Every connection a transaction was open on includes the one written on,
     * once, and only when a transaction was open there.
     *
     * @return void
     */
    public function testNamesEveryConnectionATransactionWasOpenOn(): void
    {
        self::assertSame(['host'], self::failedOn('audit', false, ['host'])->openConnections());
        self::assertSame(['host', 'audit'], self::failedOn('audit', true, ['host'])->openConnections());
        self::assertSame(['host', 'other', 'audit'], self::failedOn('audit', true, ['host', 'other'])->openConnections());
        self::assertSame(['audit'], self::failedOn('audit', true, [])->openConnections());
        self::assertSame(['audit'], self::failedOn('audit', true, ['audit'])->openConnections());
        self::assertSame(['host'], self::failedOn(null, true, ['host'])->openConnections());
        self::assertSame([], self::failedOn('audit', false, [])->openConnections());
    }

    /**
     * The record, the finalised record and the failure are marked sensitive;
     * the other parameters are not.
     *
     * @return void
     */
    public function testThePayloadsAreSensitive(): void
    {
        $sensitive = [];

        foreach ((new \ReflectionMethod(FailedWrite::class, '__construct'))->getParameters() as $parameter) {
            $sensitive[$parameter->getName()] = $parameter->getAttributes(\SensitiveParameter::class) !== [];
        }

        self::assertSame([
            'record'           => true,
            'finalised'        => true,
            'failure'          => true,
            'operation'        => false,
            'store'            => false,
            'connection'       => false,
            'hostOpen'         => false,
            'openTransactions' => false,
        ], $sensitive);
    }

    /**
     * A failed store of a captured record on the connection named, with a
     * transaction open there or not, and open on the connections given.
     *
     * @param  ?string  $name
     * @param  bool  $open
     * @param  list<string>  $all
     * @return \SineMacula\Laravel\AuditLog\Delivery\FailedWrite
     */
    private static function failedOn(?string $name, bool $open, array $all): FailedWrite
    {
        return new FailedWrite(RecordFactory::captured(), null, new \RuntimeException('Failed.'), FailedOperation::STORE, 's', $name, $open, $all);
    }
}
