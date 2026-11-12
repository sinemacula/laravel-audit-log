<?php

declare(strict_types = 1);

namespace Tests\Unit\Delivery;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Delivery\PackageWrite;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use Tests\Fixtures\Records\RecordFactory;

/**
 * Unit tests for what the read path asks of a record it writes: the check
 * before delivery and the hand-over after.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PackageWrite::class)]
final class PackageWriteTest extends TestCase
{
    /**
     * Both closures are kept as given, each its own.
     *
     * @return void
     */
    public function testHoldsBothClosures(): void
    {
        $accept       = static function (AuditRecord $record): void {};
        $acknowledged = static function (FinalisedRecord $record): void {};

        $write = new PackageWrite($accept, $acknowledged);

        self::assertSame($accept, $write->accept);
        self::assertSame($acknowledged, $write->acknowledged);
    }

    /**
     * Each step runs only its own closure, and the check's exception propagates
     * as it is.
     *
     * @return void
     */
    public function testChecksAndAcknowledgesThroughItsClosures(): void
    {
        $record    = RecordFactory::captured();
        $finalised = new FinalisedRecord($record, '2026-11-01T12:00:09.500000Z', 1, 'k1', str_repeat('a', 64));
        $calls     = [];
        $refusal   = new \RuntimeException('The evidence was altered.');

        $write = new PackageWrite(
            static function (AuditRecord $checked) use (&$calls, $record): void {
                $calls[] = ['accept', $checked === $record];
            },
            static function (FinalisedRecord $handed) use (&$calls, $finalised): void {
                $calls[] = ['acknowledged', $handed === $finalised];
            },
        );

        $write->check($record);
        $write->acknowledge($finalised);

        self::assertSame([['accept', true], ['acknowledged', true]], $calls);

        $refusing = new PackageWrite(static function () use ($refusal): never {
            throw $refusal;
        }, static function (): void {});

        try {
            $refusing->check($record);

            self::fail('Expected the check\'s refusal to propagate.');
        } catch (\RuntimeException $exception) {
            self::assertSame($refusal, $exception);
        }
    }

    /**
     * Both closures are marked sensitive, since each captures what a read
     * disclosed, and the value is read-only.
     *
     * @return void
     */
    public function testBothClosuresAreMarkedSensitive(): void
    {
        $parameters = (new \ReflectionMethod(PackageWrite::class, '__construct'))->getParameters();

        self::assertSame(['accept', 'acknowledged'], array_map(static fn (\ReflectionParameter $parameter): string => $parameter->getName(), $parameters));

        foreach ($parameters as $parameter) {
            self::assertNotSame([], $parameter->getAttributes(\SensitiveParameter::class), $parameter->getName());
        }

        foreach (['check', 'acknowledge'] as $method) {
            $parameter = (new \ReflectionMethod(PackageWrite::class, $method))->getParameters()[0];

            self::assertNotSame([], $parameter->getAttributes(\SensitiveParameter::class), $method);
        }

        self::assertTrue((new \ReflectionClass(PackageWrite::class))->isReadOnly());
    }
}
