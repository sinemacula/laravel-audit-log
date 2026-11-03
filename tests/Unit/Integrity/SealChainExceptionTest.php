<?php

declare(strict_types = 1);

namespace Tests\Unit\Integrity;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Integrity\SealChainException;

/**
 * Unit tests for the seal chain exception: the message for a last seal whose
 * digest disagrees and for one of another log, the seal and finding each names,
 * the class it specialises, and the absence of any exception it could carry.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SealChainException::class)]
final class SealChainExceptionTest extends TestCase
{
    /** @var string A seal id. */
    private const string SEAL_ID = '01932b4e-9000-7000-8000-000000000001';

    /**
     * A last seal whose digest disagrees is refused with the fixed message.
     *
     * @return void
     */
    public function testTheHeadMessageIsPinned(): void
    {
        self::assertSame(
            'The last seal\'s stored digest does not match its fields, so no seal is chained onto it; run audit-log:verify.',
            SealChainException::forHead(self::SEAL_ID)->getMessage(),
        );
    }

    /**
     * A last seal of another log is refused with the fixed message.
     *
     * @return void
     */
    public function testTheLogMessageIsPinned(): void
    {
        self::assertSame(
            'The last seal belongs to another log id, so no seal is chained onto it; the log id must not change once a seal exists.',
            SealChainException::forLog(self::SEAL_ID)->getMessage(),
        );
    }

    /**
     * Each refusal names the last seal and the finding it gives: the seal
     * digest for a digest that disagrees, the log mismatch for another log.
     *
     * @return void
     */
    public function testEachNamesItsFinding(): void
    {
        $head = SealChainException::forHead(self::SEAL_ID);
        $log  = SealChainException::forLog('01932b4e-9000-7000-8000-000000000002');

        self::assertSame(self::SEAL_ID, $head->sealId);
        self::assertSame(Finding::SEAL_DIGEST, $head->finding);
        self::assertSame('01932b4e-9000-7000-8000-000000000002', $log->sealId);
        self::assertSame(Finding::LOG_MISMATCH, $log->finding);
    }

    /**
     * Neither refusal carries another exception, nor can be given one.
     *
     * @return void
     */
    public function testHasNoPrevious(): void
    {
        $constructor = new \ReflectionMethod(SealChainException::class, '__construct');

        self::assertNull(SealChainException::forHead(self::SEAL_ID)->getPrevious());
        self::assertNull(SealChainException::forLog(self::SEAL_ID)->getPrevious());
        self::assertTrue($constructor->isPrivate());
        self::assertSame(['message', 'sealId', 'finding'], array_map(static fn (\ReflectionParameter $parameter): string => $parameter->getName(), $constructor->getParameters()));
    }

    /**
     * The refusal is a final unexpected value: the stored seal is not what it
     * must be.
     *
     * @return void
     */
    public function testIsAnUnexpectedValue(): void
    {
        self::assertInstanceOf(\UnexpectedValueException::class, SealChainException::forHead(self::SEAL_ID));
        self::assertSame(0, SealChainException::forLog(self::SEAL_ID)->getCode());
        self::assertTrue((new \ReflectionClass(SealChainException::class))->isFinal());
    }
}
