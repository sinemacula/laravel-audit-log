<?php

declare(strict_types = 1);

namespace Tests\Unit\Integrity;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Integrity\SealChainException;

/**
 * Unit tests for the seal chain exception.
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
     * A journal head that cannot be read is refused with the fixed message,
     * which names no value of the row.
     *
     * @return void
     */
    public function testTheJournalMessageIsPinned(): void
    {
        self::assertSame(
            'The lifecycle journal\'s last row has a malformed sequence or HMAC, so no seal commits to it; run audit-log:verify.',
            SealChainException::forJournal()->getMessage(),
        );
    }

    /**
     * A journal behind the last seal's commitment names that seal with the
     * commitment finding.
     *
     * @return void
     */
    public function testAJournalBehindTheCommitmentNamesTheSeal(): void
    {
        $behind = SealChainException::forJournalBehind('01932b4e-c000-7000-8000-000000000001');

        self::assertSame('The lifecycle journal\'s head is behind the last seal\'s commitment to it, so no seal commits to it; run audit-log:verify.', $behind->getMessage());
        self::assertSame('01932b4e-c000-7000-8000-000000000001', $behind->sealId);
        self::assertSame(Finding::JOURNAL_COMMITMENT, $behind->finding);
        self::assertNull($behind->getPrevious());
        self::assertSame(0, $behind->getCode());
    }

    /**
     * The journal's refusal names no seal, since it is of the journal's head,
     * and gives the finding of a journal row that cannot be read.
     *
     * @return void
     */
    public function testTheJournalRefusalNamesNoSealAndIsMalformed(): void
    {
        $journal = SealChainException::forJournal();

        self::assertNull($journal->sealId);
        self::assertSame(Finding::JOURNAL_MALFORMED, $journal->finding);
        self::assertNull($journal->getPrevious());
        self::assertSame(0, $journal->getCode());
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
