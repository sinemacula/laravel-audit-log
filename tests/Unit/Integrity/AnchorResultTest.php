<?php

declare(strict_types = 1);

namespace Tests\Unit\Integrity;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\AnchorResult;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;

/**
 * Unit tests for the tally of one anchoring pass.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AnchorResult::class)]
final class AnchorResultTest extends TestCase
{
    /** @var string The id of a seal the tests record. */
    private const string SEAL_ID = '01932b4e-9000-7000-8000-000000000001';

    /** @var string The id of another seal the tests record. */
    private const string OTHER_SEAL_ID = '01932b4e-9000-7000-8000-000000000002';

    /**
     * A pass starts configured, with nothing anchored, unavailable, conflicted
     * or refused, and neither alarms nor stops.
     *
     * @return void
     */
    public function testStartsEmpty(): void
    {
        $result = new AnchorResult;

        self::assertTrue($result->isConfigured());
        self::assertSame(0, $result->anchoredCount());
        self::assertNull($result->lastAnchored());
        self::assertNull($result->unavailableClass());
        self::assertNull($result->waitingFrom());
        self::assertNull($result->conflict());
        self::assertNull($result->refusal());
        self::assertFalse($result->isAlarm());
        self::assertFalse($result->isStopped());
    }

    /**
     * A pass with no anchor configured says so, and holds nothing else.
     *
     * @return void
     */
    public function testAPassWithNoAnchorIsNotConfigured(): void
    {
        $result = new AnchorResult(false);

        self::assertFalse($result->isConfigured());
        self::assertSame(0, $result->anchoredCount());
        self::assertFalse($result->isStopped());
    }

    /**
     * Each seal anchored counts once, and the last one is kept.
     *
     * @return void
     */
    public function testCountsAnchoredSeals(): void
    {
        $result = new AnchorResult;

        $result->anchored(4);
        $result->anchored(5);
        $result->anchored(6);

        self::assertSame(3, $result->anchoredCount());
        self::assertSame(6, $result->lastAnchored());
        self::assertFalse($result->isAlarm());
        self::assertFalse($result->isStopped());
    }

    /**
     * The first unavailable class and its sequence are kept, a later one
     * ignored, and an unavailable anchor stops the pass without alarming.
     *
     * @return void
     */
    public function testKeepsTheFirstUnavailableClass(): void
    {
        $result = new AnchorResult;

        $result->unavailable(7, \RuntimeException::class);
        $result->unavailable(9, \LogicException::class);

        self::assertSame(\RuntimeException::class, $result->unavailableClass());
        self::assertSame(7, $result->waitingFrom());
        self::assertFalse($result->isAlarm());
        self::assertTrue($result->isStopped());
    }

    /**
     * An anchor unavailable before any seal waits from none, and a later
     * sequence does not replace that first record.
     *
     * @return void
     */
    public function testAnAnchorUnavailableBeforeAnySealWaitsFromNone(): void
    {
        $result = new AnchorResult;

        $result->unavailable(null, \UnexpectedValueException::class);
        $result->unavailable(3, \RuntimeException::class);

        self::assertSame(\UnexpectedValueException::class, $result->unavailableClass());
        self::assertNull($result->waitingFrom());
        self::assertTrue($result->isStopped());
    }

    /**
     * A conflict and a refusal each alarm and stop the pass, and each keeps
     * what it names.
     *
     * @return void
     */
    public function testAConflictOrARefusalIsAnAlarm(): void
    {
        $conflicted = new AnchorResult;
        $refused    = new AnchorResult;

        $conflicted->conflicted(2, self::SEAL_ID);
        $refused->refused(3, self::SEAL_ID, Finding::SEAL_DIGEST);

        self::assertSame(['sequence' => 2, 'sealId' => self::SEAL_ID], $conflicted->conflict());
        self::assertNull($conflicted->refusal());
        self::assertTrue($conflicted->isAlarm());
        self::assertTrue($conflicted->isStopped());

        self::assertSame(['sequence' => 3, 'sealId' => self::SEAL_ID, 'finding' => Finding::SEAL_DIGEST], $refused->refusal());
        self::assertNull($refused->conflict());
        self::assertTrue($refused->isAlarm());
        self::assertTrue($refused->isStopped());
    }

    /**
     * Only the first conflict and the first refusal are kept.
     *
     * @return void
     */
    public function testKeepsTheFirstConflictAndRefusal(): void
    {
        $result = new AnchorResult;

        $result->conflicted(2, self::SEAL_ID);
        $result->conflicted(5, self::OTHER_SEAL_ID);
        $result->refused(3, self::SEAL_ID, Finding::SEAL_KEY);
        $result->refused(6, self::OTHER_SEAL_ID, Finding::SEAL_SIGNATURE);

        self::assertSame(['sequence' => 2, 'sealId' => self::SEAL_ID], $result->conflict());
        self::assertSame(['sequence' => 3, 'sealId' => self::SEAL_ID, 'finding' => Finding::SEAL_KEY], $result->refusal());
    }

    /**
     * A seal whose id is malformed is refused without naming one.
     *
     * @return void
     */
    public function testARefusalMayNameNoId(): void
    {
        $result = new AnchorResult;

        $result->refused(8, null, Finding::SEAL_MALFORMED);

        self::assertSame(['sequence' => 8, 'sealId' => null, 'finding' => Finding::SEAL_MALFORMED], $result->refusal());
        self::assertTrue($result->isAlarm());
    }
}
