<?php

declare(strict_types = 1);

namespace Tests\Unit\Integrity;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\AnchoredHead;
use SineMacula\Laravel\AuditLog\Integrity\VerificationContext;

/**
 * Unit tests for what every segment of one run shares.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(VerificationContext::class)]
final class VerificationContextTest extends TestCase
{
    /** @var string When the grace starts. */
    private const string GRACE_FROM = '2026-11-01T12:45:00.000000Z';

    /** @var string When the grace ends: the run's clock. */
    private const string GRACE_TO = '2026-11-01T13:00:00.000000Z';

    /** @var string A seal's digest. */
    private const string DIGEST = '329162defc18f3f10f3a8a351a7faa0c0e5e1004d65ea3b432feb0b54d3282c6';

    /**
     * The context keeps the head, whether to ask, the grace's start and end,
     * and whether the head settles anchoring, as given; by default it does not.
     *
     * @return void
     */
    public function testKeepsWhatTheRunShares(): void
    {
        $remote  = new AnchoredHead(4, self::DIGEST);
        $context = new VerificationContext($remote, true, self::GRACE_FROM, self::GRACE_TO, true);

        self::assertSame($remote, $context->remote);
        self::assertTrue($context->askAnchor);
        self::assertSame(self::GRACE_FROM, $context->graceFrom);
        self::assertSame(self::GRACE_TO, $context->graceTo);
        self::assertTrue($context->byHead);
        self::assertNull((new VerificationContext(null, false, self::GRACE_FROM, self::GRACE_TO))->remote);
        self::assertFalse((new VerificationContext(null, false, self::GRACE_FROM, self::GRACE_TO))->byHead);
    }

    /**
     * Without the anchor the context stops asking it and keeps the rest; the
     * original is unchanged.
     *
     * @return void
     */
    public function testWithoutAnchorStopsAsking(): void
    {
        $remote  = new AnchoredHead(4, self::DIGEST);
        $context = new VerificationContext($remote, true, self::GRACE_FROM, self::GRACE_TO, true);
        $without = $context->withoutAnchor();

        self::assertFalse($without->askAnchor);
        self::assertSame($remote, $without->remote);
        self::assertSame(self::GRACE_FROM, $without->graceFrom);
        self::assertSame(self::GRACE_TO, $without->graceTo);
        self::assertTrue($without->byHead);
        self::assertTrue($context->askAnchor);
        self::assertFalse($without->withoutAnchor()->askAnchor);
    }

    /**
     * Rows of `[grace start, grace end]`: an end of the grace that is not an
     * instant in the package's form, or a start after the end.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideRefusedGraces(): iterable
    {
        yield from [
            'a start not an instant' => ['2026-11-01 12:45:00', self::GRACE_TO],
            'an end not an instant'  => [self::GRACE_FROM, '2026-11-01 13:00:00'],
            'a start after the end'  => [self::GRACE_TO, self::GRACE_FROM],
        ];
    }

    /**
     * A grace whose ends are not instants in the package's form, or that runs
     * backwards, is refused.
     *
     * @param  string  $from
     * @param  string  $to
     * @return void
     */
    #[DataProvider('provideRefusedGraces')]
    public function testRefusesAGraceThatIsNotARunOfInstants(string $from, string $to): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A verification\'s grace must run between two ISO-8601 UTC instants with microseconds, the first not after the second.');

        new VerificationContext(null, true, $from, $to);
    }

    /**
     * A grace that starts and ends at the same instant is accepted.
     *
     * @return void
     */
    public function testAGraceOfOneInstantIsAccepted(): void
    {
        self::assertSame(self::GRACE_TO, (new VerificationContext(null, true, self::GRACE_TO, self::GRACE_TO))->graceFrom);
    }
}
