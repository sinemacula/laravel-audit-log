<?php

declare(strict_types = 1);

namespace Tests\Unit\Integrity;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Integrity\SealEnvelope;
use SineMacula\Laravel\AuditLog\Integrity\SealSummary;

/**
 * Unit tests for the seal summary: the tuple it keeps, taken from an envelope
 * and the digest given, its canonical form pinned by the golden anchor bytes,
 * the comparison of every field, and each malformed field refused.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SealSummary::class)]
final class SealSummaryTest extends TestCase
{
    /** @var string The golden seal vectors. */
    private const string GOLDEN = __DIR__ . '/../../Fixtures/Integrity/seal-v1.json';

    /** @var string The golden first seal's id. */
    private const string SEAL_ID = '01932b4e-9000-7000-8000-000000000001';

    /** @var string The golden first seal's digest. */
    private const string DIGEST = '81472ef9f38d641924cf10f61fa9b5c57f5c7dfbd10c8b7d26bcc3259dde7069';

    /**
     * The summary keeps the log, the sequence, the seal id and the digest as
     * given.
     *
     * @return void
     */
    public function testKeepsTheTuple(): void
    {
        $summary = new SealSummary('app-eu-1', 1, self::SEAL_ID, self::DIGEST);

        self::assertSame('app-eu-1', $summary->logId);
        self::assertSame(1, $summary->sequence);
        self::assertSame(self::SEAL_ID, $summary->sealId);
        self::assertSame(self::DIGEST, $summary->sealDigest);
        self::assertSame(1, SealSummary::VERSION);
    }

    /**
     * A summary of an envelope takes its log, sequence and id, and the digest
     * the caller gives, which the caller recomputes rather than reads.
     *
     * @return void
     */
    public function testOfTakesTheEnvelopesFields(): void
    {
        $at      = '2026-10-31T23:36:00.000000Z';
        $seal    = new SealEnvelope('app-eu-1', '01932b4e-9000-7000-8000-000000000007', 7, self::SEAL_ID, self::DIGEST, 1, str_repeat('c', 64), $at, $at, $at, 'k2026');
        $summary = SealSummary::of($seal, $seal->digest());

        self::assertSame('app-eu-1', $summary->logId);
        self::assertSame(7, $summary->sequence);
        self::assertSame('01932b4e-9000-7000-8000-000000000007', $summary->sealId);
        self::assertSame($seal->digest(), $summary->sealDigest);
        self::assertSame(str_repeat('f', 64), SealSummary::of($seal, str_repeat('f', 64))->sealDigest);
    }

    /**
     * The canonical form of the golden first seal's summary is the golden
     * anchor's bytes, with the golden SHA-256.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheCanonicalFormIsPinned(): void
    {
        $summary = new SealSummary('app-eu-1', 1, self::SEAL_ID, self::DIGEST);
        $bytes   = CanonicalEncoder::encode($summary->toArray());

        self::assertSame(['v' => 1, 'log_id' => 'app-eu-1', 'sequence' => 1, 'seal_id' => self::SEAL_ID, 'seal_digest' => self::DIGEST], $summary->toArray());
        self::assertSame(self::golden('anchor_bytes'), $bytes);
        self::assertSame(self::golden('anchor_sha256'), hash('sha256', $bytes));
        self::assertSame(self::golden('seal_1_digest'), self::DIGEST);
    }

    /**
     * Two summaries are the same only when every one of the four fields is; a
     * change to any one makes them differ, each way round.
     *
     * @return void
     */
    public function testIsSameAsComparesEveryField(): void
    {
        $summary = new SealSummary('app-eu-1', 1, self::SEAL_ID, self::DIGEST);

        self::assertTrue($summary->isSameAs(new SealSummary('app-eu-1', 1, self::SEAL_ID, self::DIGEST)));
        self::assertTrue($summary->isSameAs($summary));

        $others = [
            'log id'   => new SealSummary('app-eu-2', 1, self::SEAL_ID, self::DIGEST),
            'sequence' => new SealSummary('app-eu-1', 2, self::SEAL_ID, self::DIGEST),
            'seal id'  => new SealSummary('app-eu-1', 1, '01932b4e-9000-7000-8000-000000000002', self::DIGEST),
            'digest'   => new SealSummary('app-eu-1', 1, self::SEAL_ID, str_repeat('a', 64)),
        ];

        foreach ($others as $what => $other) {
            self::assertFalse($summary->isSameAs($other), $what);
            self::assertFalse($other->isSameAs($summary), $what);
        }
    }

    /**
     * Rows of `[log id, sequence, seal id, digest, message]`: one or more for
     * each field.
     *
     * @return iterable<string, array{0: string, 1: int, 2: string, 3: string, 4: string}>
     */
    public static function provideMalformedFields(): iterable
    {
        $logId  = 'A seal summary\'s `log_id` must be 1 to 64 letters, digits, dots, underscores or hyphens, starting with a letter or a digit.';
        $id     = 'A seal summary\'s `seal_id` must be a lower-case UUID.';
        $digest = 'A seal summary\'s `seal_digest` must be 64 lower-case hexadecimal characters.';

        yield from [
            'an empty log id'           => ['', 1, self::SEAL_ID, self::DIGEST, $logId],
            'a log id with a slash'     => ['app/eu', 1, self::SEAL_ID, self::DIGEST, $logId],
            'a log id of two dots'      => ['..', 1, self::SEAL_ID, self::DIGEST, $logId],
            'a log id of 65 characters' => [str_repeat('a', 65), 1, self::SEAL_ID, self::DIGEST, $logId],
            'a sequence of 0'           => ['app-eu-1', 0, self::SEAL_ID, self::DIGEST, 'A seal summary\'s `sequence` must be at least 1.'],
            'an upper-case seal id'     => ['app-eu-1', 1, strtoupper(self::SEAL_ID), self::DIGEST, $id],
            'a seal id that is no UUID' => ['app-eu-1', 1, 'seal-1', self::DIGEST, $id],
            'a short digest'            => ['app-eu-1', 1, self::SEAL_ID, substr(self::DIGEST, 1), $digest],
            'an upper-case digest'      => ['app-eu-1', 1, self::SEAL_ID, strtoupper(self::DIGEST), $digest],
        ];
    }

    /**
     * Each malformed field is refused with its message.
     *
     * @param  string  $logId
     * @param  int  $sequence
     * @param  string  $sealId
     * @param  string  $digest
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMalformedFields')]
    public function testRefusesEachMalformedField(string $logId, int $sequence, string $sealId, string $digest, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        new SealSummary($logId, $sequence, $sealId, $digest);
    }

    /**
     * The longest log id and the greatest sequence are kept.
     *
     * @return void
     */
    public function testAcceptsEachBoundary(): void
    {
        $summary = new SealSummary(str_repeat('a', 64), PHP_INT_MAX, self::SEAL_ID, self::DIGEST);

        self::assertSame(str_repeat('a', 64), $summary->logId);
        self::assertSame(PHP_INT_MAX, $summary->sequence);
    }

    /**
     * The golden string under the key given.
     *
     * @param  string  $field
     * @return string
     *
     * @throws \JsonException
     */
    private static function golden(string $field): string
    {
        $golden = json_decode((string) file_get_contents(self::GOLDEN), true, 512, JSON_THROW_ON_ERROR);
        $value  = is_array($golden) ? ($golden[$field] ?? null) : null;

        return is_string($value) ? $value : self::fail(sprintf('The golden seal has no `%s`.', $field));
    }
}
