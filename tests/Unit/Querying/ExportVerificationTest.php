<?php

declare(strict_types = 1);

namespace Tests\Unit\Querying;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Querying\Enums\ExportFinding;
use SineMacula\Laravel\AuditLog\Querying\ExportVerification;

/**
 * Unit tests for the result of an export's verification.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExportVerification::class)]
final class ExportVerificationTest extends TestCase
{
    /** @var string The id of the export entry every verification names. */
    private const string ENTRY_ID = '01932b4e-a000-7000-8000-000000000001';

    /**
     * A verification is verified only when it found nothing.
     *
     * @return void
     */
    public function testIsVerifiedOnlyWithoutAFinding(): void
    {
        self::assertTrue((new ExportVerification(self::ENTRY_ID, 3, []))->isVerified());
        self::assertFalse((new ExportVerification(self::ENTRY_ID, 3, [ExportFinding::LINE_TAMPERED]))->isVerified());
        self::assertFalse((new ExportVerification(null, 0, [ExportFinding::BUNDLE_MALFORMED]))->isVerified());
    }

    /**
     * The entry's id, line count and findings are kept as given, in order.
     *
     * @return void
     */
    public function testKeepsItsFields(): void
    {
        $verification = new ExportVerification(self::ENTRY_ID, 2, [ExportFinding::FILE_MISMATCH, ExportFinding::MEMBERSHIP_MISMATCH]);

        self::assertSame(self::ENTRY_ID, $verification->entryId);
        self::assertSame(2, $verification->lines);
        self::assertSame([ExportFinding::FILE_MISMATCH, ExportFinding::MEMBERSHIP_MISMATCH], $verification->findings);
    }

    /**
     * A verification of a bundle that names no entry keeps no id.
     *
     * @return void
     */
    public function testAnEntryIdMayBeAbsent(): void
    {
        self::assertNull((new ExportVerification(null, 0, [ExportFinding::BUNDLE_MALFORMED]))->entryId);
    }
}
