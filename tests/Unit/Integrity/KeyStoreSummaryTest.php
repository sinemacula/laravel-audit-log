<?php

declare(strict_types = 1);

namespace Tests\Unit\Integrity;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Integrity\KeyStoreSummary;

/**
 * Unit tests for the summary of the key store's verification.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(KeyStoreSummary::class)]
final class KeyStoreSummaryTest extends TestCase
{
    /** @var string The class of an encrypter the verification is skipped for. */
    private const string ENCRYPTER = 'App\Privacy\VaultEncrypter';

    /**
     * A verification that ran keeps its counts, is not skipped and names no
     * encrypter, in its properties and its array form alike.
     *
     * @return void
     */
    public function testItKeepsTheCountsOfAVerificationThatRan(): void
    {
        $summary = new KeyStoreSummary(12, 3, 2);

        self::assertSame(12, $summary->keys);
        self::assertSame(3, $summary->erased);
        self::assertSame(2, $summary->findings);
        self::assertFalse($summary->skipped);
        self::assertNull($summary->encrypter);
        self::assertSame(['keys' => 12, 'erased' => 3, 'findings' => 2, 'skipped' => false, 'encrypter' => null], $summary->toArray());
    }

    /**
     * A skipped verification counts nothing and is skipped, before it names the
     * encrypter it was skipped for.
     *
     * @return void
     */
    public function testASkippedVerificationCountsNothing(): void
    {
        self::assertSame(['keys' => 0, 'erased' => 0, 'findings' => 0, 'skipped' => true, 'encrypter' => null], KeyStoreSummary::skipped()->toArray());
    }

    /**
     * Only a skipped verification names the encrypter it was skipped for.
     *
     * @return void
     */
    public function testOnlyASkippedVerificationNamesTheEncrypter(): void
    {
        $ran = new KeyStoreSummary(4, 1, 0);

        $skipped = KeyStoreSummary::skipped()->naming(self::ENCRYPTER);

        self::assertSame(['keys' => 0, 'erased' => 0, 'findings' => 0, 'skipped' => true, 'encrypter' => self::ENCRYPTER], $skipped->toArray());
        self::assertSame($ran, $ran->naming(self::ENCRYPTER));
        self::assertNull($ran->naming(self::ENCRYPTER)->encrypter);
    }

    /**
     * Naming a skipped verification keeps whatever counts it holds.
     *
     * @return void
     */
    public function testNamingKeepsTheCounts(): void
    {
        $named = (new KeyStoreSummary(5, 2, 1, true))->naming(self::ENCRYPTER);

        self::assertSame(['keys' => 5, 'erased' => 2, 'findings' => 1, 'skipped' => true, 'encrypter' => self::ENCRYPTER], $named->toArray());
    }
}
