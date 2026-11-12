<?php

declare(strict_types = 1);

namespace Tests\Unit\Console;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Console\VerifyLines;
use SineMacula\Laravel\AuditLog\Integrity\Enums\AnchorStatus;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Integrity\Enums\IntegrityStatus;
use SineMacula\Laravel\AuditLog\Integrity\JournalSummary;
use SineMacula\Laravel\AuditLog\Integrity\KeyStoreSummary;
use SineMacula\Laravel\AuditLog\Integrity\RunFinding;
use SineMacula\Laravel\AuditLog\Integrity\SegmentReport;
use SineMacula\Laravel\AuditLog\Integrity\VerificationSummary;
use SineMacula\Laravel\AuditLog\Integrity\VerificationTally;
use Symfony\Component\Console\Formatter\OutputFormatter;

/**
 * Unit tests for the lines `audit-log:verify` prints as text, nothing in an id
 * or a class read as a style.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(VerifyLines::class)]
final class VerifyLinesTest extends TestCase
{
    /** @var string The id of the seal a line names. */
    private const string SEAL_ID = '01932b4e-9000-7000-8000-000000000001';

    /** @var string The id of the entry a finding was found at. */
    private const string ENTRY_ID = '01932b4e-a000-7000-8000-000000000001';

    /**
     * A seal's line names its sequence and id, its statuses and members, then
     * whether it awaits its first anchoring, then its finding and first id.
     *
     * @return void
     */
    public function testTheSegmentLineIsPinned(): void
    {
        $valid    = new SegmentReport(3, self::SEAL_ID, IntegrityStatus::VALID, AnchorStatus::UNANCHORED, 2, null, null, null, true);
        $tampered = new SegmentReport(4, self::SEAL_ID, IntegrityStatus::TAMPERED, AnchorStatus::ANCHORED, 5, Finding::KEY_USE_MISSING, self::ENTRY_ID);
        $nameless = new SegmentReport(5, '', IntegrityStatus::UNVERIFIABLE, AnchorStatus::UNANCHORED, 0, Finding::SEAL_MALFORMED);

        $line = 'seal 4 ' . self::SEAL_ID . ' integrity=tampered anchoring=anchored members=5 finding=key_use_missing first=' . self::ENTRY_ID;

        self::assertSame('seal 3 ' . self::SEAL_ID . ' integrity=valid anchoring=unanchored members=2 awaiting-anchor', VerifyLines::segmentLine($valid));
        self::assertSame($line, VerifyLines::segmentLine($tampered));
        self::assertSame('seal 5 none integrity=unverifiable anchoring=unanchored members=0 finding=seal_malformed first=none', VerifyLines::segmentLine($nameless));
    }

    /**
     * A run finding's line names the check, the status it gives, how many times
     * it was found and the first id, or none.
     *
     * @return void
     */
    public function testTheFindingLineIsPinned(): void
    {
        $restored = new RunFinding(Finding::KEY_RESTORED, self::ENTRY_ID, 3);

        self::assertSame('finding key_restored integrity=tampered count=3 first=' . self::ENTRY_ID, VerifyLines::findingLine($restored));
        self::assertSame('finding key_unverifiable integrity=unverifiable count=1 first=none', VerifyLines::findingLine(new RunFinding(Finding::KEY_UNVERIFIABLE)));
    }

    /**
     * Rows of `[id, what a line shows]`: no id is `none`, and an altered
     * table's id is repaired, stripped of control characters and escaped.
     *
     * @return iterable<string, array{0: ?string, 1: string}>
     */
    public static function provideIds(): iterable
    {
        yield from [
            'no id'          => [null, 'none'],
            'an empty id'    => ['', 'none'],
            'an id'          => [self::SEAL_ID, self::SEAL_ID],
            'a style'        => ["\e[31m<fg=red>x</>", OutputFormatter::escape('[31m<fg=red>x</>')],
            'text not UTF-8' => ["x\xFFy", "x\u{FFFD}y"],
        ];
    }

    /**
     * An id is shown as text.
     *
     * @param  ?string  $id
     * @param  string  $shown
     * @return void
     */
    #[DataProvider('provideIds')]
    public function testAnIdIsShownAsText(?string $id, string $shown): void
    {
        self::assertSame($shown, VerifyLines::id($id));
    }

    /**
     * The counts' lines name every status, in order, with the seals awaiting
     * their first anchoring among the unanchored.
     *
     * @return void
     */
    public function testTheCountLinesArePinned(): void
    {
        $integrity = ['valid' => 1, 'pruned' => 2, 'incomplete' => 3, 'unverifiable' => 4, 'tampered' => 5];
        $anchoring = ['anchored' => 6, 'unanchored' => 7, 'unavailable' => 8, 'contradicted' => 9];

        self::assertSame('Integrity: 1 valid, 2 pruned, 3 incomplete, 4 unverifiable, 5 tampered.', VerifyLines::integrityLine($integrity));
        self::assertSame('Anchoring: 6 anchored, 7 unanchored (2 awaiting their first anchoring), 8 unavailable, 9 contradicted.', VerifyLines::anchoringLine($anchoring, 2));
    }

    /**
     * The journal's line names the rows read, the head and the sequence the
     * latest seal commits to, each `none` when there is none.
     *
     * @return void
     */
    public function testTheJournalLineIsPinned(): void
    {
        self::assertSame('Journal: 4 rows to sequence 4; the latest seal commits to 3.', VerifyLines::journalLine(new JournalSummary(4, 4, 3)));
        self::assertSame('Journal: 0 rows to sequence none; the latest seal commits to none.', VerifyLines::journalLine(new JournalSummary(0, null, null)));
    }

    /**
     * The key store's line names the keys verified, those erased and the key
     * findings; a skipped one says so, naming the encrypter as text.
     *
     * @return void
     */
    public function testTheKeysLineIsPinned(): void
    {
        $skipped = KeyStoreSummary::skipped()->naming('App\Privacy\<fg=red>Vault</>');

        self::assertSame('Keys: 12 verified, 3 erased, 2 findings.', VerifyLines::keysLine(new KeyStoreSummary(12, 3, 2)));
        $shown = OutputFormatter::escape('App\Privacy\<fg=red>Vault</>');

        self::assertSame('Keys: skipped; the bound field encrypter ' . $shown . ' does not use the package\'s key store.', VerifyLines::keysLine($skipped));
        self::assertSame('Keys: skipped; the bound field encrypter none does not use the package\'s key store.', VerifyLines::keysLine(KeyStoreSummary::skipped()));
    }

    /**
     * The coverage names the seals checked and the head, or that the log has
     * none.
     *
     * @return void
     */
    public function testTheCoverageIsPinned(): void
    {
        self::assertSame('Checked seals 2 to 4 of head 5;', VerifyLines::coverage(self::summary(5, null, null, false)));
        self::assertSame('Checked no seals: the log has none;', VerifyLines::coverage(self::summary(null, null, null, false)));
    }

    /**
     * Rows of `[anchor's status, its head, whether it discovers, the clause]`:
     * what the run learnt of the anchor's head, in order of precedence.
     *
     * @return iterable<string, array{0: ?\SineMacula\Laravel\AuditLog\Integrity\Enums\AnchorStatus, 1: ?int, 2: bool, 3: string}>
     */
    public static function provideAnchorClauses(): iterable
    {
        yield from [
            'no anchor'             => [null, null, false, 'no anchor is configured.'],
            'no discovery'          => [AnchorStatus::UNANCHORED, null, false, 'the anchor cannot report its head.'],
            'an unavailable anchor' => [AnchorStatus::UNAVAILABLE, 4, true, 'the anchor is unavailable.'],
            'a head'                => [AnchorStatus::ANCHORED, 4, true, 'the anchor\'s head is 4.'],
            'a contradiction'       => [AnchorStatus::CONTRADICTED, null, true, 'the anchor holds another digest for a seal.'],
            'an empty anchor'       => [AnchorStatus::UNANCHORED, null, true, 'the anchor holds no seal.'],
        ];
    }

    /**
     * The anchor clause says what the run learnt of the anchor's head.
     *
     * @param  ?\SineMacula\Laravel\AuditLog\Integrity\Enums\AnchorStatus  $remote
     * @param  ?int  $remoteHead
     * @param  bool  $discovers
     * @param  string  $clause
     * @return void
     */
    #[DataProvider('provideAnchorClauses')]
    public function testTheAnchorClause(?AnchorStatus $remote, ?int $remoteHead, bool $discovers, string $clause): void
    {
        self::assertSame($clause, VerifyLines::anchorClause(self::summary(5, $remoteHead, $remote, $discovers)));
    }

    /**
     * The constructor is private: the class is a utility container only.
     *
     * @SuppressWarnings("php:S3011")
     *
     * @return void
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(VerifyLines::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(VerifyLines::class, $instance);
    }

    /**
     * The summary of a run of seals 2 to 4 under the head, the anchor's head,
     * its status and whether it discovers.
     *
     * @param  ?int  $head
     * @param  ?int  $remoteHead
     * @param  ?\SineMacula\Laravel\AuditLog\Integrity\Enums\AnchorStatus  $remote
     * @param  bool  $discovers
     * @return \SineMacula\Laravel\AuditLog\Integrity\VerificationSummary
     */
    private static function summary(?int $head, ?int $remoteHead, ?AnchorStatus $remote, bool $discovers): VerificationSummary
    {
        return VerificationSummary::of([2, 4], $head, $remoteHead, $remote, false, $discovers, new VerificationTally);
    }
}
