<?php

declare(strict_types = 1);

namespace Tests\Feature\Integrity;

use Illuminate\Config\Repository;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\IntegritySettings;
use SineMacula\Laravel\AuditLog\Integrity\JournalRow;
use SineMacula\Laravel\AuditLog\Integrity\JournalSigner;
use SineMacula\Laravel\AuditLog\Integrity\KeyRing;
use Tests\Concerns\SealsEntries;
use Tests\Concerns\WritesTheJournal;
use Tests\TestCase;

/**
 * Tampers with the lifecycle journal through raw statements, as a holder of the
 * database's credentials could, and shows verify finds each.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class JournalTamperingTest extends TestCase
{
    use SealsEntries, WritesTheJournal;

    /** @var string The first hold's id. */
    private const string FIRST_HOLD = '01932b4e-d000-7000-8000-000000000001';

    /** @var string The second hold's id. */
    private const string SECOND_HOLD = '01932b4e-d000-7000-8000-000000000002';

    /** @var string An HMAC no row holds. */
    private const string OTHER_HMAC = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

    /**
     * Write the journal and seal an entry after it, so the seal commits to its
     * head; an untampered log passes.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->journalHold(self::FIRST_HOLD);
        $this->journalHold(self::SECOND_HOLD);
        $this->journalRow(JournalKind::RELEASE, ['hold_id' => self::FIRST_HOLD], self::FIRST_HOLD);
        $this->storeEntries(1);
        $this->sealAll();
    }

    /**
     * The untampered journal and its seal pass, and the summary names the
     * journal's head and the seal's commitment to it.
     *
     * @return void
     */
    public function testAnUntamperedJournalPasses(): void
    {
        [$exit, $findings, $summary] = $this->verify();

        self::assertSame(0, $exit);
        self::assertSame([], $findings);
        self::assertSame(['rows' => 3, 'head' => 3, 'committed' => 3], $summary['journal'] ?? null);
    }

    /**
     * Rows of `[the tampering, the findings it gives, by the sequence each is
     * found at]`.
     *
     * @return iterable<string, array{0: \Closure(self): void, 1: array<string, string>}>
     */
    public static function provideTamperings(): iterable
    {
        yield from [
            'an edited payload' => [
                static function (self $test): void {
                    $test->tamperJournal(2, ['payload' => '{"basis":"other","hold_id":"' . self::SECOND_HOLD . '","review_by":null}']);
                },
                ['journal_signature' => 'row 2'],
            ],
            'an edited authority' => [
                static function (self $test): void {
                    $test->tamperJournal(1, ['authority_id' => '8']);
                },
                ['journal_signature' => 'row 1'],
            ],
            'a deleted row' => [
                static function (self $test): void {
                    $test->journalTable()->where('sequence', 2)->delete();
                },
                ['journal_gap' => 'row 3'],
            ],
            'a swapped pair' => [
                static function (self $test): void {
                    $test->tamperJournal(1, ['sequence' => 99]);
                    $test->tamperJournal(2, ['sequence' => 1]);
                    $test->tamperJournal(99, ['sequence' => 2]);
                },
                ['journal_gap' => 'row 2', 'journal_signature' => 'row 2'],
            ],
            'a row re-signed under an unknown key' => [
                static function (self $test): void {
                    $test->resignUnderAForeignKey(3);
                },
                ['journal_commitment' => 'seal', 'journal_key' => 'row 3'],
            ],
            'a seal\'s commitment edited' => [
                static function (self $test): void {
                    $test->checkpoints()->update(['journal_head' => self::OTHER_HMAC]);
                },
                ['journal_commitment' => 'seal'],
            ],
        ];
    }

    /**
     * Each tampering gives its findings, each at the row or the seal it was
     * found at, and the run exits non-zero.
     *
     * @param  \Closure(self): void  $tamper
     * @param  array<string, string>  $expected
     * @return void
     */
    #[DataProvider('provideTamperings')]
    public function testEachTamperingIsFoundAndExitsNonZero(\Closure $tamper, array $expected): void
    {
        $rows = array_column($this->journalRows(), 'id', 'sequence');
        $seal = (string) $this->seals()[0]['id'];

        $tamper($this);

        [$exit, $findings, $summary] = $this->verify();

        $named = [];

        foreach ($expected as $finding => $where) {
            $named[$finding] = $where === 'seal' ? $seal : $rows[(int) substr($where, 4)];
        }

        self::assertSame(1, $exit);
        $found = array_intersect_key($findings, $named);

        ksort($named);
        ksort($found);

        self::assertSame($named, $found);
        self::assertFalse($summary['passed'] ?? true);
    }

    /**
     * Re-sign the stored row at the sequence under a key the ring does not
     * hold, its every other column kept.
     *
     * @param  int  $sequence
     * @return void
     */
    private function resignUnderAForeignKey(int $sequence): void
    {
        $stored   = $this->journalTable()->where('sequence', $sequence)->first();
        $settings = ['keys' => ['k-foreign' => 'audit-log foreign key 0123456789!'], 'current' => 'k-foreign'];
        $ring     = new KeyRing(new IntegritySettings(new Repository(['audit-log' => ['integrity' => $settings]])));
        $resign   = (new JournalSigner($ring))->sign(JournalRow::fromRow((array) $stored, true));

        $this->tamperJournal($sequence, ['key_id' => $resign->keyId, 'hmac' => $resign->hmac]);
    }

    /**
     * A query of the journal table on the storage connection.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private function journalTable(): Builder
    {
        return DB::connection(StorageConnection::name())->table(LifecycleTables::journalTable());
    }

    /**
     * A query of the checkpoints table on the storage connection.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private function checkpoints(): Builder
    {
        return DB::connection(StorageConnection::name())->table(IntegrityTables::checkpointsTable());
    }

    /**
     * Run `audit-log:verify --json`, returning its exit code, the first id of
     * each finding of the run, by its finding, and the summary.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return array{0: int, 1: array<string, ?string>, 2: array<array-key, mixed>}
     *
     * @throws \JsonException
     */
    private function verify(): array
    {
        $exit     = Artisan::call('audit-log:verify', ['--json' => true]);
        $findings = [];
        $summary  = [];

        foreach (array_filter(explode("\n", Artisan::output()), static fn (string $line): bool => $line !== '') as $line) {
            $decoded = json_decode($line, true, 512, JSON_THROW_ON_ERROR);

            self::assertIsArray($decoded);

            $type    = $decoded['type']    ?? null;
            $finding = $decoded['finding'] ?? null;
            $summary = $type === 'summary' ? $decoded : $summary;

            if ($type !== 'finding' || !is_string($finding)) {
                continue;
            }

            $findings[$finding] = is_string($decoded['first_bad_id'] ?? null) ? $decoded['first_bad_id'] : null;
        }

        return [$exit, $findings, $summary];
    }
}
