<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseManager;
use SineMacula\Laravel\AuditLog\Config\IntegerSetting;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;

/**
 * Verifies the whole lifecycle journal and each seal's commitment to it on
 * every verification run, whatever seals the run checks. Memory grows with the
 * seals, never with the journal, and every read is on the writer so replica lag
 * never reads as a missing row.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class JournalVerifier
{
    /** @var int Journal rows read by one statement. */
    public const int PAGE = 500;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\JournalSigner  $signer
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealSettings  $settings
     * @param  \Illuminate\Database\DatabaseManager  $database
     */
    public function __construct(

        /** The signer each row's HMAC is verified with. */
        private JournalSigner $signer,

        /** The settings the log id every row must belong to is read from. */
        private SealSettings $settings,

        /** The connections the storage connection is resolved from on every run. */
        private DatabaseManager $database,
    ) {}

    /**
     * Verify the seals' commitments and the journal, adding each finding to the
     * tally, and summarise what was read.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\VerificationTally  $tally
     * @return \SineMacula\Laravel\AuditLog\Integrity\JournalSummary
     *
     * @throws \InvalidArgumentException
     * @throws \JsonException
     */
    public function verify(VerificationTally $tally): JournalSummary
    {
        $connection                = $this->database->connection(StorageConnection::name());
        $found                     = [];
        [$commitments, $committed] = self::commitments($connection, $found);
        $chain                     = new JournalChain($this->signer, $this->settings->logId());

        foreach (self::journal($connection) as $stored) {
            self::check($chain, $stored, $commitments, $found);
        }

        // A commitment left names no row the journal holds
        foreach ($commitments as $seals) {
            self::note($found, array_map(static fn (array $seal): array => [Finding::JOURNAL_COMMITMENT, $seal[0]], $seals));
        }

        foreach ($found as [$finding, $firstId, $count]) {
            $tally->addFinding(new RunFinding($finding, $firstId, $count));
        }

        return new JournalSummary($chain->rows(), $chain->head()[0] ?? null, $committed);
    }

    /**
     * Check each seal's commitment in sequence order, noting each malformed,
     * backwards or dropped one; returns the heads committed to, by sequence,
     * and the latest seal's commitment.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  array<string, array{0: \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding, 1: ?string, 2: int}>  $found
     * @return array{0: array<int, list<array{0: ?string, 1: string}>>, 1: ?int}
     *
     * @throws \InvalidArgumentException
     */
    private static function commitments(Connection $connection, array &$found): array
    {
        $seals = $connection->table(IntegrityTables::checkpointsTable())
            ->useWritePdo()
            ->where('sequence', '>=', 1)
            ->orderBy('sequence')
            ->get(['id', 'journal_sequence', 'journal_head'])
            ->all();

        $heads     = [];
        $last      = null;
        $committed = null;

        foreach ($seals as $seal) {

            $sealId                         = is_string($seal->id ?? null) ? $seal->id : null;
            [$wellFormed, $sequence, $head] = self::commitmentOf($seal);
            $committed                      = $sequence;

            if (!$wellFormed || self::runsBackwards($sequence, $last)) {
                self::note($found, [[Finding::JOURNAL_COMMITMENT, $sealId]]);

                continue;
            }

            if ($sequence === null || $head === null) {
                continue;
            }

            $heads[$sequence][] = [$sealId, $head];
            $last               = $sequence;
        }

        return [$heads, $committed];
    }

    /**
     * Read the stored row into the chain, noting its findings and each seal
     * that committed to its sequence under another HMAC.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\JournalChain  $chain
     * @param  array<array-key, mixed>  $stored
     * @param  array<int, list<array{0: ?string, 1: string}>>  $commitments
     * @param  array<string, array{0: \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding, 1: ?string, 2: int}>  $found
     * @return void
     *
     * @throws \JsonException
     */
    private static function check(JournalChain $chain, #[\SensitiveParameter] array $stored, array &$commitments, array &$found): void
    {
        try {
            $journalRow = JournalRow::fromRow($stored, true);
        } catch (\UnexpectedValueException) {
            self::note($found, $chain->acceptMalformed(is_string($stored['id'] ?? null) ? $stored['id'] : null));

            return;
        }

        self::note($found, $chain->accept($journalRow));

        $hmac         = $journalRow->hmac;
        $contradicted = array_filter($commitments[$journalRow->sequence] ?? [], static fn (array $seal): bool => $seal[1] !== $hmac);

        self::note($found, array_map(static fn (array $seal): array => [Finding::JOURNAL_COMMITMENT, $seal[0]], array_values($contradicted)));

        unset($commitments[$journalRow->sequence]);
    }

    /**
     * Whether the commitment runs backwards from the last one made: it names no
     * row after one did, or a row before the last one named.
     *
     * @param  ?int  $sequence
     * @param  ?int  $last
     * @return bool
     */
    private static function runsBackwards(?int $sequence, ?int $last): bool
    {
        return $last !== null && ($sequence === null || $sequence < $last);
    }

    /**
     * Every journal row's stored columns, by sequence, a page at a time with
     * only one page held.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return \Generator<int, array<array-key, mixed>>
     *
     * @throws \InvalidArgumentException
     */
    private static function journal(Connection $connection): \Generator
    {
        $after = null;

        do {
            $query = $connection->table(LifecycleTables::journalTable())->useWritePdo()->orderBy('sequence')->limit(self::PAGE);

            if ($after !== null) {
                $query->where('sequence', '>', $after);
            }

            $page  = $query->get()->all();
            $full  = count($page) === self::PAGE;
            $after = $page        === [] ? null : IntegerSetting::parse($page[array_key_last($page)]->sequence ?? null);

            foreach ($page as $stored) {
                yield (array) $stored;
            }

            // Released before the next page is read, so no two are ever held
            unset($page);
        } while ($full && $after !== null);
    }

    /**
     * Whether the seal's commitment is well formed, and its journal sequence
     * and head: both `null`, or a sequence from 1 and 64 lower-case hex.
     *
     * @param  \stdClass  $seal
     * @return array{0: bool, 1: ?int, 2: ?string}
     */
    private static function commitmentOf(\stdClass $seal): array
    {
        $stored   = $seal->journal_sequence ?? null;
        $sequence = $stored === null ? null : IntegerSetting::parse($stored);
        $head     = $seal->journal_head ?? null;

        if ($stored === null && $head === null) {
            return [true, null, null];
        }

        $wellFormed = $sequence !== null && $sequence >= 1 && is_string($head) && preg_match(SealEnvelope::DIGEST_PATTERN, $head) === 1;

        return $wellFormed ? [true, $sequence, $head] : [false, $sequence, null];
    }

    /**
     * Count each finding given under its kind, keeping the id of the first.
     *
     * @param  array<string, array{0: \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding, 1: ?string, 2: int}>  $found
     * @param  list<array{0: \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding, 1: ?string}>  $findings
     * @return void
     */
    private static function note(array &$found, array $findings): void
    {
        foreach ($findings as [$finding, $id]) {
            $found[$finding->value] ??= [$finding, $id, 0];
            $found[$finding->value][2]++;
        }
    }
}
