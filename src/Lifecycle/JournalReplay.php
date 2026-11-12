<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use Illuminate\Database\Connection;
use SineMacula\Laravel\AuditLog\Config\IntegerSetting;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\JournalChain;
use SineMacula\Laravel\AuditLog\Integrity\JournalRow;
use SineMacula\Laravel\AuditLog\Integrity\JournalSigner;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * The lifecycle journal verified whole, and the active holds, policy versions
 * and prune runs a destructive decision reads from it.
 *
 * A replay is a value: an operation keeps only the one a committed transaction
 * returned, so a rolled-back attempt never leaves it ahead of the database.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class JournalReplay
{
    /** @var int Journal rows, or payloads, read by one statement. */
    public const int PAGE = 500;

    /** @var list<string> Every column of a journal row but its payload. */
    private const array SMALL_COLUMNS = [
        'id', 'sequence', 'log_id', 'kind', 'operation_id', 'occurred_at', 'authority_type', 'authority_id', 'reason',
        'external_reference', 'seal_id', 'hold_id', 'payload_digest', 'previous_hmac', 'key_id', 'hmac',
    ];

    /** @var string The phase a prune run's finish row names. */
    private const string FINISH = 'finish';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\JournalSigner  $signer
     * @param  string  $logId
     * @param  \SineMacula\Laravel\AuditLog\Integrity\JournalChain  $chain
     * @param  array<string, \SineMacula\Laravel\AuditLog\Lifecycle\Hold>  $holds
     * @param  array<string, true>  $policies
     * @param  array<int, string>  $runs
     * @param  ?\SineMacula\Laravel\AuditLog\Integrity\JournalRow  $lastAppended
     */
    private function __construct(

        /** Verifies each row's HMAC. */
        private JournalSigner $signer,

        /** The log every row must belong to. */
        private string $logId,

        /** The chain read so far; never changed once the replay holds it. */
        private JournalChain $chain,

        /** The active holds by id, in placement order. */
        #[\SensitiveParameter]
        private array $holds,

        /** The policy versions journalled. */
        private array $policies,

        /** The payload digest of every prune run row, by sequence. */
        private array $runs,

        /** The row this replay accepted last, or `null` when it accepted none. */
        #[\SensitiveParameter]
        private ?JournalRow $lastAppended,
    ) {}

    /**
     * An empty replay of the log, for `verify()` to read the journal into.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\JournalSigner  $signer
     * @param  string  $logId
     * @return self
     */
    public static function start(JournalSigner $signer, string $logId): self
    {
        return new self($signer, $logId, new JournalChain($signer, $logId), [], [], [], null);
    }

    /**
     * A fresh replay of the whole journal, checked against the latest and the
     * highest seal commitments.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return self
     *
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException
     * @throws \InvalidArgumentException
     * @throws \JsonException
     */
    public function verify(Connection $connection): self
    {
        // Seals first, so no later seal can commit to a row this replay missed
        $seals   = $connection->table(IntegrityTables::checkpointsTable())->useWritePdo();
        $latest  = (clone $seals)->where('sequence', '>=', 1)->orderByDesc('sequence')->first(['id', 'journal_sequence', 'journal_head']);
        $highest = (clone $seals)->where('journal_sequence', '>=', 1)->orderByDesc('journal_sequence')->first(['id', 'journal_sequence', 'journal_head']);

        $replay = self::start($this->signer, $this->logId)->readAfter($connection, 0);

        foreach ([$latest, $highest] as $seal) {
            if ($seal === null) {
                continue;
            }

            $replay->checkCommitment($connection, $seal);
        }

        return $replay;
    }

    /**
     * The replay advanced to the journal's head, refusing a head row whose HMAC
     * changed.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return self
     *
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException
     */
    public function advance(Connection $connection): self
    {
        $head = $this->chain->head();

        if ($head !== null) {
            $stored = $connection->table(LifecycleTables::journalTable())->useWritePdo()->where('sequence', $head[0])->first(['id', 'hmac']);

            $id = $stored->id ?? null;

            if (($stored->hmac ?? null) !== $head[1]) {
                throw JournalBrokenException::at(Finding::JOURNAL_GAP, is_string($id) ? $id : null);
            }
        }

        return $this->readAfter($connection, $head[0] ?? 0);
    }

    /**
     * The replay with the signed row accepted after its head; only
     * `Journal::append()` calls this.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\JournalRow  $row
     * @return self
     *
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException
     * @throws \JsonException
     * @throws \LogicException
     */
    public function accept(#[\SensitiveParameter] JournalRow $row): self
    {
        $chain    = clone $this->chain;
        $holds    = $this->holds;
        $policies = $this->policies;
        $runs     = $this->runs;

        // Read without its payload, as the chain reads a stored row
        self::refuse($chain->accept(self::rowOf($row->toRow(), false)));

        if ($row->kind === JournalKind::PRUNE_RUN) {
            $runs[$row->sequence] = $row->payloadDigest;
        }

        if ($row->kind->readsPayloadToReplay()) {
            self::replayPayloadOf($row, $holds, $policies);
        }

        return new self($this->signer, $this->logId, $chain, $holds, $policies, $runs, $row);
    }

    /**
     * The row this replay accepted last, or `null` when it accepted none.
     *
     * @return ?\SineMacula\Laravel\AuditLog\Integrity\JournalRow
     */
    public function lastAppended(): ?JournalRow
    {
        return $this->lastAppended;
    }

    /**
     * The active holds in placement order.
     *
     * @return list<\SineMacula\Laravel\AuditLog\Lifecycle\Hold>
     */
    public function holds(): array
    {
        return array_values($this->holds);
    }

    /**
     * The active hold of the id, or `null` when none is active under it.
     *
     * @param  string  $holdId
     * @return ?\SineMacula\Laravel\AuditLog\Lifecycle\Hold
     */
    public function hold(string $holdId): ?Hold
    {
        return $this->holds[$holdId] ?? null;
    }

    /**
     * Whether the chain ever placed a hold of the id, active or released.
     *
     * @param  string  $holdId
     * @return bool
     */
    public function hasPlacedHold(string $holdId): bool
    {
        return $this->chain->hasPlaced($holdId);
    }

    /**
     * Whether a policy row of the version is in the chain.
     *
     * @param  string  $version
     * @return bool
     */
    public function hasPolicyVersion(string $version): bool
    {
        return array_key_exists($version, $this->policies);
    }

    /**
     * The verified payload of the last finished prune run, or `null` when none
     * has finished.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return ?array<array-key, mixed>
     *
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException
     */
    public function lastRunFinish(Connection $connection): ?array
    {
        foreach (array_chunk(array_reverse(array_keys($this->runs)), self::PAGE) as $sequences) {
            $stored = $connection->table(LifecycleTables::journalTable())->useWritePdo()->whereIn('sequence', $sequences)->get()->keyBy('sequence')->all();

            foreach ($sequences as $sequence) {
                $journalRow = self::rowOf((array) ($stored[$sequence] ?? throw JournalBrokenException::at(Finding::JOURNAL_GAP, null)), true);
                $payload    = $journalRow->payloadMap() ?? [];

                if (!hash_equals($this->runs[$sequence], hash('sha256', (string) $journalRow->payload))) {
                    throw JournalBrokenException::at(Finding::JOURNAL_SIGNATURE, $journalRow->id);
                }

                if (($payload['phase'] ?? null) === self::FINISH) {
                    return $payload;
                }
            }
        }

        return null;
    }

    /**
     * The sequence and HMAC of the last verified row, or `null` for an empty
     * journal.
     *
     * @return ?array{0: int, 1: string}
     */
    public function head(): ?array
    {
        return $this->chain->head();
    }

    /**
     * A new replay of this one and every row after the sequence, reading only
     * the payloads that decide something.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  int  $after
     * @return self
     *
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException
     * @throws \InvalidArgumentException
     * @throws \JsonException
     */
    private function readAfter(Connection $connection, int $after): self
    {
        $chain    = clone $this->chain;
        $holds    = $this->holds;
        $policies = $this->policies;
        $runs     = $this->runs;
        $pending  = [];

        do {
            $page = $connection->table(LifecycleTables::journalTable())
                ->useWritePdo()
                ->where('sequence', '>', $after)
                ->orderBy('sequence')
                ->limit(self::PAGE)
                ->get(self::SMALL_COLUMNS)
                ->all();

            $after = self::readPage($chain, $page, $runs, $pending) ?? $after;

            if (count($pending) < self::PAGE) {
                continue;
            }

            self::replayPayloads($connection, $pending, $holds, $policies);

            $pending = [];
        } while (count($page) === self::PAGE);

        self::replayPayloads($connection, $pending, $holds, $policies);

        return new self($this->signer, $this->logId, $chain, $holds, $policies, $runs, $this->lastAppended);
    }

    /**
     * Read a page of rows through the chain and return the last sequence, or
     * `null` for an empty page.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\JournalChain  $chain
     * @param  array<int, \stdClass>  $page
     * @param  array<int, string>  $runs
     * @param  array<int, array<string, scalar|null>>  $pending
     * @return ?int
     *
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException
     * @throws \JsonException
     */
    private static function readPage(JournalChain $chain, #[\SensitiveParameter] array $page, array &$runs, #[\SensitiveParameter] array &$pending): ?int
    {
        $last = null;

        foreach ($page as $found) {
            /** @var array<string, scalar|null> $stored */
            $stored     = (array) $found;
            $journalRow = self::rowOf($stored, false);
            $last       = $journalRow->sequence;

            self::refuse($chain->accept($journalRow));

            if ($journalRow->kind === JournalKind::PRUNE_RUN) {
                $runs[$last] = $journalRow->payloadDigest;
            }

            if (!$journalRow->kind->readsPayloadToReplay()) {
                continue;
            }

            $pending[$last] = $stored;
        }

        return $last;
    }

    /**
     * Refuse a seal whose commitment the chain contradicts, so a journal
     * truncated or restored behind a seal is caught.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  \stdClass  $seal
     * @return void
     *
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException
     */
    private function checkCommitment(Connection $connection, \stdClass $seal): void
    {
        $stored = $seal->journal_sequence ?? null;
        $hmac   = $seal->journal_head     ?? null;

        if ($stored === null && $hmac === null) {
            return;
        }

        $sequence = IntegerSetting::parse($stored);
        $head     = $this->chain->head();

        $at = match (true) {
            $sequence === null || $head === null || $sequence < 1 || $sequence > $head[0] => null,
            $sequence === $head[0]                                                        => $head[1],
            default                                                                       => $connection->table(LifecycleTables::journalTable())
                ->useWritePdo()
                ->where('sequence', $sequence)
                ->value('hmac'),
        };

        if (!is_string($hmac) || $at !== $hmac) {
            throw JournalBrokenException::at(Finding::JOURNAL_COMMITMENT, is_string($seal->id ?? null) ? $seal->id : null);
        }
    }

    /**
     * Read and verify the pending rows' payloads, replaying them in sequence
     * order.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  array<int, array<array-key, mixed>>  $pending
     * @param  array<string, \SineMacula\Laravel\AuditLog\Lifecycle\Hold>  $holds
     * @param  array<string, true>  $policies
     * @return void
     *
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException
     */
    private static function replayPayloads(Connection $connection, #[\SensitiveParameter] array $pending, #[\SensitiveParameter] array &$holds, array &$policies): void
    {
        foreach (array_chunk($pending, self::PAGE, true) as $chunk) {
            $payloads = $connection->table(LifecycleTables::journalTable())
                ->useWritePdo()
                ->whereIn('sequence', array_keys($chunk))
                ->pluck('payload', 'sequence')
                ->all();

            foreach ($chunk as $sequence => $stored) {
                $journalRow = self::rowOf([...$stored, 'payload' => $payloads[$sequence] ?? null], true);

                if (!$journalRow->hasPayloadOfItsDigest()) {
                    throw JournalBrokenException::at(Finding::JOURNAL_SIGNATURE, $journalRow->id);
                }

                self::replayPayloadOf($journalRow, $holds, $policies);
            }
        }
    }

    /**
     * Replay the verified row's payload into the policies or the holds.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\JournalRow  $row
     * @param  array<string, \SineMacula\Laravel\AuditLog\Lifecycle\Hold>  $holds
     * @param  array<string, true>  $policies
     * @return void
     *
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException
     */
    private static function replayPayloadOf(#[\SensitiveParameter] JournalRow $row, #[\SensitiveParameter] array &$holds, array &$policies): void
    {
        $payload = $row->payloadMap()  ?? [];
        $version = $payload['version'] ?? null;

        if ($row->kind === JournalKind::POLICY && is_string($version)) {
            $policies[$version] = true;

            return;
        }

        if ($row->kind === JournalKind::RELEASE && $row->holdId !== null && ($payload['hold_id'] ?? null) === $row->holdId) {
            unset($holds[$row->holdId]);

            return;
        }

        $hold = $row->kind === JournalKind::HOLD ? self::holdOf($row, $payload) : null;

        if ($hold === null) {
            throw JournalBrokenException::at(Finding::JOURNAL_MALFORMED, $row->id);
        }

        $holds[$hold->id] = $hold;
    }

    /**
     * The hold the verified row and its payload place, or `null` when they do
     * not describe one.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\JournalRow  $row
     * @param  array<array-key, mixed>  $payload
     * @return ?\SineMacula\Laravel\AuditLog\Lifecycle\Hold
     */
    private static function holdOf(#[\SensitiveParameter] JournalRow $row, #[\SensitiveParameter] array $payload): ?Hold
    {
        $scope    = $payload['scope'] ?? null;
        $basis    = HoldBasis::tryFrom(is_string($payload['basis'] ?? null) ? $payload['basis'] : '');
        $stored   = $payload['review_by'] ?? null;
        $reviewBy = is_string($stored) ? $stored : null;

        try {
            return match (true) {
                $row->holdId        === null,
                $row->authorityType === null,
                $row->authorityId   === null,
                $row->reason        === null,
                ($payload['hold_id'] ?? null) !== $row->holdId,
                !is_array($scope),
                $basis === null,
                $stored !== $reviewBy => null,
                default               => new Hold(
                    $row->holdId,
                    HoldScope::fromArray($scope),
                    $basis,
                    $reviewBy,
                    $row->occurredAt,
                    Reference::of($row->authorityType, $row->authorityId),
                    $row->reason,
                    $row->externalReference,
                    $row->operationId,
                    $row->sequence,
                ),
            };
        } catch (\InvalidArgumentException|\UnexpectedValueException) {
            return null;
        }
    }

    /**
     * The journal row of the stored columns, with its payload when asked.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $stored
     * @param  bool  $withPayload
     * @return \SineMacula\Laravel\AuditLog\Integrity\JournalRow
     *
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException
     */
    private static function rowOf(#[\SensitiveParameter] array $stored, bool $withPayload): JournalRow
    {
        try {
            return JournalRow::fromRow($stored, $withPayload);
        } catch (\UnexpectedValueException) {
            throw JournalBrokenException::at(Finding::JOURNAL_MALFORMED, is_string($stored['id'] ?? null) ? $stored['id'] : null);
        }
    }

    /**
     * Refuse the first of the chain's findings.
     *
     * @param  list<array{0: \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding, 1: ?string}>  $findings
     * @return void
     *
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException
     */
    private static function refuse(array $findings): void
    {
        if ($findings === []) {
            return;
        }

        throw JournalBrokenException::at($findings[0][0], $findings[0][1]);
    }
}
