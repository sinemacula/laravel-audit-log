<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;

/**
 * The lifecycle journal's chain rules, applied a row at a time in sequence
 * order, for verification and for the replay a destructive operation decides
 * from.
 *
 * Only the ids of placed and active holds and of open runs and batches are
 * kept, so memory grows with those, never with the journal. It holds no
 * resource, so a replay can keep a clone as an independent value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class JournalChain
{
    /** @var string The payload key that names a prune run. */
    private const string RUN_ID = 'run_id';

    /** @var string The payload key that names an import batch. */
    private const string BATCH_ID = 'batch_id';

    /** @var ?array{0: int, 1: string} The sequence and HMAC of the last good row, or `null` before one. */
    private ?array $head = null;

    /** @var ?array{0: int, 1: string} The sequence and HMAC of the last row read as it is stored, which the next row must follow. */
    private ?array $link = null;

    /** @var bool Whether the last row could not be read, so the next has nothing to link to. */
    private bool $unlinked = false;

    /** @var array<string, true> The ids of every hold ever placed, active or released. */
    private array $placed = [];

    /** @var array<string, true> The ids of the active holds, in the order they were placed. */
    private array $active = [];

    /** @var array<string, array<string, true>> The open run and batch ids, by the payload key that names them. */
    private array $open = [self::RUN_ID => [], self::BATCH_ID => []];

    /** @var bool Whether any row so far gave a finding. */
    private bool $broken = false;

    /** @var int The rows read so far, malformed ones included. */
    private int $rows = 0;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\JournalSigner  $signer
     * @param  string  $logId
     */
    public function __construct(

        /** The signer each row's HMAC is verified with. */
        private readonly JournalSigner $signer,

        /** The log every row must belong to: the seals' log. */
        private readonly string $logId,
    ) {}

    /**
     * Read the next row: its link, its signature and, when good, its
     * transition; returns its findings, each with the row's id.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\JournalRow  $journalRow
     * @return list<array{0: \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding, 1: ?string}>
     *
     * @throws \JsonException
     */
    public function accept(#[\SensitiveParameter] JournalRow $journalRow): array
    {
        $this->rows++;

        $findings = [];
        $advances = $this->link === null || $journalRow->sequence > $this->link[0];

        if (!$this->isLinked($journalRow)) {
            $findings[] = [Finding::JOURNAL_GAP, $journalRow->id];
        }

        $signature = $this->signatureFinding($journalRow);

        if ($signature !== null) {
            $findings[] = [$signature, $journalRow->id];
        }

        if ($advances) {
            $this->link     = [$journalRow->sequence, $journalRow->hmac];
            $this->unlinked = false;
        }

        if ($signature === null && $advances) {
            $this->head = [$journalRow->sequence, $journalRow->hmac];

            if ($this->refusesTransitionOf($journalRow)) {
                $findings[] = [Finding::JOURNAL_TRANSITION, $journalRow->id];
            }
        }

        $this->broken = $this->broken || $findings !== [];

        return $findings;
    }

    /**
     * Read a row that cannot be read as a journal row, by its id when it has
     * one: it is malformed, and the next row has nothing to link to.
     *
     * @param  ?string  $id
     * @return list<array{0: \SineMacula\Laravel\AuditLog\Integrity\Enums\Finding, 1: ?string}>
     */
    public function acceptMalformed(?string $id): array
    {
        $this->rows++;

        $this->broken   = true;
        $this->unlinked = true;

        return [[Finding::JOURNAL_MALFORMED, $id]];
    }

    /**
     * The sequence and HMAC of the last good row, or `null` before one.
     *
     * @return ?array{0: int, 1: string}
     */
    public function head(): ?array
    {
        return $this->head;
    }

    /**
     * The ids of the active holds, in the order they were placed.
     *
     * @return list<string>
     */
    public function activeHoldIds(): array
    {
        return array_map(strval(...), array_keys($this->active));
    }

    /**
     * Whether the hold id was ever placed, whether it is active or released.
     *
     * @param  string  $holdId
     * @return bool
     */
    public function hasPlaced(string $holdId): bool
    {
        return array_key_exists($holdId, $this->placed);
    }

    /**
     * Whether any row so far gave a finding.
     *
     * @return bool
     */
    public function isBroken(): bool
    {
        return $this->broken;
    }

    /**
     * The rows read so far, malformed ones included.
     *
     * @return int
     */
    public function rows(): int
    {
        return $this->rows;
    }

    /**
     * Whether the row follows the one before it in the configured log: one more
     * sequence and the HMAC before it, or 1 and none first. After a row that
     * could not be read, a later sequence is all it must have.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\JournalRow  $journalRow
     * @return bool
     */
    private function isLinked(#[\SensitiveParameter] JournalRow $journalRow): bool
    {
        if ($journalRow->logId !== $this->logId) {
            return false;
        }

        if ($this->unlinked) {
            return $this->link === null || $journalRow->sequence > $this->link[0];
        }

        [$sequence, $hmac] = $this->link ?? [0, null];

        return $journalRow->sequence === $sequence + 1 && $journalRow->previousHmac === $hmac;
    }

    /**
     * The finding the row's signature gives, or `null` when its HMAC verifies
     * and any payload read is the text of its digest.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\JournalRow  $journalRow
     * @return ?\SineMacula\Laravel\AuditLog\Integrity\Enums\Finding
     */
    private function signatureFinding(#[\SensitiveParameter] JournalRow $journalRow): ?Finding
    {
        try {
            return $this->signer->verifies($journalRow) && $journalRow->hasPayloadOfItsDigest() ? null : Finding::JOURNAL_SIGNATURE;
        } catch (UnknownKeyException) {
            return Finding::JOURNAL_KEY;
        } catch (\UnexpectedValueException) {
            return Finding::JOURNAL_MALFORMED;
        }
    }

    /**
     * Apply the good row's transition, and whether the chain refuses it: a
     * refused transition changes nothing the chain holds.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\JournalRow  $journalRow
     * @return bool
     *
     * @throws \JsonException
     */
    private function refusesTransitionOf(#[\SensitiveParameter] JournalRow $journalRow): bool
    {
        $payload = $journalRow->payloadMap();

        return match ($journalRow->kind) {
            JournalKind::HOLD            => $this->failsToPlace($journalRow->holdId),
            JournalKind::RELEASE         => $this->failsToRelease($journalRow->holdId),
            JournalKind::PRUNE           => $this->failsToPrune($journalRow->sealId, $payload),
            JournalKind::PRUNE_RUN       => $payload !== null && $this->failsToRun($payload),
            JournalKind::IMPORT_STARTED  => $payload !== null && $this->failsToOpen(self::BATCH_ID, $payload[self::BATCH_ID] ?? null),
            JournalKind::IMPORT_FINISHED => $payload !== null && $this->failsToClose(self::BATCH_ID, $payload[self::BATCH_ID] ?? null),
            default                      => false,
        };
    }

    /**
     * Place the hold, and whether the chain refuses it: a hold with no id, or
     * one whose id was ever placed before.
     *
     * @param  ?string  $holdId
     * @return bool
     */
    private function failsToPlace(?string $holdId): bool
    {
        if ($holdId === null || $this->hasPlaced($holdId)) {
            return true;
        }

        $this->placed[$holdId] = true;
        $this->active[$holdId] = true;

        return false;
    }

    /**
     * Release the hold, and whether the chain refuses it: a release of no hold,
     * or of one that is not active.
     *
     * @param  ?string  $holdId
     * @return bool
     */
    private function failsToRelease(?string $holdId): bool
    {
        if ($holdId === null || !array_key_exists($holdId, $this->active)) {
            return true;
        }

        unset($this->active[$holdId]);

        return false;
    }

    /**
     * Whether the chain refuses the prune chunk: one that names no seal and,
     * with its payload, one whose record covers another seal, or whose run is
     * not open.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  ?string  $sealId
     * @param  ?array<array-key, mixed>  $payload
     * @return bool
     */
    private function failsToPrune(?string $sealId, #[\SensitiveParameter] ?array $payload): bool
    {
        if ($sealId === null) {
            return true;
        }

        if ($payload === null) {
            return false;
        }

        $record = $payload['record']     ?? null;
        $runId  = $payload[self::RUN_ID] ?? null;

        return !is_array($record) || ($record['seal_id'] ?? null) !== $sealId || !is_string($runId) || !array_key_exists($runId, $this->open[self::RUN_ID]);
    }

    /**
     * Start or finish the prune run its payload names, and whether the chain
     * refuses it: a phase that is neither, a start of a run already open, or a
     * finish of one that is not.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $payload
     * @return bool
     */
    private function failsToRun(#[\SensitiveParameter] array $payload): bool
    {
        $runId = $payload[self::RUN_ID] ?? null;

        return match ($payload['phase'] ?? null) {
            'start'  => $this->failsToOpen(self::RUN_ID, $runId),
            'finish' => $this->failsToClose(self::RUN_ID, $runId),
            default  => true,
        };
    }

    /**
     * Open the run or the batch, and whether the chain refuses it: an id that
     * is not text, or one already open.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  'batch_id'|'run_id'  $key
     * @param  mixed  $id
     * @return bool
     */
    private function failsToOpen(string $key, mixed $id): bool
    {
        if (!is_string($id) || array_key_exists($id, $this->open[$key])) {
            return true;
        }

        $this->open[$key][$id] = true;

        return false;
    }

    /**
     * Finish the run or the batch, and whether the chain refuses it: an id that
     * is not text, or one that is not open, never started or finished already.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  'batch_id'|'run_id'  $key
     * @param  mixed  $id
     * @return bool
     */
    private function failsToClose(string $key, mixed $id): bool
    {
        if (!is_string($id) || !array_key_exists($id, $this->open[$key])) {
            return true;
        }

        unset($this->open[$key][$id]);

        return false;
    }
}
