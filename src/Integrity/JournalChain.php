<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Integrity;

use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;

/**
 * The rules of the lifecycle journal's chain, applied to its rows one at a time
 * in sequence order: the one place they live, for verification and for the
 * replay a destructive operation decides from.
 *
 * Each row must follow the one before it: its sequence one more, 1 first, its
 * previous HMAC the HMAC of the row before, none first, and its log the
 * configured one, else it is a gap; one that does not move the sequence
 * forward, repeated or out of order, is never applied. Its HMAC must verify
 * under the key it names, and a payload it was read with must be the text its
 * digest was taken of, else it is a signature finding, or an unverifiable one
 * when the ring does not hold its key. A row that fails its signature is never
 * applied, so the head stays the last good row; the next row is still linked to
 * it as it is stored, so one bad row is one finding. A row that cannot be read
 * at all is malformed, and the row after it is held only to a later sequence,
 * since there is nothing to link it to.
 *
 * A good row is then a transition the chain must allow. A hold names a hold id
 * never placed before, active or released, since hold ids are never reused; a
 * release names an active hold; a prune names a seal, and, read with its
 * payload, the seal its record covers. Where payloads are read, every prune
 * chunk and every prune run's finish names a run that started and has not
 * finished, and every import's finish a batch that started and has not
 * finished, so a second finish is refused too, as is a second start of one
 * still open. Only the ids are kept: of the holds ever placed and still active,
 * and of the runs and batches still open, each dropped at its finish, so what
 * the chain holds grows with holds and open operations, never with the journal.
 *
 * The chain holds no resource, so a clone of it is independent of it, which a
 * replay kept as a value relies on.
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

    /** @var array<string, array<string, true>> The ids of the runs and the batches started and not yet finished, by the payload key that names them. */
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
     * Read the next row: its link to the row before, its signature and, when it
     * is good, the transition it makes. The findings it gives are returned,
     * each with the row's id, in that order.
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
     * and its payload, if it was read, is the text of its digest: a key the
     * ring does not hold is unverifiable, and an HMAC no key could have made is
     * malformed.
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
