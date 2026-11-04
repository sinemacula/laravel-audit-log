<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use Illuminate\Database\Connection;
use Illuminate\Support\Str;
use SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Integrity\AnchoredHead;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\NullAnchor;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\JournalRow;
use SineMacula\Laravel\AuditLog\Integrity\JournalSigner;
use SineMacula\Laravel\AuditLog\Integrity\SealSettings;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ErasureStatus;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * Erases again, after a database was restored, every owner an erasures file
 * names, and journals the restore reconciled once every one of them is erased.
 *
 * The file is the operator's own record of the owners erased since the restored
 * head, one JSON object per line, `{"type": <owner type>, "id": <owner id>}`,
 * at most 100,000 lines that are not blank, each of at most 1,024 bytes; a
 * blank line is skipped. It is read twice: whole first, for its SHA-256 and its
 * length, refused with an `InvalidArgumentException` before anything is erased
 * when it holds more lines than that; then line by line, hashing again as it
 * reads, each read a mebibyte at a time. A line that is not exactly such an
 * object, or is longer than the limit, is rejected and counted; an owner named
 * twice is erased once.
 *
 * Each owner is erased on its own, in part and accepting pending deliveries,
 * since the restored outbox is no new evidence and a blocked key's obligation
 * stands: by the eraser under a fresh operation, or by the erasure given, which
 * `AuditLifecycle` makes `erase()`, so each is recorded as any erasure is. A
 * refused erasure is counted and the next owner erased; any other failure stops
 * the run, and the erasures before it stand. A file whose second read differs
 * from its first fails the run with an `UnexpectedValueException`, journalling
 * nothing. The owners are erased in one `ErasureRun`, so the installation is
 * confirmed once and each journal row verified once for the whole file, never
 * once per owner.
 *
 * Only when the file was read whole and unchanged, no line was rejected and
 * every owner ended erased whole or already erased is a `restore_reconciled`
 * row appended, in one `MaintenanceTransaction` onto the verified head, naming
 * the authority, the file's SHA-256, the counts, and the anchor's head as it
 * reports it, its sequence and digest, both `null` when the anchor cannot
 * report one; an anchor that fails to answer fails the run before anything is
 * journalled. That row is what tells `audit-log:check` the restore was
 * reconciled.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ErasureReapplier
{
    /** @var int The most lines an erasures file may hold. */
    public const int MAX_LINES = 100000;

    /** @var int The longest line an erasures file may hold, in bytes, without its line feed. */
    public const int MAX_LINE_BYTES = 1024;

    /** @var string Why a file that changed between its two reads fails the run. */
    private const string CHANGED = 'The erasures file changed while its owners were erased again; the restore is not reconciled.';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Eraser  $eraser
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Journal  $journal
     * @param  \SineMacula\Laravel\AuditLog\Integrity\JournalSigner  $signer
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\MaintenanceTransaction  $transaction
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealSettings  $settings
     * @param  \SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor  $anchor
     * @param  \SineMacula\Laravel\AuditLog\Contracts\Clock  $clock
     */
    public function __construct(

        /** Erases each owner when no erasure is given. */
        private Eraser $eraser,

        /** The journal the reconciliation is appended to. */
        private Journal $journal,

        /** The signer the journal is verified with. */
        private JournalSigner $signer,

        /** The frame the reconciliation is journalled in, behind the lifecycle lock. */
        private MaintenanceTransaction $transaction,

        /** The settings the journal's log id is read from. */
        private SealSettings $settings,

        /** The anchor whose head the reconciliation names. */
        private CheckpointAnchor $anchor,

        /** The time each owner's own operation id is minted at. */
        private Clock $clock,
    ) {}

    /**
     * Erase again every owner the file at the path names, by the erasure given
     * or the eraser's, and journal the restore reconciled under the operation
     * when every one ended erased; return what was done.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  string  $operationId
     * @param  string  $path
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Authority  $authority
     * @param  ?\Closure(\SineMacula\Laravel\AuditLog\Records\Reference, \SineMacula\Laravel\AuditLog\Lifecycle\ErasureRun): \SineMacula\Laravel\AuditLog\Lifecycle\ErasureResult  $erase
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ReapplyResult
     *
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\LifecycleContentionException
     * @throws \SineMacula\Laravel\AuditLog\Database\InstallationMismatchException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     * @throws \Throwable
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public function reapply(string $operationId, string $path, Authority $authority, #[\SensitiveParameter] ?\Closure $erase = null): ReapplyResult
    {
        $file   = new ImportFile($path);
        $digest = self::measured($file);
        $erase ??= function (#[\SensitiveParameter] Reference $owner, ErasureRun $erasures) use ($authority): ErasureResult {
            $ownOperationId = $this->ownOperationId();

            return $this->eraser->erase($ownOperationId, $owner, $authority, true, true, $erasures);
        };
        $tally  = self::unchanged($file, $digest, $this->eraseEach($file, $erase));
        $counts = [$tally['owners'], $tally['erased'], $tally['already']];

        if ($tally['rejected'] > 0 || $tally['partial'] > 0 || $tally['refused'] > 0) {
            return new ReapplyResult(
                $operationId,
                $digest,
                ...$counts,
                partial: $tally['partial'],
                refused: $tally['refused'],
                rejected: $tally['rejected'],
                recorded: $tally['recorded'],
            );
        }

        $head = $this->anchoredHead();
        $row  = $this->journalled($operationId, $authority, [
            'file_sha256'       => $digest,
            'owners'            => $tally['owners'],
            'erased'            => $tally['erased'],
            'already_erased'    => $tally['already'],
            'anchored_sequence' => $head?->sequence,
            'anchored_digest'   => $head?->digest,
        ]);

        return new ReapplyResult(
            $operationId,
            $digest,
            ...$counts,
            partial: 0,
            refused: 0,
            rejected: 0,
            recorded: $tally['recorded'],
            reconciliationId: $row->id,
            anchoredSequence: $head?->sequence,
            anchoredDigest: $head?->digest,
        );
    }

    /**
     * The file's SHA-256, read whole first, refused when it holds more lines
     * that are not blank than a reapply reads.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportFile  $file
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private static function measured(ImportFile $file): string
    {
        $lines = $file->lines(self::MAX_LINE_BYTES);
        $count = 0;

        for ($lines->rewind(); $lines->valid(); $lines->next()) {
            if (++$count > self::MAX_LINES) {
                throw new \InvalidArgumentException(sprintf('An erasures file holds at most %d lines that are not blank.', self::MAX_LINES));
            }
        }

        return $file->readDigest();
    }

    /**
     * The tally of the second read, once the file it read is known to be the
     * file the first read measured; a file whose two reads differ is refused.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportFile  $file
     * @param  string  $digest
     * @param  array{owners: int, erased: int, already: int, partial: int, refused: int, rejected: int, recorded: bool}  $tally
     * @return array{owners: int, erased: int, already: int, partial: int, refused: int, rejected: int, recorded: bool}
     *
     * @throws \UnexpectedValueException
     */
    private static function unchanged(ImportFile $file, string $digest, array $tally): array
    {
        if (!hash_equals($digest, $file->readDigest())) {
            throw new \UnexpectedValueException(self::CHANGED);
        }

        return $tally;
    }

    /**
     * Erase each distinct owner the file's lines name, reading them again, in
     * one run of erasures that confirms the installation once and carries the
     * verified journal from owner to owner, and tally how each ended and how
     * many lines were rejected.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportFile  $file
     * @param  \Closure(\SineMacula\Laravel\AuditLog\Records\Reference, \SineMacula\Laravel\AuditLog\Lifecycle\ErasureRun): \SineMacula\Laravel\AuditLog\Lifecycle\ErasureResult  $erase
     * @return array{owners: int, erased: int, already: int, partial: int, refused: int, rejected: int, recorded: bool}
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     * @throws \Throwable
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function eraseEach(ImportFile $file, #[\SensitiveParameter] \Closure $erase): array
    {
        $tally    = ['owners' => 0, 'erased' => 0, 'already' => 0, 'partial' => 0, 'refused' => 0, 'rejected' => 0, 'recorded' => true];
        $seen     = [];
        $erasures = new ErasureRun;

        foreach ($file->lines(self::MAX_LINE_BYTES) as $line) {
            $owner = is_string($line) ? self::ownerOf($line) : null;

            if ($owner === null) {
                $tally['rejected']++;

                continue;
            }

            $key = hash('sha256', $owner->type . "\0" . $owner->id, true);

            if (isset($seen[$key])) {
                continue;
            }

            $seen[$key] = true;

            $tally = self::tallied($tally, $erase, $owner, $erasures);
        }

        return $tally;
    }

    /**
     * The tally with the owner erased, by how the erasure ended: a refusal is
     * counted, and any other failure thrown.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  array{owners: int, erased: int, already: int, partial: int, refused: int, rejected: int, recorded: bool}  $tally
     * @param  \Closure(\SineMacula\Laravel\AuditLog\Records\Reference, \SineMacula\Laravel\AuditLog\Lifecycle\ErasureRun): \SineMacula\Laravel\AuditLog\Lifecycle\ErasureResult  $erase
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ErasureRun  $erasures
     * @return array{owners: int, erased: int, already: int, partial: int, refused: int, rejected: int, recorded: bool}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private static function tallied(array $tally, #[\SensitiveParameter] \Closure $erase, #[\SensitiveParameter] Reference $owner, ErasureRun $erasures): array
    {
        $tally['owners']++;

        try {
            $result = $erase($owner, $erasures);
        } catch (ErasureRefusedException) {
            // A refused owner is counted and left for the operator: the restore
            // stays unreconciled, and the next owner is erased
            $tally['refused']++;

            return $tally;
        }

        $ended = match ($result->status) {
            ErasureStatus::COMPLETE       => 'erased',
            ErasureStatus::PARTIAL        => 'partial',
            ErasureStatus::ALREADY_ERASED => 'already',
        };

        $tally[$ended]++;
        $tally['recorded'] = $tally['recorded'] && $result->recorded;

        return $tally;
    }

    /**
     * The owner a line names: a JSON object of exactly a string `type` and a
     * string or integer `id` that make a reference; `null` for anything else.
     *
     * @param  string  $line
     * @return ?\SineMacula\Laravel\AuditLog\Records\Reference
     */
    private static function ownerOf(#[\SensitiveParameter] string $line): ?Reference
    {
        try {
            $decoded = json_decode($line, true, 2, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            // A line that is not JSON names no owner, and is counted
            return null;
        }

        $named = is_array($decoded) && !array_is_list($decoded) && count($decoded) === 2;
        $type  = $named ? ($decoded['type'] ?? null) : null;
        $id    = $named ? ($decoded['id'] ?? null) : null;

        try {
            return is_string($type) && (is_string($id) || is_int($id)) ? Reference::of($type, $id) : null;
        } catch (\InvalidArgumentException) {
            // A type or an id a reference refuses names no owner, and is
            // counted
            return null;
        }
    }

    /**
     * The anchor's head, or `null` when the anchor is the null anchor or cannot
     * report its head; an anchor that cannot be read throws.
     *
     * @return ?\SineMacula\Laravel\AuditLog\Integrity\AnchoredHead
     */
    private function anchoredHead(): ?AnchoredHead
    {
        if ($this->anchor instanceof NullAnchor || !$this->anchor->supportsDiscovery()) {
            return null;
        }

        return $this->anchor->latest();
    }

    /**
     * Append the `restore_reconciled` row of the payload, under the operation
     * and on the authority given, onto the verified head, once the installation
     * is confirmed; and return it.
     *
     * @param  string  $operationId
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Authority  $authority
     * @param  array{file_sha256: string, owners: int, erased: int, already_erased: int, anchored_sequence: ?int, anchored_digest: ?string}  $payload
     * @return \SineMacula\Laravel\AuditLog\Integrity\JournalRow
     *
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\LifecycleContentionException
     * @throws \SineMacula\Laravel\AuditLog\Database\InstallationMismatchException
     * @throws \Throwable
     */
    private function journalled(string $operationId, Authority $authority, #[\SensitiveParameter] array $payload): JournalRow
    {
        $this->transaction->confirm();

        return $this->transaction->run($operationId, function (Connection $connection) use ($operationId, $authority, $payload): JournalRow {
            $replay = JournalReplay::start($this->signer, $this->settings->logId())->verify($connection);

            return $this->journal->append($connection, $replay, JournalKind::RESTORE_RECONCILED, $operationId, $authority, $payload)->lastAppended()
                ?? throw new \LogicException('The journal accepted a reconciliation its replay does not hold.');
        });
    }

    /**
     * A fresh operation id for one owner's erasure: a UUID v7 of the clock's
     * time.
     *
     * @return string
     */
    private function ownOperationId(): string
    {
        return Str::uuid7($this->clock->now())->toString();
    }
}
