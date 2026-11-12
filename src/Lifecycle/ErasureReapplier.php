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
 * Erases again, after a restore, every owner an erasures file names, and
 * journals the restore reconciled once every one of them is erased.
 *
 * Each owner is erased in part and accepting pending deliveries, since the
 * restored outbox is no new evidence and a blocked key's obligation stands.
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

    /** @var int Longest line of an erasures file, in bytes, without its newline. */
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

        /** Verifies the journal. */
        private JournalSigner $signer,

        /** Journals the reconciliation behind the lifecycle lock. */
        private MaintenanceTransaction $transaction,

        /** Gives the journal's log id. */
        private SealSettings $settings,

        /** The anchor whose head the reconciliation names. */
        private CheckpointAnchor $anchor,

        /** Mints each owner's own operation id. */
        private Clock $clock,
    ) {}

    /**
     * Erase again every owner the file names and journal the restore reconciled
     * when every one ended erased.
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
     * The file's SHA-256, refusing a file with more than `MAX_LINES` lines.
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
     * The tally, refused when the file changed since it was measured.
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
     * Erase each distinct owner the file names in one run of erasures, and
     * tally how each ended.
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
     * The tally with the owner erased; a refusal is counted, any other failure
     * thrown.
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
            // Left for the operator; the restore stays unreconciled
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
     * The owner a `{"type", "id"}` line names, or `null` for anything else.
     *
     * @param  string  $line
     * @return ?\SineMacula\Laravel\AuditLog\Records\Reference
     */
    private static function ownerOf(#[\SensitiveParameter] string $line): ?Reference
    {
        try {
            $decoded = json_decode($line, true, 2, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            // Counted as rejected
            return null;
        }

        $named = is_array($decoded) && !array_is_list($decoded) && count($decoded) === 2;
        $type  = $named ? ($decoded['type'] ?? null) : null;
        $id    = $named ? ($decoded['id'] ?? null) : null;

        try {
            return is_string($type) && (is_string($id) || is_int($id)) ? Reference::of($type, $id) : null;
        } catch (\InvalidArgumentException) {
            // Counted as rejected
            return null;
        }
    }

    /**
     * The anchor's head, or `null` when the anchor cannot report one.
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
     * Append and return the `restore_reconciled` row onto the verified head.
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
     * A fresh UUID v7 operation id for one owner's erasure.
     *
     * @return string
     */
    private function ownOperationId(): string
    {
        return Str::uuid7($this->clock->now())->toString();
    }
}
