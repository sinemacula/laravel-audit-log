<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\QueryException;
use Illuminate\Support\Str;
use SineMacula\Laravel\AuditLog\Config\IntegerSetting;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Contracts\RetentionPolicy;
use SineMacula\Laravel\AuditLog\Database\FailureClassifier;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\JournalSigner;
use SineMacula\Laravel\AuditLog\Integrity\SealSettings;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportFormat;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportRejection;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportStatus;
use SineMacula\Laravel\AuditLog\Records\SourceSettings;
use SineMacula\Laravel\AuditLog\Support\StoredTime;

/**
 * Imports another system's records, as a privileged operation: a file of either
 * import format read into this installation's entries, as its acceptance of a
 * foreign assertion, never as activity it witnessed.
 *
 * An import is refused inside a transaction on the storage or the maintenance
 * connection, with a malformed import setting, and when its source is this
 * installation, whose own records come back through `audit-log:replay`. The
 * file's SHA-256 is read first, whole. The installation is confirmed, the batch
 * row inserted `running`, and one lifecycle transaction then verifies the
 * journal and appends `import_started` and, with a hold asked for, places the
 * hold on the batch, its journal row and projection row with it, so the hold
 * commits with the start, before any entry; a failure of that transaction
 * journals the batch's finish if its start did commit, marks the batch
 * `failed`, with no entry written, and is rethrown. The file is then read
 * again, its lines parsed and written in chunks of `audit-log.import.chunk`,
 * each in its own storage transaction, and hashed as it is read: a file that
 * changed between the two reads fails the batch. The batch ends `complete` when
 * nothing was rejected and nothing conflicted and `partial` otherwise. Any
 * failure after the start ends it `failed`, as best it can, reporting what
 * fails, leaves the hold in place, and is rethrown, a failed statement masked
 * so no binding of an imported record reaches the caller's reporter.
 *
 * The journal is the truth of how a batch ended, and the batch row follows it:
 * `import_finished` is journalled first, behind the lifecycle lock, only while
 * the verified journal holds the batch's `import_started` and no finish of it,
 * and the batch is made final after, as best it can. A batch whose finish could
 * not be journalled stays `running`, which `audit-log:check` notes once it is
 * stale; one whose finish was journalled but whose row was not made final is
 * made final by `close()`. So a batch's finish is journalled at most once,
 * never for a batch that never started, and a crash at any boundary leaves a
 * batch that `close()` brings to its end.
 *
 * Imported rows are signed by this installation's ring and sealed in its chain,
 * marked imported, never dispatched as `AuditRecorded` and never delivered to a
 * destination. A dry run reads, validates, minimises encrypting nothing and
 * classifies, counts the lines already past retention on arrival, and writes
 * nothing: no batch, no journal row, no key, no record.
 *
 * `close()` brings a batch whose import stopped to its end: a running batch
 * whose start the journal holds and whose finish it does not is journalled
 * `interrupted`, under its import's operation, and marked so; one whose finish
 * the journal holds is marked with the status journalled, which journals
 * nothing; one the journal never started is marked `interrupted` and journals
 * nothing; and a final batch whose start the journal holds with no finish has
 * that finish journalled from its row. Any other batch, and an id that is not a
 * lower-case UUID, is refused before anything is read. The activity records of
 * an import and its hold are written by the caller once the operation has
 * committed; a caller told of the start, through the closure it may give, can
 * record the hold even when the import then fails.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AuditImporter
{
    /** @var string The pattern of a batch id: a lower-case UUID. */
    private const string BATCH_ID = '/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/';

    /** @var string The refusal of a batch that cannot be closed. */
    private const string NOT_CLOSABLE = 'Only a running import batch, or a final one whose finish was never journalled, is closed.';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\MaintenanceTransaction  $transaction
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Journal  $journal
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\HoldKeeper  $holds
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportBatches  $batches
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportWriter  $writer
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportSettings  $settings
     * @param  \SineMacula\Laravel\AuditLog\Contracts\Clock  $clock
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportJournal  $batchJournal
     *
     * @SuppressWarnings("php:S107")
     */
    public function __construct(

        /** The container the parsers, the policy and the journal's signer are resolved from on every import. */
        private Container $container,

        /** The frame of the journal rows, behind the lifecycle lock. */
        private MaintenanceTransaction $transaction,

        /** The journal an import's start and finish are appended to. */
        private Journal $journal,

        /** Places the hold an import asks for with its start. */
        private HoldKeeper $holds,

        /** The batches table. */
        private ImportBatches $batches,

        /** Writes each chunk of lines. */
        private ImportWriter $writer,

        /** The chunk size and the longest line read. */
        private ImportSettings $settings,

        /** The time ids are drawn and lines imported at. */
        private Clock $clock,

        /** Where a batch stands in the verified journal. */
        private ImportJournal $batchJournal,
    ) {}

    /**
     * Import the source on the authority given, or plan it as a dry run, with a
     * hold on its batch, of the basis given, placed with its start when one is
     * asked for. The closure given, if any, is told of the start once it has
     * committed, with the result as it then stands; what it throws fails the
     * batch, as any failure after the start does.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportSource  $source
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Authority  $authority
     * @param  bool  $dryRun
     * @param  bool  $hold
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis  $basis
     * @param  ?\Closure(\SineMacula\Laravel\AuditLog\Lifecycle\ImportResult): void  $started
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ImportResult
     *
     * @throws \SineMacula\Laravel\AuditLog\Database\InstallationMismatchException
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\LifecycleContentionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \RuntimeException
     * @throws \UnexpectedValueException
     * @throws \Throwable
     */
    public function import(
        ImportSource $source,
        Authority $authority,
        bool $dryRun = false,
        bool $hold = false,
        HoldBasis $basis = HoldBasis::OTHER,
        #[\SensitiveParameter]
        ?\Closure $started = null,
    ): ImportResult {
        $this->refuseInsideATransaction();
        $this->settings->validate();
        $this->refuseOwnSource($source);

        $file        = new ImportFile($source->path);
        $sha256      = $file->sha256();
        $now         = $this->clock->now();
        $operationId = Str::uuid7($now)->toString();
        $tally       = new ImportTally;
        $retention   = $this->retentionAt($now, $tally);

        if ($dryRun) {
            $this->read($file, $source, $tally, fn (#[\SensitiveParameter] array $lines) => $this->writer->plan($lines, $tally, $this->clock->now(), $retention));

            return ImportResult::of($operationId, true, null, null, null, $tally);
        }

        $this->transaction->confirm();

        $batchId = Str::uuid7($now)->toString();
        $holdId  = $hold ? Str::uuid7($now)->toString() : null;
        $import  = [$operationId, $batchId, $sha256, StoredTime::toStorage(StoredTime::format($now))];

        $this->batches->start(self::batchOf($import, $source, $authority, $holdId));

        [$replay, $placed] = $this->start($import, $holdId, $source, $authority, $basis);

        $begun  = $started === null ? null : static fn () => $started(ImportResult::of($operationId, false, $batchId, ImportStatus::RUNNING, $placed, $tally));
        $status = $this->run($file, $source, $tally, $retention, $import, $replay, $authority, $begun);

        return ImportResult::of($operationId, false, $batchId, $status, $placed, $tally);
    }

    /**
     * Bring the batch whose import stopped to its end, on the authority given:
     * journal its finish when the journal holds its start and no finish, then
     * make it final with the status the journal holds. A batch the journal
     * never started is marked `interrupted`; any other batch, and a malformed
     * id, is refused.
     *
     * @param  string  $batchId
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Authority  $authority
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ImportResult
     *
     * @throws \SineMacula\Laravel\AuditLog\Database\InstallationMismatchException
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\JournalBrokenException
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\LifecycleContentionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function close(string $batchId, Authority $authority): ImportResult
    {
        $this->refuseInsideATransaction();

        [$batch, $stored, $startedAt] = self::closable($batchId, fn (string $id): ?array => $this->batches->find($id));

        $running = $stored === ImportStatus::RUNNING;

        $this->transaction->confirm();

        $import = [Str::uuid7($this->clock->now())->toString(), $batchId, self::textOf($batch['file_sha256'] ?? null) ?? '', $startedAt];

        $closing = $running ? ImportStatus::INTERRUPTED : $stored;

        [$status, $operationId, $journalled] = $this->journalFinish($import, $this->replay(), $authority, $closing, self::countsOf($batch), false, $running);

        $status ??= ImportStatus::INTERRUPTED;

        if ($running) {
            $this->batches->settles($batchId, $status);
        }

        return self::closed($operationId ?? $import[0], $journalled || $operationId === null, $batchId, $status, $batch);
    }

    /**
     * Tell the closure given of the start, read and write the file's lines,
     * check the file did not change, journal the batch's finish, then make the
     * batch final as best it can, and return the status journalled; a failure
     * before the finish was journalled ends the batch `failed`, as best it can,
     * and is rethrown masked.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportFile  $file
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportSource  $source
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportTally  $tally
     * @param  ?\SineMacula\Laravel\AuditLog\Lifecycle\RetentionDecisions  $retention
     * @param  array{0: string, 1: string, 2: string, 3: string}  $import
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay  $replay
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Authority  $authority
     * @param  ?\Closure(): void  $started
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportStatus
     *
     * @throws \UnexpectedValueException
     * @throws \Throwable
     *
     * @SuppressWarnings("php:S107")
     */
    private function run(
        ImportFile $file,
        ImportSource $source,
        ImportTally $tally,
        ?RetentionDecisions $retention,
        array $import,
        JournalReplay $replay,
        Authority $authority,
        #[\SensitiveParameter]
        ?\Closure $started,
    ): ImportStatus {
        [, $batchId, $sha256] = $import;

        try {
            if ($started !== null) {
                $started();
            }

            $this->read($file, $source, $tally, fn (#[\SensitiveParameter] array $lines) => $this->writer->write($batchId, $lines, $tally, $this->clock->now(), $retention));

            if (!hash_equals($sha256, $file->readDigest())) {
                throw new \UnexpectedValueException('The import file changed while it was read (`source_changed`), so the batch failed.');
            }

            $ended  = $tally->isComplete() ? ImportStatus::COMPLETE : ImportStatus::PARTIAL;
            $status = $this->journalFinish($import, $replay, $authority, $ended, $tally->toBatch())[0] ?? $ended;
        } catch (\Throwable $exception) {
            $this->fail($import, $replay, $authority, $tally, false);

            throw $exception instanceof QueryException ? FailureClassifier::masked($exception) : $exception;
        }

        $this->succeeds('Marking a finished import\'s batch final', fn () => $this->batches->settles($batchId, $status, $tally));

        return $status;
    }

    /**
     * Begin the import in one lifecycle transaction: the journal verified,
     * `import_started` appended and, with a hold id, the hold placed on the
     * batch; return the replay that accepted them and the hold, once committed.
     * A failure ends the batch `failed`, as best it can, journalling its finish
     * only if its start did commit, and is rethrown masked.
     *
     * @param  array{0: string, 1: string, 2: string, 3: string}  $import
     * @param  ?string  $holdId
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportSource  $source
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Authority  $authority
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis  $basis
     * @return array{0: \SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay, 1: ?\SineMacula\Laravel\AuditLog\Lifecycle\Hold}
     *
     * @throws \Throwable
     */
    private function start(array $import, ?string $holdId, ImportSource $source, Authority $authority, HoldBasis $basis): array
    {
        [$operationId, $batchId, $sha256] = $import;

        $payload = [
            'batch_id'            => $batchId,
            'source_id'           => $source->sourceId,
            'source_region'       => $source->region,
            'format'              => $source->format->value,
            'file_sha256'         => $sha256,
            'externally_verified' => false,
            'hold_id'             => $holdId,
        ];

        $replay = $this->replay();

        try {
            return $this->transaction->run($operationId, function (Connection $connection) use ($replay, $operationId, $batchId, $holdId, $authority, $basis, $payload): array {
                $next = $this->journal->append($connection, $replay->verify($connection), JournalKind::IMPORT_STARTED, $operationId, $authority, $payload, holdId: $holdId);

                if ($holdId === null) {
                    return [$next, null];
                }

                [$hold, $next] = $this->holds->placeIn($connection, $next, $operationId, HoldScope::all()->importBatch($batchId), $authority, $basis, null, $holdId);

                return [$next, $hold];
            });
        } catch (\Throwable $exception) {
            $this->fail($import, $replay, $authority, new ImportTally, true);

            throw $exception instanceof QueryException ? FailureClassifier::masked($exception) : $exception;
        }
    }

    /**
     * Read the file's lines, counting each, rejecting those that cannot be read
     * or parsed, and hand the rest to the closure a chunk at a time.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportFile  $file
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportSource  $source
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportTally  $tally
     * @param  \Closure(list<\SineMacula\Laravel\AuditLog\Lifecycle\ImportLine>): void  $write
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    private function read(ImportFile $file, ImportSource $source, ImportTally $tally, #[\SensitiveParameter] \Closure $write): void
    {
        $parser = $source->format === ImportFormat::EXPORT_V1 ? $this->container->make(ExportLineAdapter::class) : $this->container->make(ImportLineParser::class);
        $size   = $this->settings->chunk();
        $chunk  = [];

        foreach ($file->lines($this->settings->maxLineBytes()) as $number => $text) {
            $tally->countRead();

            $line = $text instanceof ImportRejection ? $text : $parser->parse($number, $text, $source);

            if ($line instanceof ImportRejection) {
                $tally->countRejected($line);

                continue;
            }

            $tally->countDropped($line->dropped);

            $chunk[] = $line;

            if (count($chunk) < $size) {
                continue;
            }

            $write($chunk);

            $chunk = [];
        }

        if ($chunk === []) {
            return;
        }

        $write($chunk);
    }

    /**
     * End the batch `failed`, each step as best it can, reporting what fails:
     * its finish journalled while the journal holds its start and no finish,
     * then the batch made final with the status the journal holds, or `failed`
     * when the journal never started it. A batch whose finish could not be
     * journalled stays `running` for `close()`, unless its start may never have
     * committed, which marks it `failed` all the same; a batch closed while its
     * import ran is left as its close left it.
     *
     * @param  array{0: string, 1: string, 2: string, 3: string}  $import
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay  $replay
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Authority  $authority
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportTally  $tally
     * @param  bool  $atStart
     * @return void
     */
    private function fail(array $import, JournalReplay $replay, Authority $authority, ImportTally $tally, bool $atStart): void
    {
        $status     = null;
        $journalled = $this->succeeds('Journalling a failed import\'s finish', function () use ($import, $replay, $authority, $tally, $atStart, &$status): void {
            $status = $this->journalFinish($import, $replay, $authority, ImportStatus::FAILED, $tally->toBatch(), !$atStart)[0];
        });

        if (!$journalled && !$atStart) {
            return;
        }

        $this->succeeds('Marking a failed import\'s batch final', fn () => $this->batches->settles($import[1], $status ?? ImportStatus::FAILED, $tally));
    }

    /**
     * Journal the batch's finish in one lifecycle transaction, onto the replay
     * of the import's start advanced, or onto a fresh replay verified, under
     * its import's operation, unless the verified journal already holds a
     * finish of the batch or no start of it; return the status the journal then
     * holds for the batch, the operation it is journalled under, and whether
     * this call journalled it, or nothing for a batch never started. Unless
     * `$finishedToo`, a batch the journal finished already, or never started,
     * is refused.
     *
     * @param  array{0: string, 1: string, 2: string, 3: string}  $import
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay  $replay
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Authority  $authority
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportStatus  $status
     * @param  array{lines_read: int, imported: int, duplicates: int, conflicts: int, rejected: int, conflict_ids?: ?string}  $counts
     * @param  bool  $advance
     * @param  bool  $finishedToo
     * @return array{0: ?\SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportStatus, 1: ?string, 2: bool}
     *
     * @throws \Throwable
     */
    private function journalFinish(
        array $import,
        JournalReplay $replay,
        Authority $authority,
        ImportStatus $status,
        array $counts,
        bool $advance = true,
        bool $finishedToo = true,
    ): array {
        [$operationId, $batchId, $sha256, $since] = $import;

        $payload = [
            'batch_id'    => $batchId,
            'status'      => $status->value,
            'lines_read'  => $counts['lines_read'],
            'imported'    => $counts['imported'],
            'duplicates'  => $counts['duplicates'],
            'conflicts'   => $counts['conflicts'],
            'rejected'    => $counts['rejected'],
            'file_sha256' => $sha256,
        ];

        $append = function (Connection $connection) use ($replay, $advance, $authority, $payload, $batchId, $since, $status, $finishedToo): array {
            $head             = $advance ? $replay->advance($connection) : $replay->verify($connection);
            [$start, $finish] = $this->batchJournal->of($connection, $batchId, $since);

            if ($start === null || $finish !== null) {
                return [self::journalled($finishedToo, $finish[1]['status'] ?? null, $start === null), $start?->operationId, false];
            }

            $this->journal->append($connection, $head, JournalKind::IMPORT_FINISHED, $start->operationId, $authority, $payload);

            return [$status, $start->operationId, true];
        };

        return $this->transaction->run($operationId, $append);
    }

    /**
     * Whether the step succeeds, run as best it can: a failure is reported,
     * named by its class alone, so nothing of a line, a statement or a binding
     * reaches a reporter.
     *
     * @param  string  $what
     * @param  \Closure(): void  $step
     * @return bool
     */
    private function succeeds(string $what, #[\SensitiveParameter] \Closure $step): bool
    {
        try {
            $step();
        } catch (\Throwable $exception) {
            $this->container->make(ExceptionHandler::class)->report(new \RuntimeException(sprintf('%s did not complete: %s.', $what, $exception::class)));

            return false;
        }

        return true;
    }

    /**
     * The run's retention decisions at the instant given, which count the lines
     * past retention on arrival, or `null` when the bound policy cannot be
     * resolved: the count is then given up, reported once by its class, and the
     * import goes on.
     *
     * @param  \DateTimeInterface  $now
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportTally  $tally
     * @return ?\SineMacula\Laravel\AuditLog\Lifecycle\RetentionDecisions
     */
    private function retentionAt(\DateTimeInterface $now, ImportTally $tally): ?RetentionDecisions
    {
        $decisions = null;
        $resolved  = $this->succeeds('Resolving the retention policy an import counts the lines past retention with', function () use ($now, &$decisions): void {
            $decisions = new RetentionDecisions($this->container->make(RetentionPolicy::class), $now);
        });

        if (!$resolved) {
            $tally->givePastRetentionUp();
        }

        return $decisions;
    }

    /**
     * A fresh replay of nothing yet, of the configured log, for one lifecycle
     * transaction.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private function replay(): JournalReplay
    {
        return JournalReplay::start($this->container->make(JournalSigner::class), $this->container->make(SealSettings::class)->logId());
    }

    /**
     * Refuse an import inside a transaction on the storage or the maintenance
     * connection: its chunks would become savepoints of the host's.
     *
     * @return void
     *
     * @throws \LogicException
     */
    private function refuseInsideATransaction(): void
    {
        $database = $this->container->make(DatabaseManager::class);

        if ($database->connection(StorageConnection::name())->transactionLevel() === 0 && $database->connection(StorageConnection::forMaintenance())->transactionLevel() === 0) {
            return;
        }

        throw new \LogicException('An import runs outside any transaction on the storage and the maintenance connections, and refuses to run inside one.');
    }

    /**
     * Refuse a source that is this installation, before its file is read.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportSource  $source
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private function refuseOwnSource(ImportSource $source): void
    {
        if ($source->sourceId !== $this->container->make(SourceSettings::class)->id()) {
            return;
        }

        throw new \InvalidArgumentException('An import\'s source is never this installation\'s own `source.id`; its own records come back through `audit-log:replay`.');
    }

    /**
     * The batch to close, its stored status and when it started, refused before
     * anything is read when its id is not a lower-case UUID, and when it does
     * not exist.
     *
     * @param  string  $batchId
     * @param  \Closure(string): ?array<string, scalar|null>  $find
     * @return array{0: array<string, scalar|null>, 1: \SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportStatus, 2: string}
     *
     * @throws \InvalidArgumentException
     */
    private static function closable(string $batchId, #[\SensitiveParameter] \Closure $find): array
    {
        $batch     = preg_match(self::BATCH_ID, $batchId) === 1 ? $find($batchId) : null;
        $status    = ImportStatus::tryFrom(self::textOf($batch['status'] ?? null) ?? '');
        $startedAt = self::textOf($batch['started_at'] ?? null);

        if ($batch === null || $status === null || $startedAt === null) {
            throw new \InvalidArgumentException(self::NOT_CLOSABLE);
        }

        return [$batch, $status, $startedAt];
    }

    /**
     * The status the journal holds for a batch it never started, `null`, or
     * finished, the finish's; refused unless `$finishedToo`, since a close of a
     * final batch journals only the finish it lacks.
     *
     * @param  bool  $finishedToo
     * @param  bool|float|int|string|null  $status
     * @param  bool  $neverStarted
     * @return ?\SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportStatus
     *
     * @throws \InvalidArgumentException
     */
    private static function journalled(bool $finishedToo, bool|float|int|string|null $status, bool $neverStarted): ?ImportStatus
    {
        if (!$finishedToo) {
            throw new \InvalidArgumentException(self::NOT_CLOSABLE);
        }

        if ($neverStarted) {
            return null;
        }

        return ImportStatus::tryFrom(is_string($status) ? $status : '') ?? ImportStatus::INTERRUPTED;
    }

    /**
     * The result of a close: its operation, whether it committed a finish of
     * its own or ended a batch never started, the batch, the status reached,
     * and the counts and conflicts the batch row holds.
     *
     * @param  string  $operationId
     * @param  bool  $committed
     * @param  string  $batchId
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportStatus  $status
     * @param  array<string, scalar|null>  $batch
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ImportResult
     */
    private static function closed(string $operationId, bool $committed, string $batchId, ImportStatus $status, array $batch): ImportResult
    {
        $counts = self::countsOf($batch);

        return new ImportResult(
            operationId: $operationId,
            committed: $committed,
            recorded: false,
            dryRun: false,
            batchId: $batchId,
            status: $status,
            holdId: self::textOf($batch['hold_id'] ?? null),
            hold: null,
            linesRead: $counts['lines_read'],
            imported: $counts['imported'],
            duplicates: $counts['duplicates'],
            conflicts: $counts['conflicts'],
            rejected: $counts['rejected'],
            rejections: [],
            conflictIds: self::conflictIdsOf($batch['conflict_ids'] ?? null),
            pastRetention: 0,
            dropped: 0,
        );
    }

    /**
     * The columns the batch's import gives its row.
     *
     * @param  array{0: string, 1: string, 2: string}  $import
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportSource  $source
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Authority  $authority
     * @param  ?string  $holdId
     * @return array<string, bool|string|null>
     */
    private static function batchOf(array $import, ImportSource $source, Authority $authority, ?string $holdId): array
    {
        return [
            'id'                  => $import[1],
            'source_id'           => $source->sourceId,
            'source_region'       => $source->region,
            'input_format'        => $source->format->value,
            'importer_type'       => $authority->operator->type,
            'importer_id'         => $authority->operator->id,
            'reason'              => $authority->reason,
            'external_reference'  => $authority->externalReference,
            'file_sha256'         => $import[2],
            'externally_verified' => false,
            'hold_id'             => $holdId,
        ];
    }

    /**
     * The counts the stored batch holds.
     *
     * @param  array<string, scalar|null>  $batch
     * @return array{lines_read: int, imported: int, duplicates: int, conflicts: int, rejected: int}
     */
    private static function countsOf(array $batch): array
    {
        $count = static fn (string $column): int => IntegerSetting::parse($batch[$column] ?? null) ?? 0;

        return [
            'lines_read' => $count('lines_read'),
            'imported'   => $count('imported'),
            'duplicates' => $count('duplicates'),
            'conflicts'  => $count('conflicts'),
            'rejected'   => $count('rejected'),
        ];
    }

    /**
     * The conflicting ids the stored batch lists, or none.
     *
     * @param  bool|float|int|string|null  $stored
     * @return list<string>
     */
    private static function conflictIdsOf(bool|float|int|string|null $stored): array
    {
        $ids = is_string($stored) ? json_decode($stored, true) : null;

        return is_array($ids) ? array_values(array_filter($ids, is_string(...))) : [];
    }

    /**
     * The stored value as text, or `null` for anything else.
     *
     * @param  bool|float|int|string|null  $value
     * @return ?string
     */
    private static function textOf(bool|float|int|string|null $value): ?string
    {
        return is_string($value) ? $value : null;
    }
}
