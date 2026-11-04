<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Querying;

use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Query\Builder;
use SineMacula\Laravel\AuditLog\Access\AccessScope;
use SineMacula\Laravel\AuditLog\Access\Enums\ReadPurpose;
use SineMacula\Laravel\AuditLog\Access\ScopeCompiler;
use SineMacula\Laravel\AuditLog\Contracts\AuditAccessPolicy;
use SineMacula\Laravel\AuditLog\Contracts\AuditFormatter;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Delivery\DeliverySettings;
use SineMacula\Laravel\AuditLog\Delivery\Enums\DeliveryMode;
use SineMacula\Laravel\AuditLog\Export\CefFormatter;
use SineMacula\Laravel\AuditLog\Export\Enums\ExportFormat;
use SineMacula\Laravel\AuditLog\Export\OcsfFormatter;
use SineMacula\Laravel\AuditLog\Integrity\KeyRing;
use SineMacula\Laravel\AuditLog\Querying\Enums\Acknowledgement;
use SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Records\ExportManifest;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Records\Manifest;
use SineMacula\Laravel\AuditLog\Runtime\ReportLatch;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;
use SineMacula\Laravel\AuditLog\Support\StoredTime;

/**
 * Exports the entries a viewer may see under the filters to a file, journals
 * the export, and publishes it with its bundle only once the journal is
 * acknowledged.
 *
 * A target that exists without `force`, a directory that does not exist or is
 * not writable or cannot hold a hard link without `force`, an engine an export
 * cannot read, and a malformed `export.chunk` are refused before anything else,
 * and are not recorded. The gate then lets the export in or refuses it, and
 * everything after runs inside the read guard's window: the access policy is
 * asked for the viewer's scope for `export`; the file is prepared beside the
 * target and the snapshot opened; unless the scope is denied or the filters
 * cannot meet it, the bound, the greatest recorded time and id under the scope,
 * is read as the snapshot's first statement, then the entries up to it in
 * chunks of `export.chunk`, ascending by recorded time and then id, each
 * narrowed by the scope compiler alone. Each line is the stored envelope
 * untouched for NDJSON, and the formatter's projection for OCSF and CEF; the
 * bulk members an entry references are never read.
 *
 * The journal is written once the snapshot has ended, so a SQLite reader never
 * becomes a writer: `audit_log.trail_exported`, fail-closed, with the export's
 * manifest as its `export` artifact, `success`, or `denied` with `no_scope` for
 * an export a denied viewer is given, which is empty and published all the
 * same. Its bundle is built from the very envelope the store or the outbox
 * acknowledged, then the bundle and the file are published.
 *
 * A policy that throws is recorded as a failure with `policy_failed`, and what
 * it threw propagates unchanged. A statement that fails is recorded as a
 * failure with `query_failed`, and a line that cannot be formatted or written,
 * or a manifest that cannot be built of what the snapshot and the file hold,
 * with `format_failed`; the snapshot is abandoned, the temporary file removed,
 * and `AuditReadRefusedException` names the class that failed. A journal that
 * cannot be written removes the temporary file and refuses the export, so no
 * file is ever published unrecorded. A publication that fails removes what it
 * had written, is recorded as `audit_log.export_publish_failed` naming the
 * export entry, and refuses the export.
 *
 * It resolves everything from the container on every call, so it outlives
 * requests safely.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Exporter
{
    /** @var string Why an export whose scope the policy denied wrote nothing. */
    private const string NO_SCOPE = 'no_scope';

    /** @var string Why an export whose policy threw failed. */
    private const string POLICY_FAILED = 'policy_failed';

    /** @var string Why an export whose statement failed failed. */
    private const string QUERY_FAILED = 'query_failed';

    /** @var string Why an export whose line could not be formatted or written failed. */
    private const string FORMAT_FAILED = 'format_failed';

    /** @var string Why an export's publication failed. */
    private const string PUBLISH_FAILED = 'publish_failed';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The container everything an export needs is resolved from on every call. */
        private Container $container,
    ) {}

    /**
     * Export the entries the viewer may see under the filters to the path, in
     * the format, replacing what is there only with `force`, and return what
     * was published once the export is journalled and published.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\Viewer  $viewer
     * @param  \SineMacula\Laravel\AuditLog\Querying\TrailFilters  $filters
     * @param  string  $path
     * @param  \SineMacula\Laravel\AuditLog\Export\Enums\ExportFormat  $format
     * @param  bool  $force
     * @return \SineMacula\Laravel\AuditLog\Querying\ExportResult
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException
     */
    public function export(#[\SensitiveParameter] Viewer $viewer, TrailFilters $filters, string $path, ExportFormat $format, bool $force): ExportResult
    {
        ExportFile::check($path, $force);
        ExportSnapshot::check($this->container->make(DatabaseManager::class));

        $chunk = $this->container->make(ReadSettings::class)->exportChunk();
        $gate  = $this->container->make(ReadGate::class);

        $gate->enter();

        return $gate->window(fn (): ExportResult => $this->run($viewer, $filters, $path, $format, $force, $chunk));
    }

    /**
     * Authorise, extract, journal and publish the export, inside the read
     * guard's window.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\Viewer  $viewer
     * @param  \SineMacula\Laravel\AuditLog\Querying\TrailFilters  $filters
     * @param  string  $path
     * @param  \SineMacula\Laravel\AuditLog\Export\Enums\ExportFormat  $format
     * @param  bool  $force
     * @param  int  $chunk
     * @return \SineMacula\Laravel\AuditLog\Querying\ExportResult
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException
     */
    private function run(#[\SensitiveParameter] Viewer $viewer, TrailFilters $filters, string $path, ExportFormat $format, bool $force, int $chunk): ExportResult
    {
        $policy = $this->container->make(AuditAccessPolicy::class);
        $name   = get_debug_type($policy);

        $record = function (
            ?AccessScope $scope,
            Outcome $outcome,
            ?string $reason,
            ?ExportFile $file = null,
            ?Manifest $manifest = null,
        ) use (
            $viewer,
            $filters,
            $format,
            $name,
        ): FinalisedRecord {
            $evidence = AccessEvidence::forExport($this->terms($filters, $scope), $name, $format->value, $file?->lines() ?? 0, $file?->fileSha256(), $manifest, $outcome);

            return $this->container->make(AccessRecorder::class)->record(PackageActivity::TRAIL_EXPORTED, $viewer, $scope, $evidence, $outcome, $reason);
        };

        $scope = $this->authorise($policy, $viewer, static fn (): FinalisedRecord => $record(null, Outcome::FAILURE, self::POLICY_FAILED));

        $recordFailure = static fn (string $reason): FinalisedRecord => $record($scope, Outcome::FAILURE, $reason);

        [$file, $snapshot] = $this->extract($scope, $filters, $path, $format, $force, $chunk, $recordFailure);

        $manifest = $this->describe($file, fn (): Manifest => self::manifestOf($viewer, $this->terms($filters, $scope), $format, $snapshot, $file), $recordFailure);
        $outcome  = $scope->isDenied() ? Outcome::DENIED : Outcome::SUCCESS;
        $journal  = $this->journal($file, static fn (): FinalisedRecord => $record($scope, $outcome, $scope->isDenied() ? self::NO_SCOPE : null, $file, $manifest));

        $this->publish($file, $journal, $manifest, $force, function () use ($viewer, $scope, $journal): void {
            $evidence = AccessEvidence::forPublishFailure($journal->record->id);

            $this->container->make(AccessRecorder::class)->record(PackageActivity::EXPORT_PUBLISH_FAILED, $viewer, $scope, $evidence, Outcome::FAILURE, self::PUBLISH_FAILED);
        });

        return new ExportResult($journal->record->id, $path, $path . ExportFile::MANIFEST_SUFFIX, $format, $file->lines(), $file->fileSha256(), $this->acknowledgement());
    }

    /**
     * The scope the policy gives the viewer as the application gave it, for
     * `export`; a policy that throws is recorded as a failure with no scope,
     * and what it threw propagates unchanged.
     *
     * @param  \SineMacula\Laravel\AuditLog\Contracts\AuditAccessPolicy  $policy
     * @param  \SineMacula\Laravel\AuditLog\Querying\Viewer  $viewer
     * @param  \Closure(): \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $recordFailure
     * @return \SineMacula\Laravel\AuditLog\Access\AccessScope
     *
     * @throws \Throwable
     */
    private function authorise(AuditAccessPolicy $policy, #[\SensitiveParameter] Viewer $viewer, #[\SensitiveParameter] \Closure $recordFailure): AccessScope
    {
        // The policy is the application's code, which may throw anything
        /** @throws \Throwable */
        $ask = static fn (): AccessScope => $policy->scope($viewer->original, ReadPurpose::EXPORT);

        try {
            return $ask();
        } catch (\Throwable $failure) {
            $this->refuseOnceRecorded($recordFailure, $failure);
        }
    }

    /**
     * Prepare the file and read the export into it inside the snapshot, then
     * end the snapshot, returning the file and what the manifest says of the
     * snapshot. A failure abandons the snapshot, removes the temporary file and
     * is recorded under the stage it failed in, then refused.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \SineMacula\Laravel\AuditLog\Access\AccessScope  $scope
     * @param  \SineMacula\Laravel\AuditLog\Querying\TrailFilters  $filters
     * @param  string  $path
     * @param  \SineMacula\Laravel\AuditLog\Export\Enums\ExportFormat  $format
     * @param  bool  $force
     * @param  int  $chunk
     * @param  \Closure(string): \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $recordFailure
     * @return array{0: \SineMacula\Laravel\AuditLog\Querying\ExportFile, 1: array{connection: string, consistency: string, database: string, engine: string, table: string}}
     *
     * @throws \SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function extract(
        AccessScope $scope,
        TrailFilters $filters,
        string $path,
        ExportFormat $format,
        bool $force,
        int $chunk,
        #[\SensitiveParameter] \Closure $recordFailure,
    ): array {
        $stage    = self::FORMAT_FAILED;
        $file     = null;
        $snapshot = null;

        try {
            $file = ExportFile::prepare($path, $force);

            $stage    = self::QUERY_FAILED;
            $snapshot = ExportSnapshot::open($this->container->make(DatabaseManager::class));

            $semantics = $snapshot->semantics();

            if (!$this->container->make(ScopeCompiler::class)->isEmpty($scope, $filters)) {
                $this->copy($snapshot, $scope, $filters, $format, $file, $chunk, $stage);
            }

            $snapshot->close();
        } catch (\Throwable $failure) {
            $snapshot?->abandon();
            $file?->discard();

            $this->refuseOnceRecorded(static fn () => $recordFailure($stage), AuditReadRefusedException::failed($failure::class));
        }

        return [$file, $semantics];
    }

    /**
     * Copy every entry up to the bound into the file, a chunk of the size at a
     * time, keeping the stage the copy is in: a statement, or a line's
     * formatting and writing.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\ExportSnapshot  $snapshot
     * @param  \SineMacula\Laravel\AuditLog\Access\AccessScope  $scope
     * @param  \SineMacula\Laravel\AuditLog\Querying\TrailFilters  $filters
     * @param  \SineMacula\Laravel\AuditLog\Export\Enums\ExportFormat  $format
     * @param  \SineMacula\Laravel\AuditLog\Querying\ExportFile  $file
     * @param  int  $chunk
     * @param  string  $stage
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     */
    private function copy(ExportSnapshot $snapshot, AccessScope $scope, TrailFilters $filters, ExportFormat $format, ExportFile $file, int $chunk, string &$stage): void
    {
        $bound = $this->bound($snapshot, $scope, $filters);

        if ($bound === null) {
            return;
        }

        $stage     = self::FORMAT_FAILED;
        $formatter = $this->formatterOf($format);
        $codec     = $this->container->make(RowCodec::class);
        $position  = null;

        do {
            $stage = self::QUERY_FAILED;
            $rows  = $this->chunk($snapshot, $scope, $filters, $position, $bound, $chunk);
            $stage = self::FORMAT_FAILED;

            foreach ($rows as $row) {
                $entry = StoredEntry::fromRow($row, $codec);

                $file->write($formatter === null ? $entry->line() : $formatter->format($entry->finalised()), $entry->id(), $entry->recordedAt());

                $position = $entry->recordedPosition();
            }
        } while (count($rows) === $chunk);

        $stage = self::QUERY_FAILED;
    }

    /**
     * The greatest recorded time and id under the scope and the filters, read
     * in one statement, or `null` when nothing is there.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\ExportSnapshot  $snapshot
     * @param  \SineMacula\Laravel\AuditLog\Access\AccessScope  $scope
     * @param  \SineMacula\Laravel\AuditLog\Querying\TrailFilters  $filters
     * @return ?\SineMacula\Laravel\AuditLog\Querying\Position
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function bound(ExportSnapshot $snapshot, AccessScope $scope, TrailFilters $filters): ?Position
    {
        $last = (array) ($this->entries($snapshot, $scope, $filters)->orderByDesc('recorded_at')->orderByDesc('id')->first(['recorded_at', 'id']) ?? []);

        if ($last === []) {
            return null;
        }

        $recordedAt = $last['recorded_at'] ?? null;
        $id         = $last['id']          ?? null;

        return new Position(StoredTime::fromStorage(is_string($recordedAt) ? $recordedAt : ''), is_string($id) ? $id : '');
    }

    /**
     * The rows of one chunk, as the engine returned them: every column of the
     * entries table, narrowed by the scope compiler to the scope, the filters
     * and the keyset after the position up to the bound, oldest first, at most
     * the chunk.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\ExportSnapshot  $snapshot
     * @param  \SineMacula\Laravel\AuditLog\Access\AccessScope  $scope
     * @param  \SineMacula\Laravel\AuditLog\Querying\TrailFilters  $filters
     * @param  ?\SineMacula\Laravel\AuditLog\Querying\Position  $position
     * @param  \SineMacula\Laravel\AuditLog\Querying\Position  $bound
     * @param  int  $chunk
     * @return list<array<string, scalar|null>>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function chunk(ExportSnapshot $snapshot, AccessScope $scope, TrailFilters $filters, ?Position $position, Position $bound, int $chunk): array
    {
        $query = $this->container->make(ScopeCompiler::class)->after($this->entries($snapshot, $scope, $filters), $position, $bound);
        $rows  = $query->orderBy('recorded_at')->orderBy('id')->limit($chunk)->get(array_keys(RowCodec::COLUMNS))->all();

        /** @var list<array<string, scalar|null>> */
        return array_values(array_map(static fn (#[\SensitiveParameter] object $row): array => (array) $row, $rows));
    }

    /**
     * A query of the entries table on the snapshot's connection, narrowed by
     * the scope compiler to the scope and the filters.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\ExportSnapshot  $snapshot
     * @param  \SineMacula\Laravel\AuditLog\Access\AccessScope  $scope
     * @param  \SineMacula\Laravel\AuditLog\Querying\TrailFilters  $filters
     * @return \Illuminate\Database\Query\Builder
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function entries(ExportSnapshot $snapshot, AccessScope $scope, TrailFilters $filters): Builder
    {
        return $this->container->make(ScopeCompiler::class)->apply($snapshot->connection()->table(EntrySettings::table()), $scope, $filters);
    }

    /**
     * The formatter of a projection, or `null` for NDJSON, whose line is the
     * stored envelope itself.
     *
     * @param  \SineMacula\Laravel\AuditLog\Export\Enums\ExportFormat  $format
     * @return ?\SineMacula\Laravel\AuditLog\Contracts\AuditFormatter
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function formatterOf(ExportFormat $format): ?AuditFormatter
    {
        return match ($format) {
            ExportFormat::NDJSON => null,
            ExportFormat::OCSF   => $this->container->make(OcsfFormatter::class),
            ExportFormat::CEF    => $this->container->make(CefFormatter::class),
        };
    }

    /**
     * The export's manifest, as the build gives it; a manifest that cannot be
     * built of what the snapshot and the file hold removes the temporary file,
     * is recorded as a failure with `format_failed`, then refused, naming the
     * class that failed and nothing it held.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\ExportFile  $file
     * @param  \Closure(): \SineMacula\Laravel\AuditLog\Records\Manifest  $build
     * @param  \Closure(string): \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $recordFailure
     * @return \SineMacula\Laravel\AuditLog\Records\Manifest
     *
     * @throws \SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException
     *
     * @param-immediately-invoked-callable $build
     */
    private function describe(ExportFile $file, #[\SensitiveParameter] \Closure $build, #[\SensitiveParameter] \Closure $recordFailure): Manifest
    {
        try {
            return $build();
        } catch (\Throwable $failure) {
            $file->discard();

            $this->refuseOnceRecorded(static fn () => $recordFailure(self::FORMAT_FAILED), AuditReadRefusedException::failed($failure::class));
        }
    }

    /**
     * The terms of the export under the filters and the scope, fingerprinted
     * under the ring's signing key.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\TrailFilters  $filters
     * @param  ?\SineMacula\Laravel\AuditLog\Access\AccessScope  $scope
     * @return \SineMacula\Laravel\AuditLog\Querying\ReadTerms
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     * @throws \SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException
     */
    private function terms(TrailFilters $filters, ?AccessScope $scope): ReadTerms
    {
        return ReadTerms::of($this->container->make(KeyRing::class)->signingKey(), $filters, $scope);
    }

    /**
     * Write the journal and return the record the store or the outbox
     * acknowledged; a journal that cannot be written removes the temporary
     * file, and its refusal propagates.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\ExportFile  $file
     * @param  \Closure(): \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @return \SineMacula\Laravel\AuditLog\Records\FinalisedRecord
     *
     * @throws \Throwable
     *
     * @param-immediately-invoked-callable $record
     */
    private function journal(ExportFile $file, #[\SensitiveParameter] \Closure $record): FinalisedRecord
    {
        try {
            return $record();
        } catch (\Throwable $refusal) {
            $file->discard();

            throw $refusal;
        }
    }

    /**
     * Write the bundle, from the journal's acknowledged envelope, the
     * manifest's descriptor and its plaintext, then publish it and the file. A
     * failure removes what was written, is recorded, a recording that fails
     * reported once and swallowed, and refuses the export.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\ExportFile  $file
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $journal
     * @param  \SineMacula\Laravel\AuditLog\Records\Manifest  $manifest
     * @param  bool  $force
     * @param  \Closure(): void  $recordFailure
     * @return void
     *
     * @throws \SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException
     */
    private function publish(
        ExportFile $file,
        #[\SensitiveParameter] FinalisedRecord $journal,
        Manifest $manifest,
        bool $force,
        #[\SensitiveParameter] \Closure $recordFailure,
    ): void {
        try {
            $file->writeBundle(ExportBundle::encode($manifest->descriptor(), $journal->toArray(), $manifest->canonical));
            $file->publish($force);
        } catch (\Throwable $failure) {
            $file->discard();

            try {
                $recordFailure();
            } catch (\Throwable $unrecorded) {
                $this->report($unrecorded);
            }

            throw AuditReadRefusedException::publishFailed($failure::class);
        }
    }

    /**
     * The export's manifest, as an `export` artifact: the format, the viewer,
     * the keyed fingerprints of the scope and the filters, what the snapshot
     * was, and the file's lines, positions and digests.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\Viewer  $viewer
     * @param  \SineMacula\Laravel\AuditLog\Querying\ReadTerms  $terms
     * @param  \SineMacula\Laravel\AuditLog\Export\Enums\ExportFormat  $format
     * @param  array{connection: string, consistency: string, database: string, engine: string, table: string}  $snapshot
     * @param  \SineMacula\Laravel\AuditLog\Querying\ExportFile  $file
     * @return \SineMacula\Laravel\AuditLog\Records\Manifest
     *
     * @throws \InvalidArgumentException
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private static function manifestOf(#[\SensitiveParameter] Viewer $viewer, ReadTerms $terms, ExportFormat $format, array $snapshot, ExportFile $file): Manifest
    {
        return ExportManifest::manifestOf(
            $format->value,
            $viewer->reference,
            $terms->scopeFingerprint ?? '',
            $terms->queryFingerprint,
            $snapshot,
            $file->lines(),
            $file->first(),
            $file->last(),
            $file->fileSha256(),
            $file->membershipSha256(),
        );
    }

    /**
     * How the journal was acknowledged: accepted as a committed outbox row in
     * outbox mode, and stored otherwise.
     *
     * @return \SineMacula\Laravel\AuditLog\Querying\Enums\Acknowledgement
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private function acknowledgement(): Acknowledgement
    {
        return $this->container->make(DeliverySettings::class)->mode() === DeliveryMode::OUTBOX ? Acknowledgement::ACCEPTED : Acknowledgement::STORED;
    }

    /**
     * Record the refusal, then throw it; a recording that fails is reported
     * once, through the report latch, and the refusal is thrown all the same.
     *
     * @param  \Closure(): \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @param  \Throwable  $refusal
     * @return never
     *
     * @throws \Throwable
     */
    private function refuseOnceRecorded(#[\SensitiveParameter] \Closure $record, \Throwable $refusal): never
    {
        try {
            $record();
        } catch (\Throwable $failure) {
            $this->report($failure);
        }

        throw $refusal;
    }

    /**
     * Report a failure to record the export once, through the report latch,
     * ignoring a reporter that fails.
     *
     * @param  \Throwable  $failure
     * @return void
     */
    private function report(\Throwable $failure): void
    {
        try {
            $handler = $this->container->make(ExceptionHandler::class);

            $this->container->make(ReportLatch::class)->once(static function () use ($handler, $failure): void {
                $handler->report($failure);
            });
        } catch (\Throwable) {
            // The export is refused all the same; a broken reporter has nowhere
            // left to say so, and must not replace the refusal
        }
    }
}
