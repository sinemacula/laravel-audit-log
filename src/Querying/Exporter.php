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
 * Exports the entries a viewer may see to a file in one snapshot, journals the
 * export, and publishes it with its bundle only once the journal is
 * acknowledged.
 *
 * The journal is written after the snapshot ends, so a SQLite reader never
 * becomes a writer.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Exporter
{
    /** @var string The reason of a denied export. */
    private const string NO_SCOPE = 'no_scope';

    /** @var string The reason of an export whose policy threw. */
    private const string POLICY_FAILED = 'policy_failed';

    /** @var string The reason of an export whose statement failed. */
    private const string QUERY_FAILED = 'query_failed';

    /** @var string The reason of an export that could not format or write. */
    private const string FORMAT_FAILED = 'format_failed';

    /** @var string The reason of an export whose publication failed. */
    private const string PUBLISH_FAILED = 'publish_failed';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Resolved from on every call, so the exporter outlives requests safely. */
        private Container $container,
    ) {}

    /**
     * Export the entries the viewer may see; a bad target, engine or chunk
     * setting is refused before anything is recorded.
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
     * Authorise, extract, journal and publish the export.
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
     * The viewer's scope for `export`; a policy that throws is recorded as a
     * failure and what it threw propagates unchanged.
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
     * Read the export into the file inside the snapshot; a failure is cleaned
     * up, recorded under its stage, then refused.
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
     * Copy every entry up to the bound into the file a chunk at a time,
     * tracking the stage for the failure reason.
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
     * The greatest recorded time and id under the scope, or `null`.
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
     * One chunk's rows after the position up to the bound, oldest first.
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
     * The entries on the snapshot's connection, narrowed to the scope.
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
     * The formatter of a projection, or `null` for NDJSON's stored envelope.
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
     * The export's manifest; a failed build is cleaned up, recorded, then
     * refused naming only its class.
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
     * The export's terms, fingerprinted under the ring's signing key.
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
     * Write the journal, removing the temporary file if it cannot be written,
     * so no file is published unrecorded.
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
     * Write the bundle from the acknowledged envelope, then publish it and the
     * file; a failure is cleaned up, recorded and refused.
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
     * The export's manifest, as an `export` artifact.
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
     * How the journal was acknowledged under the delivery mode.
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
     * Record the refusal, then throw it, even when the recording fails.
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
     * Report a failure to record the export once, ignoring a broken reporter.
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
            // A broken reporter must not replace the refusal
        }
    }
}
