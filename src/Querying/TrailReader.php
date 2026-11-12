<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Querying;

use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\Query\Builder;
use SineMacula\Laravel\AuditLog\Access\AccessScope;
use SineMacula\Laravel\AuditLog\Access\Enums\ReadPurpose;
use SineMacula\Laravel\AuditLog\Access\ScopeCompiler;
use SineMacula\Laravel\AuditLog\Contracts\AuditAccessPolicy;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\KeyRing;
use SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Runtime\ReportLatch;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;

/**
 * Reads a page of the trail, or counts it, for a viewer, and records the read
 * before anything it found leaves the package.
 *
 * A denied scope is answered before a cursor is opened, so a viewer revoked
 * between pages sees what an empty trail shows.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class TrailReader
{
    /** @var int The page size when none is given, capped at `read.max_per_page`. */
    public const int DEFAULT_PER_PAGE = 50;

    /** @var string The reason of a denied read. */
    private const string NO_SCOPE = 'no_scope';

    /** @var string The reason of a read whose cursor was refused. */
    private const string CURSOR_REJECTED = 'cursor_rejected';

    /** @var string The reason of a read whose policy threw. */
    private const string POLICY_FAILED = 'policy_failed';

    /** @var string The reason of a read whose statement failed. */
    private const string QUERY_FAILED = 'query_failed';

    /** @var string The reason of a read whose rows could not be shown. */
    private const string FORMAT_FAILED = 'format_failed';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Resolved from on every call, so the reader outlives requests safely. */
        private Container $container,
    ) {}

    /**
     * The page the viewer may see, newest first, once the read is recorded; a
     * bad page size is refused unrecorded.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\Viewer  $viewer
     * @param  \SineMacula\Laravel\AuditLog\Querying\TrailFilters  $filters
     * @param  ?int  $perPage
     * @param  ?string  $cursor
     * @return \SineMacula\Laravel\AuditLog\Querying\TrailPage
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException
     * @throws \SineMacula\Laravel\AuditLog\Querying\InvalidCursorException
     */
    public function page(#[\SensitiveParameter] Viewer $viewer, TrailFilters $filters, ?int $perPage, ?string $cursor): TrailPage
    {
        $most = $this->container->make(ReadSettings::class)->maxPerPage();
        $perPage ??= min(self::DEFAULT_PER_PAGE, $most);

        self::refuseAPageSizeOutside($perPage, $most);

        return $this->guarded(fn (): TrailPage => $this->readPage($viewer, $filters, $perPage, $cursor));
    }

    /**
     * How many entries the viewer may see, once the count is recorded.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\Viewer  $viewer
     * @param  \SineMacula\Laravel\AuditLog\Querying\TrailFilters  $filters
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException
     */
    public function count(#[\SensitiveParameter] Viewer $viewer, TrailFilters $filters): int
    {
        return $this->guarded(fn (): int => $this->readCount($viewer, $filters));
    }

    /**
     * Let the read in through the gate, then run it inside its window.
     *
     * @template TResult
     *
     * @param  \Closure(): TResult  $read
     * @return TResult
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException
     *
     * @param-immediately-invoked-callable $read
     */
    private function guarded(#[\SensitiveParameter] \Closure $read): mixed
    {
        $gate = $this->container->make(ReadGate::class);

        $gate->enter();

        return $gate->window($read);
    }

    /**
     * Read and record a page.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\Viewer  $viewer
     * @param  \SineMacula\Laravel\AuditLog\Querying\TrailFilters  $filters
     * @param  int  $perPage
     * @param  ?string  $cursor
     * @return \SineMacula\Laravel\AuditLog\Querying\TrailPage
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException
     * @throws \SineMacula\Laravel\AuditLog\Querying\InvalidCursorException
     */
    private function readPage(#[\SensitiveParameter] Viewer $viewer, TrailFilters $filters, int $perPage, ?string $cursor): TrailPage
    {
        $policy    = $this->container->make(AuditAccessPolicy::class);
        $presented = $cursor !== null;
        $position  = null;

        $record = function (
            ?AccessScope $scope,
            Outcome $outcome,
            ?string $reason = null,
            ?FieldDisclosure $fields = null,
            #[\SensitiveParameter] StoredEntry ...$shown,
        ) use (
            $viewer,
            $filters,
            $policy,
            $perPage,
            $presented,
            &$position,
        ): void {
            $returned = [];

            foreach ($shown as $entry) {
                $returned[] = [$entry->id(), $entry->hmac()];
            }

            $fields ??= FieldDisclosure::none($scope?->revealsEncryptedFields() ?? false);
            $evidence = AccessEvidence::forPage($this->terms($filters, $scope), get_debug_type($policy), $presented, $position, $perPage, $returned, $fields, $outcome);

            $this->container->make(AccessRecorder::class)->record(PackageActivity::TRAIL_READ, $viewer, $scope, $evidence, $outcome, $reason);
        };

        $scope = $this->authorise($policy, $viewer, ReadPurpose::READ, $record);

        if ($scope->isDenied()) {
            $record($scope, Outcome::DENIED, self::NO_SCOPE);

            return TrailPage::empty($perPage);
        }

        $binding = CursorBinding::for($viewer, ReadPurpose::READ, $filters, $scope, $perPage, StorageConnection::resolvedName(), EntrySettings::table());

        if ($cursor !== null) {
            $position = $this->open($cursor, $binding, static fn () => $record($scope, Outcome::DENIED, self::CURSOR_REJECTED));
        }

        if ($this->isEmpty($scope, $filters, $record)) {
            return TrailPage::empty($perPage);
        }

        $rows = $this->attempt(fn (): array => $this->rows($scope, $filters, $position, $perPage + 1), static fn () => $record($scope, Outcome::FAILURE, self::QUERY_FAILED));
        $more = count($rows) > $perPage ? $binding : null;

        [$projected, $shown, $next] = $this->attempt(
            fn (): array => $this->project(array_slice($rows, 0, $perPage), $scope->revealsEncryptedFields(), $more),
            static fn () => $record($scope, Outcome::FAILURE, self::FORMAT_FAILED),
        );

        $record($scope, Outcome::SUCCESS, null, $projected->fields, ...$shown);

        return new TrailPage($projected->entries, $next, $perPage);
    }

    /**
     * Count and record a count.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\Viewer  $viewer
     * @param  \SineMacula\Laravel\AuditLog\Querying\TrailFilters  $filters
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException
     */
    private function readCount(#[\SensitiveParameter] Viewer $viewer, TrailFilters $filters): int
    {
        $policy = $this->container->make(AuditAccessPolicy::class);

        $record = function (?AccessScope $scope, Outcome $outcome, ?string $reason = null, int $returned = 0) use ($viewer, $filters, $policy): void {
            $evidence = AccessEvidence::forCount($this->terms($filters, $scope), get_debug_type($policy), $returned, $outcome);

            $this->container->make(AccessRecorder::class)->record(PackageActivity::TRAIL_COUNTED, $viewer, $scope, $evidence, $outcome, $reason);
        };

        $scope = $this->authorise($policy, $viewer, ReadPurpose::COUNT, $record);

        if ($this->isEmpty($scope, $filters, $record)) {
            return 0;
        }

        $count = $this->attempt(fn (): int => $this->entries($scope, $filters)->count(), static fn () => $record($scope, Outcome::FAILURE, self::QUERY_FAILED));

        $record($scope, Outcome::SUCCESS, null, $count);

        return $count;
    }

    /**
     * The viewer's scope for the purpose; a policy that throws is recorded as a
     * failure and what it threw propagates unchanged.
     *
     * @param  \SineMacula\Laravel\AuditLog\Contracts\AuditAccessPolicy  $policy
     * @param  \SineMacula\Laravel\AuditLog\Querying\Viewer  $viewer
     * @param  \SineMacula\Laravel\AuditLog\Access\Enums\ReadPurpose  $purpose
     * @param  \Closure(?\SineMacula\Laravel\AuditLog\Access\AccessScope, \SineMacula\Laravel\AuditLog\Records\Enums\Outcome, ?string): void  $record
     * @return \SineMacula\Laravel\AuditLog\Access\AccessScope
     *
     * @throws \Throwable
     */
    private function authorise(AuditAccessPolicy $policy, #[\SensitiveParameter] Viewer $viewer, ReadPurpose $purpose, #[\SensitiveParameter] \Closure $record): AccessScope
    {
        // The policy is the application's code, which may throw anything
        /** @throws \Throwable */
        $ask = static fn (): AccessScope => $policy->scope($viewer->original, $purpose);

        try {
            return $ask();
        } catch (\Throwable $failure) {
            $this->refuseOnceRecorded(static fn () => $record(null, Outcome::FAILURE, self::POLICY_FAILED), $failure);
        }
    }

    /**
     * The cursor's position; a refused cursor is recorded as a denial, then
     * refused.
     *
     * @param  string  $cursor
     * @param  \SineMacula\Laravel\AuditLog\Querying\CursorBinding  $binding
     * @param  \Closure(): void  $recordRefusal
     * @return \SineMacula\Laravel\AuditLog\Querying\Position
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\AuditLog\Querying\InvalidCursorException
     */
    private function open(string $cursor, CursorBinding $binding, #[\SensitiveParameter] \Closure $recordRefusal): Position
    {
        try {
            return $this->container->make(CursorCodec::class)->open($cursor, $binding);
        } catch (InvalidCursorException $refusal) {
            $this->refuseOnceRecorded($recordRefusal, $refusal);
        }
    }

    /**
     * Whether the read finds nothing without a statement, once recorded.
     *
     * @param  \SineMacula\Laravel\AuditLog\Access\AccessScope  $scope
     * @param  \SineMacula\Laravel\AuditLog\Querying\TrailFilters  $filters
     * @param  \Closure(?\SineMacula\Laravel\AuditLog\Access\AccessScope, \SineMacula\Laravel\AuditLog\Records\Enums\Outcome, ?string): void  $record
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function isEmpty(AccessScope $scope, TrailFilters $filters, #[\SensitiveParameter] \Closure $record): bool
    {
        if ($scope->isDenied()) {
            $record($scope, Outcome::DENIED, self::NO_SCOPE);

            return true;
        }

        if (!$this->container->make(ScopeCompiler::class)->isEmpty($scope, $filters)) {
            return false;
        }

        $record($scope, Outcome::SUCCESS, null);

        return true;
    }

    /**
     * What the work returns; a failure is recorded, then refused naming only
     * its class.
     *
     * @template TResult
     *
     * @param  \Closure(): TResult  $work
     * @param  \Closure(): void  $recordFailure
     * @return TResult
     *
     * @throws \SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException
     *
     * @param-immediately-invoked-callable $work
     */
    private function attempt(#[\SensitiveParameter] \Closure $work, #[\SensitiveParameter] \Closure $recordFailure): mixed
    {
        try {
            return $work();
        } catch (\Throwable $failure) {
            $this->refuseOnceRecorded($recordFailure, AuditReadRefusedException::failed($failure::class));
        }
    }

    /**
     * A page's rows after the position, newest first, at most the limit.
     *
     * @param  \SineMacula\Laravel\AuditLog\Access\AccessScope  $scope
     * @param  \SineMacula\Laravel\AuditLog\Querying\TrailFilters  $filters
     * @param  ?\SineMacula\Laravel\AuditLog\Querying\Position  $position
     * @param  int  $limit
     * @return list<array<string, scalar|null>>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function rows(AccessScope $scope, TrailFilters $filters, ?Position $position, int $limit): array
    {
        $query = $this->entries($scope, $filters);

        if ($position !== null) {
            $this->container->make(ScopeCompiler::class)->before($query, $position);
        }

        $rows = $query->orderByDesc('occurred_at')->orderByDesc('id')->limit($limit)->get(array_keys(RowCodec::COLUMNS))->all();

        /** @var list<array<string, scalar|null>> */
        return array_values(array_map(static fn (#[\SensitiveParameter] object $row): array => (array) $row, $rows));
    }

    /**
     * The projected page, the stored entries, and the next cursor when a
     * binding is given.
     *
     * @param  list<array<string, scalar|null>>  $rows
     * @param  bool  $reveal
     * @param  ?\SineMacula\Laravel\AuditLog\Querying\CursorBinding  $more
     * @return array{0: \SineMacula\Laravel\AuditLog\Querying\ProjectedPage, 1: list<\SineMacula\Laravel\AuditLog\Querying\StoredEntry>, 2: ?string}
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     * @throws \SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException
     */
    private function project(#[\SensitiveParameter] array $rows, bool $reveal, ?CursorBinding $more): array
    {
        $codec  = $this->container->make(RowCodec::class);
        $stored = [];
        $last   = null;

        foreach ($rows as $row) {
            $last     = StoredEntry::fromRow($row, $codec);
            $stored[] = $last;
        }

        $projected = $this->container->make(EntryProjector::class)->project($stored, $reveal);
        $next      = $more === null || $last === null ? null : $this->container->make(CursorCodec::class)->issue($more, $last->occurredPosition());

        return [$projected, $stored, $next];
    }

    /**
     * The entries on the storage connection, narrowed to the scope.
     *
     * @param  \SineMacula\Laravel\AuditLog\Access\AccessScope  $scope
     * @param  \SineMacula\Laravel\AuditLog\Querying\TrailFilters  $filters
     * @return \Illuminate\Database\Query\Builder
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function entries(AccessScope $scope, TrailFilters $filters): Builder
    {
        $query = $this->container->make(ConnectionResolverInterface::class)->connection(StorageConnection::name())->table(EntrySettings::table());

        return $this->container->make(ScopeCompiler::class)->apply($query, $scope, $filters);
    }

    /**
     * The read's terms, fingerprinted under the ring's signing key.
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
     * Record the refusal, then throw it, even when the recording fails.
     *
     * @param  \Closure(): void  $record
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
     * Report a failure to record the read once, ignoring a broken reporter.
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

    /**
     * Refuse a page size outside 1 to the most a page may ask for.
     *
     * @param  int  $perPage
     * @param  int  $most
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function refuseAPageSizeOutside(int $perPage, int $most): void
    {
        if ($perPage >= 1 && $perPage <= $most) {
            return;
        }

        throw new \InvalidArgumentException(sprintf('A page of the audit trail holds from 1 to %d entries.', $most));
    }
}
