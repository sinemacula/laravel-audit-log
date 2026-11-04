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
 * Reads a page of the trail, or counts its entries, for a viewer, and records
 * the read before anything it found leaves the package.
 *
 * A page size outside 1 to `read.max_per_page` is refused before anything else,
 * and is not recorded; a page that names no size holds `DEFAULT_PER_PAGE`
 * entries, or `read.max_per_page` when that is fewer. The gate then lets the
 * read in or refuses it, and everything after runs inside the read guard's
 * window: the access policy is asked for the viewer's scope for the purpose; a
 * denied scope is answered with a uniform empty result before a cursor is
 * opened, so a viewer whose access was revoked between pages sees what an empty
 * trail shows; a page's cursor is then opened against the read it was issued
 * for; a scope the filters cannot meet is answered with an empty result and no
 * statement; and otherwise one statement reads the storage connection's entries
 * table, a replica when one is configured, narrowed by the scope compiler
 * alone. A page reads one row beyond its size to learn whether another page
 * follows; that row is dropped before it is decoded, so it is never shown,
 * disclosed or counted. The page's entries are projected together, their
 * encrypted fields revealed through one call to the field reader only when the
 * scope reveals them, so a field reader that fails is reported once for the
 * page, and the page's record keeps the scope's grant and how many fragments it
 * showed in each state.
 *
 * Every read after the gate is recorded under its code: a success with what it
 * returned, a denied scope as `denied` with `no_scope`, a refused cursor as
 * `denied` with `cursor_rejected`, and a policy, a statement or a row that
 * fails as `failure` with `policy_failed`, `query_failed` or `format_failed`. A
 * failure is recorded before anything is thrown: the policy's own exception
 * unchanged, the cursor's refusal, and otherwise `AuditReadRefusedException`
 * naming the class that failed and nothing it held. When that record cannot be
 * written, the refusal is thrown all the same and the recording failure is
 * reported once. A success whose record cannot be written returns nothing.
 *
 * It resolves everything from the container on every call, so it outlives
 * requests safely.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class TrailReader
{
    /** @var int How many entries a page holds when it names no size and `read.max_per_page` allows as many. */
    public const int DEFAULT_PER_PAGE = 50;

    /** @var string Why a read whose scope the policy denied returned nothing. */
    private const string NO_SCOPE = 'no_scope';

    /** @var string Why a read whose cursor was refused returned nothing. */
    private const string CURSOR_REJECTED = 'cursor_rejected';

    /** @var string Why a read whose policy threw failed. */
    private const string POLICY_FAILED = 'policy_failed';

    /** @var string Why a read whose statement failed failed. */
    private const string QUERY_FAILED = 'query_failed';

    /** @var string Why a read whose rows could not be decoded or shown failed. */
    private const string FORMAT_FAILED = 'format_failed';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The container everything a read needs is resolved from on every call. */
        private Container $container,
    ) {}

    /**
     * The page of entries the viewer may see under the filters, newest first,
     * after the position the cursor holds, or from the newest without one, once
     * the read is recorded; a page that names no size holds `DEFAULT_PER_PAGE`
     * entries, or `read.max_per_page` when that is fewer.
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
     * How many entries the viewer may see under the filters, once the count is
     * recorded.
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
     * Let the read in through the gate, then run it inside the read guard's
     * window.
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
     * Read and record a page: the scope, then nothing for a denied scope, the
     * cursor, then nothing for a disjoint scope, or the one statement and its
     * projection.
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
            array $returned = [],
            ?FieldDisclosure $fields = null,
        ) use (
            $viewer,
            $filters,
            $policy,
            $perPage,
            $presented,
            &$position,
        ): void {
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

        [$projected, $returned, $next] = $this->attempt(
            fn (): array => $this->project(array_slice($rows, 0, $perPage), $scope->revealsEncryptedFields(), $more),
            static fn () => $record($scope, Outcome::FAILURE, self::FORMAT_FAILED),
        );

        $record($scope, Outcome::SUCCESS, null, $returned, $projected->fields);

        return new TrailPage($projected->entries, $next, $perPage);
    }

    /**
     * Count and record a count: the scope, then nothing for a denied or
     * disjoint scope, or the one `count(*)` statement.
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
     * The scope the policy gives the viewer as the application gave it, for the
     * purpose; a policy that throws is recorded as a failure with no scope, and
     * what it threw propagates unchanged.
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
     * The position the cursor holds, once it is shown to have been issued for
     * this read; a refused cursor is recorded as a denial, then refused.
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
     * Whether the read finds nothing without a statement, once it is recorded:
     * a denied scope as a denial, and a scope the filters cannot meet as a
     * success that returned nothing.
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
     * What the work returns; work that fails is recorded as a failure, then
     * refused, naming the class that failed and nothing it held.
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
     * The rows of the one statement of a page, as the engine returned them:
     * every column of the entries table, narrowed by the scope compiler to the
     * scope, the filters and, after a cursor, the entries after its position,
     * newest first, at most the limit.
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
     * The page shown of the rows, each decoded as stored, then projected
     * together, revealing their encrypted fields when the scope does, the id
     * and HMAC of each, and the cursor of the last one when another page
     * follows, which it does when a binding is given.
     *
     * @param  list<array<string, scalar|null>>  $rows
     * @param  bool  $reveal
     * @param  ?\SineMacula\Laravel\AuditLog\Querying\CursorBinding  $more
     * @return array{0: \SineMacula\Laravel\AuditLog\Querying\ProjectedPage, 1: list<array{0: string, 1: string}>, 2: ?string}
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     * @throws \SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException
     */
    private function project(#[\SensitiveParameter] array $rows, bool $reveal, ?CursorBinding $more): array
    {
        $codec    = $this->container->make(RowCodec::class);
        $stored   = [];
        $returned = [];
        $last     = null;

        foreach ($rows as $row) {
            $last       = StoredEntry::fromRow($row, $codec);
            $stored[]   = $last;
            $returned[] = [$last->id(), $last->hmac()];
        }

        $projected = $this->container->make(EntryProjector::class)->project($stored, $reveal);
        $next      = $more === null || $last === null ? null : $this->container->make(CursorCodec::class)->issue($more, $last->occurredPosition());

        return [$projected, $returned, $next];
    }

    /**
     * A query of the entries table on the storage connection, narrowed by the
     * scope compiler to the scope and the filters.
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
     * The terms of the read under the filters and the scope, fingerprinted
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
     * Record the refusal, then throw it; a recording that fails is reported
     * once, through the report latch, and the refusal is thrown all the same.
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
     * Report the failure to record a refused read once, through the report
     * latch, ignoring a reporter that fails.
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
            // The read is refused all the same; a broken reporter has nowhere
            // left to say so, and must not replace the refusal
        }
    }

    /**
     * Refuse a page size outside 1 to the most a page may ask for, naming the
     * range.
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
