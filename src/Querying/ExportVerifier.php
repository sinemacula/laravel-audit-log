<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Querying;

use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Contracts\Encryption\StringEncrypter;
use Illuminate\Database\ConnectionResolverInterface;
use SineMacula\Laravel\AuditLog\Access\AccessScope;
use SineMacula\Laravel\AuditLog\Access\Enums\ReadPurpose;
use SineMacula\Laravel\AuditLog\Access\ScopeCompiler;
use SineMacula\Laravel\AuditLog\Contracts\AuditAccessPolicy;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Export\Enums\ExportFormat;
use SineMacula\Laravel\AuditLog\Integrity\ArtifactInspector;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Integrity\KeyRing;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException;
use SineMacula\Laravel\AuditLog\Querying\Enums\ExportFinding;
use SineMacula\Laravel\AuditLog\Querying\Enums\PackageActivity;
use SineMacula\Laravel\AuditLog\Records\Enums\ArtifactKind;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Records\EnvelopeCodec;
use SineMacula\Laravel\AuditLog\Records\ExportManifest;
use SineMacula\Laravel\AuditLog\Runtime\ReportLatch;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;

/**
 * Verifies an export through the whole chain, from the bundle to each line of
 * the file, and records the verification before returning what it found.
 *
 * A denied viewer runs no statement and sees the entry missing, exactly as one
 * outside the scope does.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ExportVerifier
{
    /** @var string The reason of a denied verification. */
    private const string NO_SCOPE = 'no_scope';

    /** @var string The reason of a verification whose policy threw. */
    private const string POLICY_FAILED = 'policy_failed';

    /** @var string The reason of a verification whose statement failed. */
    private const string QUERY_FAILED = 'query_failed';

    /** @var string A lower-case UUID, as an entry's id. */
    private const string UUID_PATTERN = '/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/';

    /** @var string A CEF line's id: its extension's first field, after an unescaped pipe. */
    private const string CEF_ID_PATTERN = '/(?<!\\\)\|externalId=([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?: |\z)/';

    /** @var int One more than a stored JSON column's depth, for the envelope's own object. */
    private const int LINE_DEPTH = 513;

    /** @var list<string> The columns of the artifact a verification reads. */
    private const array ARTIFACT_COLUMNS = ['id', 'entry_id', 'kind', 'member_count', 'digest', 'members'];

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Resolved from on every call, so the verifier outlives requests safely. */
        private Container $container,
    ) {}

    /**
     * Verify the export at the path and return what the chain found.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\Viewer  $viewer
     * @param  string  $path
     * @return \SineMacula\Laravel\AuditLog\Querying\ExportVerification
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException
     */
    public function verify(#[\SensitiveParameter] Viewer $viewer, string $path): ExportVerification
    {
        $gate = $this->container->make(ReadGate::class);

        $gate->enter();

        return $gate->window(fn (): ExportVerification => $this->run($viewer, $path));
    }

    /**
     * Authorise, run the chain and record the verification.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\Viewer  $viewer
     * @param  string  $path
     * @return \SineMacula\Laravel\AuditLog\Querying\ExportVerification
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException
     */
    private function run(#[\SensitiveParameter] Viewer $viewer, string $path): ExportVerification
    {
        $policy = $this->container->make(AuditAccessPolicy::class);
        $name   = get_debug_type($policy);

        $record = function (
            ?AccessScope $scope,
            Outcome $outcome,
            ?string $reason,
            #[\SensitiveParameter] ?StoredEntry $entry = null,
            ExportFinding ...$findings,
        ) use (
            $viewer,
            $name,
        ): void {
            $values = [];

            foreach ($findings as $finding) {
                $values[] = $finding->value;
            }

            $terms    = ReadTerms::of($this->container->make(KeyRing::class)->signingKey(), TrailFilters::none(), $scope);
            $evidence = AccessEvidence::forVerification($terms, $name, $entry === null ? null : [$entry->id(), $entry->hmac()], $values, $outcome);

            $this->container->make(AccessRecorder::class)->record(PackageActivity::EXPORT_VERIFIED, $viewer, $scope, $evidence, $outcome, $reason);
        };

        $scope  = $this->authorise($policy, $viewer, static fn () => $record(null, Outcome::FAILURE, self::POLICY_FAILED));
        $denied = $scope->isDenied();

        [$findings, $entry, $lines, $entryId] = $this->chain($denied ? null : $scope, $path, static fn () => $record($scope, Outcome::FAILURE, self::QUERY_FAILED));

        $record($scope, $denied ? Outcome::DENIED : Outcome::SUCCESS, $denied ? self::NO_SCOPE : null, $entry, ...$findings);

        return new ExportVerification($entryId, $lines, $findings);
    }

    /**
     * The viewer's scope for `verify`; a policy that throws is recorded as a
     * failure and what it threw propagates unchanged.
     *
     * @param  \SineMacula\Laravel\AuditLog\Contracts\AuditAccessPolicy  $policy
     * @param  \SineMacula\Laravel\AuditLog\Querying\Viewer  $viewer
     * @param  \Closure(): void  $recordFailure
     * @return \SineMacula\Laravel\AuditLog\Access\AccessScope
     *
     * @throws \Throwable
     */
    private function authorise(AuditAccessPolicy $policy, #[\SensitiveParameter] Viewer $viewer, #[\SensitiveParameter] \Closure $recordFailure): AccessScope
    {
        // The policy is the application's code, which may throw anything
        /** @throws \Throwable */
        $ask = static fn (): AccessScope => $policy->scope($viewer->original, ReadPurpose::VERIFY);

        try {
            return $ask();
        } catch (\Throwable $failure) {
            $this->refuseOnceRecorded($recordFailure, $failure);
        }
    }

    /**
     * The chain's findings, the entry found, the file's lines and the bundle's
     * entry id; a `null` scope runs no statement.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  ?\SineMacula\Laravel\AuditLog\Access\AccessScope  $scope
     * @param  string  $path
     * @param  \Closure(): void  $recordFailure
     * @return array{0: list<\SineMacula\Laravel\AuditLog\Querying\Enums\ExportFinding>, 1: ?\SineMacula\Laravel\AuditLog\Querying\StoredEntry, 2: int, 3: ?string}
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function chain(?AccessScope $scope, string $path, #[\SensitiveParameter] \Closure $recordFailure): array
    {
        $bundled = is_file($path . ExportFile::MANIFEST_SUFFIX) ? @file_get_contents($path . ExportFile::MANIFEST_SUFFIX, false, null, 0, EnvelopeCodec::MAX_BYTES + 1) : false;
        $bundle  = is_string($bundled) ? ExportBundle::decode($bundled) : null;

        if ($bundle === null) {
            return [[ExportFinding::BUNDLE_MALFORMED], null, 0, null];
        }

        $id     = $bundle['entry']['id'] ?? null;
        $id     = is_string($id) && preg_match(self::UUID_PATTERN, $id) === 1 ? $id : null;
        $lookup = fn (string $id, AccessScope $scope): ?array => $this->row(EntrySettings::table(), array_keys(RowCodec::COLUMNS), $id, $scope);
        $row    = $scope === null || $id === null ? null : $this->attempt(static fn (): ?array => $lookup($id, $scope), $recordFailure);

        [$found, $entry, $plaintext] = $row === null ? [[ExportFinding::ENTRY_MISSING], null, null] : $this->journalFindings($row, $bundle, $recordFailure);
        [$checked, $fields]          = self::manifestFindings($plaintext, $bundle, $entry);
        [$read, $lines]              = $fields === null ? [[], 0] : $this->fileFindings($path, $fields);

        return [self::inChainOrder([...$found, ...$checked, ...$read]), $entry, $lines, $id];
    }

    /**
     * The findings of the entry, its descriptor and its artifact, the entry,
     * and the artifact's plaintext when it is the manifest the entry signed.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, scalar|null>  $row
     * @param  array{descriptor: array{artifact_id: string, count: int, digest: string, kind: string}, entry: array<array-key, mixed>, manifest: string}  $bundle
     * @param  \Closure(): void  $recordFailure
     * @return array{0: list<\SineMacula\Laravel\AuditLog\Querying\Enums\ExportFinding>, 1: ?\SineMacula\Laravel\AuditLog\Querying\StoredEntry, 2: ?string}
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function journalFindings(#[\SensitiveParameter] array $row, #[\SensitiveParameter] array $bundle, #[\SensitiveParameter] \Closure $recordFailure): array
    {
        try {
            $entry = StoredEntry::fromRow($row, $this->container->make(RowCodec::class));
        } catch (\UnexpectedValueException) {
            // A row that does not decode cannot be verified, nor what it names
            return [[ExportFinding::ENTRY_UNVERIFIABLE], null, null];
        }

        $swapped  = $entry->envelope['event'] !== PackageActivity::TRAIL_EXPORTED->value || !self::encodesAlike($entry->envelope, $bundle['entry']);
        $found    = [$this->signatureFinding($entry->envelope, ExportFinding::ENTRY_UNVERIFIABLE, ExportFinding::ENTRY_TAMPERED), $swapped ? ExportFinding::ENTRY_SWAPPED : null];
        $signed   = $entry->descriptor() ?? [];
        $isExport = ArtifactInspector::isDescriptor($signed) && $signed['kind'] === ArtifactKind::EXPORT->value;

        if (!$isExport || !self::encodesAlike($signed, $bundle['descriptor'])) {
            $found[] = ExportFinding::DESCRIPTOR_MISMATCH;
        }

        [$found[], $plaintext] = $isExport ? $this->artifactFindings($entry->id(), $signed, $recordFailure) : [null, null];

        return [array_values(array_filter($found)), $entry, $plaintext];
    }

    /**
     * The artifact's finding, or none and its plaintext, which is then the
     * manifest the descriptor signed.
     *
     * @param  string  $entryId
     * @param  array{artifact_id: string, count: int, digest: string, kind: string}  $descriptor
     * @param  \Closure(): void  $recordFailure
     * @return array{0: ?\SineMacula\Laravel\AuditLog\Querying\Enums\ExportFinding, 1: ?string}
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException
     */
    private function artifactFindings(string $entryId, array $descriptor, #[\SensitiveParameter] \Closure $recordFailure): array
    {
        $stored  = $this->attempt(fn (): ?array => $this->row(EntrySettings::artifactsTable(), self::ARTIFACT_COLUMNS, $descriptor['artifact_id']), $recordFailure);
        $finding = ArtifactInspector::columnsFinding($stored, $entryId, $descriptor);

        if ($finding !== null) {
            return [ExportFinding::fromArtifactFinding($finding), null];
        }

        try {
            $plaintext = $this->container->make(StringEncrypter::class)->decryptString((string) ($stored['members'] ?? ''));
        } catch (DecryptException) {
            return [ExportFinding::ARTIFACT_UNDECRYPTABLE, null];
        }

        $finding = ArtifactInspector::plaintextFinding($plaintext, $descriptor);

        return $finding === null ? [null, $plaintext] : [ExportFinding::fromArtifactFinding($finding), null];
    }

    /**
     * The file's findings against the manifest's fields, and its line count.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $path
     * @param  array<array-key, mixed>  $fields
     * @return array{0: list<\SineMacula\Laravel\AuditLog\Querying\Enums\ExportFinding>, 1: int}
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function fileFindings(string $path, array $fields): array
    {
        $format = ExportFormat::tryFrom(is_string($fields['format'] ?? null) ? $fields['format'] : '');
        $scan   = $format === null ? null : $this->scan($path, $format);

        if ($scan === null) {
            return [[ExportFinding::FILE_MISMATCH], 0];
        }

        $found = $scan['findings'];

        if ($scan['sha256'] !== ($fields['file_sha256'] ?? null)) {
            $found[] = ExportFinding::FILE_MISMATCH;
        }

        if (!self::isMembership($scan, $fields, $format)) {
            $found[] = ExportFinding::MEMBERSHIP_MISMATCH;
        }

        return [$found, $scan['lines']];
    }

    /**
     * Read the file a line at a time, or `null` when it cannot be opened.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  string  $path
     * @param  \SineMacula\Laravel\AuditLog\Export\Enums\ExportFormat  $format
     * @return ?array{sha256: string, lines: int, membership: string, first: ?array{0: ?string, 1: string}, last: ?array{0: ?string, 1: string}, findings: list<\SineMacula\Laravel\AuditLog\Querying\Enums\ExportFinding>}
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function scan(string $path, ExportFormat $format): ?array
    {
        $handle = is_file($path) ? @fopen($path, 'rb') : false;

        if ($handle === false) {
            return null;
        }

        $file       = hash_init('sha256');
        $membership = new MembershipDigest;
        $lines      = 0;
        $first      = null;
        $last       = null;
        $found      = [];

        try {
            while (($line = fgets($handle)) !== false) {
                hash_update($file, $line);

                [$last, $finding] = $this->lineFindings(str_ends_with($line, "\n") ? substr($line, 0, -1) : $line, $format);

                $first                        = ++$lines === 1 ? $last : $first;
                $found[$finding->value ?? ''] = $finding;

                if ($last === null) {
                    continue;
                }

                $membership->add($last[1]);
            }
        } finally {
            fclose($handle);
        }

        return [
            'sha256'     => hash_final($file),
            'lines'      => $lines,
            'membership' => $membership->digest(),
            'first'      => $first,
            'last'       => $last,
            'findings'   => array_values(array_filter($found)),
        ];
    }

    /**
     * A line's position, or `null` when it names no id, and its finding.
     *
     * @param  string  $line
     * @param  \SineMacula\Laravel\AuditLog\Export\Enums\ExportFormat  $format
     * @return array{0: ?array{0: ?string, 1: string}, 1: ?\SineMacula\Laravel\AuditLog\Querying\Enums\ExportFinding}
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function lineFindings(#[\SensitiveParameter] string $line, ExportFormat $format): array
    {
        if ($format === ExportFormat::CEF) {
            return preg_match(self::CEF_ID_PATTERN, $line, $match) === 1 ? [[null, $match[1]], null] : [null, ExportFinding::LINE_MALFORMED];
        }

        $envelope = self::objectOf($line);
        $position = self::positionOf($format, $envelope);

        if ($position === null) {
            return [null, ExportFinding::LINE_MALFORMED];
        }

        return [$position, $format->isEvidence() ? $this->signatureFinding($envelope, ExportFinding::LINE_UNVERIFIABLE, ExportFinding::LINE_TAMPERED) : null];
    }

    /**
     * The finding of the envelope's signature, or `null` when it matches.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $envelope
     * @param  \SineMacula\Laravel\AuditLog\Querying\Enums\ExportFinding  $unverifiable
     * @param  \SineMacula\Laravel\AuditLog\Querying\Enums\ExportFinding  $tampered
     * @return ?\SineMacula\Laravel\AuditLog\Querying\Enums\ExportFinding
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function signatureFinding(#[\SensitiveParameter] array $envelope, ExportFinding $unverifiable, ExportFinding $tampered): ?ExportFinding
    {
        try {
            return $this->container->make(RecordSigner::class)->verifies($envelope) ? null : $tampered;
        } catch (\UnexpectedValueException|UnknownKeyException) {
            // A signature that cannot be checked is unverifiable, not tampered
            return $unverifiable;
        }
    }

    /**
     * The row with the id, within the scope if given, read on the writer as a
     * fresh process may run before a replica catches up.
     *
     * @param  string  $table
     * @param  list<string>  $columns
     * @param  string  $id
     * @param  ?\SineMacula\Laravel\AuditLog\Access\AccessScope  $scope
     * @return ?array<string, scalar|null>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private function row(string $table, array $columns, string $id, ?AccessScope $scope = null): ?array
    {
        $query = $this->container->make(ConnectionResolverInterface::class)->connection(StorageConnection::name())->table($table)->useWritePdo();
        $query = $scope === null ? $query->where('id', '=', $id) : $this->container->make(ScopeCompiler::class)->entry($query, $scope, $id);
        $row   = $query->first($columns);

        /** @var ?array<string, scalar|null> */
        return $row === null ? null : (array) $row;
    }

    /**
     * What the statement returns; a failure is recorded, then refused naming
     * only its class.
     *
     * @template TResult
     *
     * @param  \Closure(): TResult  $statement
     * @param  \Closure(): void  $recordFailure
     * @return TResult
     *
     * @throws \SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException
     *
     * @param-immediately-invoked-callable $statement
     */
    private function attempt(#[\SensitiveParameter] \Closure $statement, #[\SensitiveParameter] \Closure $recordFailure): mixed
    {
        try {
            return $statement();
        } catch (\Throwable $failure) {
            $this->refuseOnceRecorded($recordFailure, AuditReadRefusedException::failed($failure::class));
        }
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
            try {
                $handler = $this->container->make(ExceptionHandler::class);

                $this->container->make(ReportLatch::class)->once(static function () use ($handler, $failure): void {
                    $handler->report($failure);
                });
            } catch (\Throwable) {
                // A broken reporter must not replace the refusal
            }
        }

        throw $refusal;
    }

    /**
     * The manifest's findings and fields: the artifact's when read, else the
     * bundle's, checked against the signed digest.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  ?string  $plaintext
     * @param  array{descriptor: array{artifact_id: string, count: int, digest: string, kind: string}, entry: array<array-key, mixed>, manifest: string}  $bundle
     * @param  ?\SineMacula\Laravel\AuditLog\Querying\StoredEntry  $entry
     * @return array{0: list<\SineMacula\Laravel\AuditLog\Querying\Enums\ExportFinding>, 1: ?array<array-key, mixed>}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private static function manifestFindings(#[\SensitiveParameter] ?string $plaintext, #[\SensitiveParameter] array $bundle, #[\SensitiveParameter] ?StoredEntry $entry): array
    {
        $manifest = $plaintext            ?? $bundle['manifest'];
        $signed   = $entry?->descriptor() ?? [];
        $digest   = ArtifactInspector::isDescriptor($signed) ? $signed['digest'] : $bundle['descriptor']['digest'];
        $fields   = ExportManifest::read($manifest)['fields'] ?? null;

        $matches = $plaintext === null ? $fields !== null && hash('sha256', $manifest) === $digest : $plaintext === $bundle['manifest'];

        return [$matches ? [] : [ExportFinding::MANIFEST_MISMATCH], $fields];
    }

    /**
     * A JSON line's recorded instant (NDJSON only) and id, or `null`.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \SineMacula\Laravel\AuditLog\Export\Enums\ExportFormat  $format
     * @param  array<array-key, mixed>  $envelope
     * @return ?array{0: ?string, 1: string}
     */
    private static function positionOf(ExportFormat $format, #[\SensitiveParameter] array $envelope): ?array
    {
        $metadata   = $envelope['metadata'] ?? null;
        $uid        = $metadata instanceof \stdClass ? ($metadata->uid ?? null) : null;
        $id         = $format === ExportFormat::OCSF ? $uid : ($envelope['id'] ?? null);
        $recordedAt = $format->isEvidence() ? ($envelope['recorded_at'] ?? null) : null;
        $recordedAt = is_string($recordedAt) ? $recordedAt : null;

        return is_string($id) ? [$recordedAt, $id] : null;
    }

    /**
     * The members of a JSON object line, objects kept as objects, or none.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $line
     * @return array<array-key, mixed>
     */
    private static function objectOf(#[\SensitiveParameter] string $line): array
    {
        try {
            $decoded = json_decode($line, false, self::LINE_DEPTH, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return [];
        }

        return $decoded instanceof \stdClass ? get_object_vars($decoded) : [];
    }

    /**
     * Whether the file's lines match the manifest's count, membership and, for
     * NDJSON, positions.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array{sha256: string, lines: int, membership: string, first: ?array{0: ?string, 1: string}, last: ?array{0: ?string, 1: string}, findings: list<\SineMacula\Laravel\AuditLog\Querying\Enums\ExportFinding>}  $scan
     * @param  array<array-key, mixed>  $fields
     * @param  \SineMacula\Laravel\AuditLog\Export\Enums\ExportFormat  $format
     * @return bool
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private static function isMembership(array $scan, array $fields, ExportFormat $format): bool
    {
        $positions = !$format->isEvidence() || [$scan['first'], $scan['last']] === [$fields['first'] ?? null, $fields['last'] ?? null];

        return $positions && $scan['lines'] === ($fields['lines'] ?? null) && $scan['membership'] === ($fields['membership_sha256'] ?? null);
    }

    /**
     * The findings in the order the chain checks them, each once.
     *
     * @param  list<\SineMacula\Laravel\AuditLog\Querying\Enums\ExportFinding>  $findings
     * @return list<\SineMacula\Laravel\AuditLog\Querying\Enums\ExportFinding>
     */
    private static function inChainOrder(array $findings): array
    {
        return array_values(array_filter(ExportFinding::cases(), static fn (ExportFinding $finding): bool => in_array($finding, $findings, true)));
    }

    /**
     * Whether the two values have the same canonical encoding.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $stored
     * @param  mixed  $bundled
     * @return bool
     */
    private static function encodesAlike(#[\SensitiveParameter] mixed $stored, #[\SensitiveParameter] mixed $bundled): bool
    {
        try {
            return CanonicalEncoder::encode($stored) === CanonicalEncoder::encode($bundled);
        } catch (\UnexpectedValueException) {
            // A value with no canonical form was not kept as given
            return false;
        }
    }
}
