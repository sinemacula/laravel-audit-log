<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Querying;

use SineMacula\Laravel\AuditLog\Access\Enums\ReadPurpose;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\DisclosureManifest;
use SineMacula\Laravel\AuditLog\Records\Enums\ArtifactKind;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Records\Manifest;

/**
 * The evidence a read's record must keep exactly: its properties, in the order
 * of the read's code, and the manifest of its artifact, if any.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AccessEvidence
{
    /** @var int Longest policy name kept, in bytes. */
    public const int MAX_POLICY_BYTES = 191;

    /** @var string The package's metadata key in a record's properties. */
    private const string METADATA_KEY = '_audit';

    /** @var string The artifact descriptor's key in the package's metadata. */
    private const string MANIFEST_KEY = 'manifest';

    /** @var string A page that started at the newest entry. */
    private const string FIRST_PAGE = 'first';

    /** @var string A page whose cursor gave no position. */
    private const string CURSOR_PAGE = 'cursor';

    /** @var string A page after a position, under a scope of not exactly one tenant. */
    private const string NEXT_PAGE = 'next';

    /**
     * Constructor.
     *
     * @param  array<string, array<array-key, int|string>|scalar|null>  $properties
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Manifest  $manifest
     */
    private function __construct(

        /** The properties the record keeps, in the order of the read's code. */
        public array $properties,

        /** The manifest of the record's artifact, or `null` for none. */
        public ?Manifest $manifest,
    ) {}

    /**
     * The evidence of a page; a denied or failed page discloses no entry and
     * counts no fragment, but keeps its grant.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\ReadTerms  $terms
     * @param  string  $policy
     * @param  bool  $cursor
     * @param  ?\SineMacula\Laravel\AuditLog\Querying\Position  $page
     * @param  int  $perPage
     * @param  list<array{0: string, 1: string}>  $returned
     * @param  \SineMacula\Laravel\AuditLog\Querying\FieldDisclosure  $fields
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Outcome  $outcome
     * @return self
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException
     *
     * @SuppressWarnings("php:S107")
     */
    public static function forPage(
        ReadTerms $terms,
        string $policy,
        bool $cursor,
        ?Position $page,
        int $perPage,
        #[\SensitiveParameter]
        array $returned,
        FieldDisclosure $fields,
        Outcome $outcome,
    ): self {
        $succeeded = $outcome === Outcome::SUCCESS;
        $members   = $succeeded ? $returned : [];
        $shown     = $succeeded ? $fields : FieldDisclosure::none($fields->reveal);

        return new self([
            ...self::read(ReadPurpose::READ, $terms, $policy),
            'page'     => self::page($terms, $cursor, $page),
            'per_page' => $perPage,
            'returned' => count($members),
            'reveal'   => $shown->reveal,
            'fields'   => $shown->toArray(),
            'outcome'  => $outcome->value,
        ], self::disclosure($terms, $members, $page));
    }

    /**
     * The evidence of a count; a denied or failed count counted none.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\ReadTerms  $terms
     * @param  string  $policy
     * @param  int  $returned
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Outcome  $outcome
     * @return self
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException
     */
    public static function forCount(ReadTerms $terms, string $policy, int $returned, Outcome $outcome): self
    {
        return new self([
            ...self::read(ReadPurpose::COUNT, $terms, $policy),
            'returned' => $outcome === Outcome::SUCCESS ? $returned : 0,
            'outcome'  => $outcome->value,
        ], self::disclosure($terms, []));
    }

    /**
     * The evidence of an export, carrying its manifest unless the export
     * failed, in which case it wrote no line and has no file digest.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\ReadTerms  $terms
     * @param  string  $policy
     * @param  string  $format
     * @param  int  $lines
     * @param  ?string  $fileSha256
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Manifest  $exportManifest
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Outcome  $outcome
     * @return self
     *
     * @throws \LogicException
     */
    public static function forExport(ReadTerms $terms, string $policy, string $format, int $lines, ?string $fileSha256, ?Manifest $exportManifest, Outcome $outcome): self
    {
        $failed = $outcome === Outcome::FAILURE;

        if (!$failed && $exportManifest?->kind !== ArtifactKind::EXPORT) {
            throw new \LogicException('The evidence of an export that succeeded or was denied is its export manifest.');
        }

        return new self([
            ...self::read(ReadPurpose::EXPORT, $terms, $policy),
            'format'      => $format,
            'returned'    => $failed ? 0 : $lines,
            'file_sha256' => $failed ? null : $fileSha256,
            'outcome'     => $outcome->value,
        ], $failed ? self::disclosure($terms, []) : $exportManifest);
    }

    /**
     * The evidence of an export's verification; a denied or failed one
     * discloses no entry.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\ReadTerms  $terms
     * @param  string  $policy
     * @param  ?array{0: string, 1: string}  $exportEntry
     * @param  list<string>  $findings
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\Outcome  $outcome
     * @return self
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException
     */
    public static function forVerification(ReadTerms $terms, string $policy, ?array $exportEntry, array $findings, Outcome $outcome): self
    {
        $read = self::read(ReadPurpose::VERIFY, $terms, $policy);

        unset($read['query_fingerprint']);

        $members = $outcome === Outcome::SUCCESS && $exportEntry !== null ? [$exportEntry] : [];

        return new self([
            ...$read,
            'export_entry' => $exportEntry[0] ?? null,
            'verdict'      => $findings === [] ? 'verified' : 'not_verified',
            'findings'     => $findings,
            'outcome'      => $outcome->value,
        ], self::disclosure($terms, $members));
    }

    /**
     * The evidence of an export whose file could not be published.
     *
     * @param  string  $exportEntryId
     * @return self
     */
    public static function forPublishFailure(string $exportEntryId): self
    {
        return new self(['export_entry' => $exportEntryId, 'outcome' => Outcome::FAILURE->value], null);
    }

    /**
     * Refuse the record unless its properties and metadata encode canonically
     * to exactly the evidence's.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @return void
     *
     * @throws \SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException
     */
    public function assertKeptBy(#[\SensitiveParameter] AuditRecord $record): void
    {
        $properties = $record->properties             ?? [];
        $metadata   = $properties[self::METADATA_KEY] ?? null;

        unset($properties[self::METADATA_KEY]);

        $expected = $this->manifest === null ? null : [self::MANIFEST_KEY => $this->manifest->descriptor()];

        if (!self::encodesAlike($properties, $this->properties) || !self::encodesAlike($metadata, $expected)) {
            throw AuditReadRefusedException::evidenceAltered();
        }
    }

    /**
     * The properties every read names first; a policy name too long to keep
     * exactly is refused.
     *
     * @param  \SineMacula\Laravel\AuditLog\Access\Enums\ReadPurpose  $purpose
     * @param  \SineMacula\Laravel\AuditLog\Querying\ReadTerms  $terms
     * @param  string  $policy
     * @return array{purpose: string, query_fingerprint: string, scope_fingerprint: ?string, fingerprint_key: string, policy: string}
     *
     * @throws \SineMacula\Laravel\AuditLog\Querying\AuditReadRefusedException
     */
    private static function read(ReadPurpose $purpose, ReadTerms $terms, string $policy): array
    {
        if (strlen($policy) > self::MAX_POLICY_BYTES) {
            throw AuditReadRefusedException::evidenceAltered();
        }

        return [
            'purpose'           => $purpose->value,
            'query_fingerprint' => $terms->queryFingerprint,
            'scope_fingerprint' => $terms->scopeFingerprint,
            'fingerprint_key'   => $terms->keyId,
            'policy'            => $policy,
        ];
    }

    /**
     * Where a page started; the position shows only under a single-tenant
     * scope, since a tenantless record could name another tenant's entry.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\ReadTerms  $terms
     * @param  bool  $cursor
     * @param  ?\SineMacula\Laravel\AuditLog\Querying\Position  $page
     * @return array{occurred_at: string, id: string}|string
     */
    private static function page(ReadTerms $terms, bool $cursor, ?Position $page): array|string
    {
        if (!$cursor) {
            return self::FIRST_PAGE;
        }

        if ($page === null) {
            return self::CURSOR_PAGE;
        }

        return $terms->scope?->singleTenant() === null ? self::NEXT_PAGE : ['occurred_at' => $page->time, 'id' => $page->id];
    }

    /**
     * The disclosure of a read's filters, scope, entries and page position.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\ReadTerms  $terms
     * @param  list<array{0: string, 1: string}>  $members
     * @param  ?\SineMacula\Laravel\AuditLog\Querying\Position  $page
     * @return \SineMacula\Laravel\AuditLog\Records\Manifest
     *
     * @throws \InvalidArgumentException
     */
    private static function disclosure(ReadTerms $terms, #[\SensitiveParameter] array $members, ?Position $page = null): Manifest
    {
        return DisclosureManifest::of($terms->filters->normalised(), $terms->scope?->toArray(), $members, $page?->toArray());
    }

    /**
     * Whether the two values have the same canonical encoding.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $kept
     * @param  mixed  $evidence
     * @return bool
     */
    private static function encodesAlike(#[\SensitiveParameter] mixed $kept, #[\SensitiveParameter] mixed $evidence): bool
    {
        try {
            return CanonicalEncoder::encode($kept) === CanonicalEncoder::encode($evidence);
        } catch (\UnexpectedValueException) {
            // A value with no canonical form was not kept as given
            return false;
        }
    }
}
