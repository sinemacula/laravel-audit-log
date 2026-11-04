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
 * The evidence the record of a read of the trail must keep exactly: its
 * properties, in the order of the read's code, and the manifest of the artifact
 * it carries, a disclosure or an export's manifest, or none.
 *
 * Each read names its purpose, the keyed fingerprints of its filters and of the
 * scope the policy answered (`null` when none was), the id of the key that
 * keyed them, the class of the policy, and its own outcome again; a page names
 * where it started, how many entries it showed, whether its scope revealed the
 * encrypted fields and how many fragments it showed in each state, and its
 * disclosure each entry's id and HMAC. A page started at the newest entry is
 * `first`, one whose cursor gave no position, refused or never opened, is
 * `cursor`, and one after a position is that position only under a scope of
 * exactly one tenant, whose record is that tenant's; under any other scope it
 * is `next`, since the record is tenantless and the position could be another
 * tenant's entry, and the position itself is kept in the disclosure. A read
 * that was denied or failed showed nothing, so its evidence names no entry and
 * counts none, of entries or of fragments, whatever it is given; a page keeps
 * its scope's grant all the same. A policy name longer than `MAX_POLICY_BYTES`
 * would not be kept exactly, so it refuses the read with
 * `AuditReadRefusedException`. Evidence is never minimised away:
 * `assertKeptBy()` refuses a record whose properties, less the package's
 * metadata, do not encode canonically to exactly the evidence's, or whose
 * metadata is anything but the descriptor of its manifest, or nothing without
 * one.
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

    /** @var string The key the package's metadata sits under in a record's properties. */
    private const string METADATA_KEY = '_audit';

    /** @var string The key of an artifact's descriptor in the package's metadata. */
    private const string MANIFEST_KEY = 'manifest';

    /** @var string The page of a read that started at the newest entry. */
    private const string FIRST_PAGE = 'first';

    /** @var string The page of a read whose cursor gave no position: it was refused, or never opened. */
    private const string CURSOR_PAGE = 'cursor';

    /** @var string The page of a read after a position, under a scope that is not of exactly one tenant. */
    private const string NEXT_PAGE = 'next';

    /** @var string The verdict of a verification that found nothing wrong. */
    private const string VERIFIED = 'verified';

    /** @var string The verdict of a verification that found anything wrong. */
    private const string NOT_VERIFIED = 'not_verified';

    /**
     * Constructor.
     *
     * @param  array<string, array<array-key, int|string>|scalar|null>  $properties
     * @param  ?\SineMacula\Laravel\AuditLog\Records\Manifest  $manifest
     */
    private function __construct(

        /** The properties the record keeps, in the order of the read's code. */
        public array $properties,

        /** The manifest of the artifact the record carries, or `null` for none. */
        public ?Manifest $manifest,
    ) {}

    /**
     * The evidence of a page: where it started, how many entries it was to
     * hold, the id and HMAC of each entry it showed, in the order shown,
     * whether its scope revealed the encrypted fields and how many fragments it
     * showed in each state, disclosed with the filters, the scope and the
     * position it read after. A denied or failed page showed nothing, and keeps
     * the grant with no fragment counted.
     *
     * Its parameters are the parts of the page's evidence, each from its own
     * stage of the read, so none groups naturally with another.
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
     * The evidence of a count: how many entries it counted, disclosed with the
     * filters and the scope and no entry. A denied or failed count counted
     * none.
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
     * The evidence of an export: its format, how many lines it wrote and the
     * digest of its file, with the export's manifest, which an export that
     * succeeded or was denied must have. A failed export published nothing: it
     * wrote no line, has no file digest, and is disclosed with the filters and
     * the scope and no entry.
     *
     * Its parameters are the parts of the export's evidence, each from its own
     * stage of the export, so none groups naturally with another.
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
     * The evidence of the verification of an export: the export entry, when it
     * was found, by its id, and disclosed by its id and HMAC; the findings, in
     * the order the chain found them; and the verdict, `verified` when there
     * are none. A denied or failed verification discloses no entry.
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
            'verdict'      => $findings === [] ? self::VERIFIED : self::NOT_VERIFIED,
            'findings'     => $findings,
            'outcome'      => $outcome->value,
        ], self::disclosure($terms, $members));
    }

    /**
     * The evidence of an export whose file could not be published: the id of
     * the entry that journalled it, and no artifact.
     *
     * @param  string  $exportEntryId
     * @return self
     */
    public static function forPublishFailure(string $exportEntryId): self
    {
        return new self(['export_entry' => $exportEntryId, 'outcome' => Outcome::FAILURE->value], null);
    }

    /**
     * Refuse the record unless it keeps the evidence exactly: its properties,
     * less the package's metadata, encode canonically to the very bytes of the
     * evidence's, and its metadata is exactly the descriptor of the evidence's
     * manifest, or absent without one.
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
     * The properties every read of the trail names first, in order: its
     * purpose, the keyed fingerprints of its filters and of its scope, `null`
     * when none was answered, the id of the key that keyed them, and the
     * policy's name, refused beyond its limit.
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
     * Where a page started, as its record shows it: `first` without a cursor,
     * `cursor` when its cursor gave no position, the position under a scope of
     * exactly one tenant, and `next` under any other.
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
     * The disclosure of a read: its normalised filters, its scope or `null`,
     * the entries it showed, and the position a page read after, or `null`.
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
     * Whether the two values have the same canonical encoding; a value with
     * none is never alike.
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
