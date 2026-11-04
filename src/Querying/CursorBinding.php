<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Querying;

use SineMacula\Laravel\AuditLog\Access\AccessScope;
use SineMacula\Laravel\AuditLog\Access\Enums\ReadPurpose;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;

/**
 * What a page cursor is bound to: the version of the cursor, the log it walks,
 * as the storage connection's name and the entries table, the viewer's
 * reference, the purpose of the read, the order, the normalised filters, the
 * fingerprint of the scope the policy answered, and the page size.
 *
 * A cursor's MAC is computed over the canonical encoding of all of these, with
 * the id of the key that signs it and the payload part exactly as it was sent,
 * so a cursor opens only for the read it was issued for, and nothing of its
 * payload is decoded to check it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CursorBinding
{
    /** @var int The version of the cursor the binding is for. */
    private const int VERSION = 1;

    /** @var string The order every page of the trail walks: newest occurrence first, then the highest id. */
    private const string ORDER = 'occurred_at_desc';

    /**
     * Constructor.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  array{0: string, 1: string}  $viewer
     * @param  string  $purpose
     * @param  array{actor: ?array{0: string, 1: string}, categories: list<string>, correlation_id: ?string, event_prefix: ?string, events: list<string>, from: ?string, outcomes: list<string>, principal: ?array{0: string, 1: string}, subject: ?array{0: string, 1: string}, tenant: ?array{0: string, 1: string}, to: ?string}  $filters
     * @param  string  $scope
     * @param  int  $perPage
     * @param  array{0: string, 1: string}  $log
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function __construct(

        /** The viewer's reference, as its type and id. */
        #[\SensitiveParameter]
        private array $viewer,

        /** The purpose of the read, as stored. */
        private string $purpose,

        /** The read's normalised filters. */
        private array $filters,

        /** The fingerprint of the scope the policy answered. */
        private string $scope,

        /** How many entries a page holds. */
        private int $perPage,

        /** The log the cursor walks: the storage connection's name and the entries table. */
        private array $log,
    ) {}

    /**
     * The binding of a read of the trail: its viewer, purpose, filters, the
     * scope the policy answered, its page size, and the storage connection's
     * resolved name and the entries table it reads.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\Viewer  $viewer
     * @param  \SineMacula\Laravel\AuditLog\Access\Enums\ReadPurpose  $purpose
     * @param  \SineMacula\Laravel\AuditLog\Querying\TrailFilters  $filters
     * @param  \SineMacula\Laravel\AuditLog\Access\AccessScope  $scope
     * @param  int  $perPage
     * @param  string  $connection
     * @param  string  $table
     * @return self
     *
     * @throws \UnexpectedValueException
     */
    public static function for(
        #[\SensitiveParameter]
        Viewer $viewer,
        ReadPurpose $purpose,
        TrailFilters $filters,
        AccessScope $scope,
        int $perPage,
        string $connection,
        string $table,
    ): self {
        return new self(
            [$viewer->reference->type, $viewer->reference->id],
            $purpose->value,
            $filters->normalised(),
            $scope->fingerprint(),
            $perPage,
            [$connection, $table],
        );
    }

    /**
     * The canonical input of a cursor's MAC under the key with the id, over the
     * payload part exactly as it was sent, which is never decoded here.
     *
     * @param  string  $keyId
     * @param  string  $payload
     * @return string
     *
     * @throws \UnexpectedValueException
     */
    public function macInput(string $keyId, #[\SensitiveParameter] string $payload): string
    {
        return CanonicalEncoder::encode([
            'filters'  => $this->filters,
            'k'        => $keyId,
            'log'      => $this->log,
            'order'    => self::ORDER,
            'payload'  => $payload,
            'per_page' => $this->perPage,
            'purpose'  => $this->purpose,
            'scope'    => $this->scope,
            'v'        => self::VERSION,
            'viewer'   => $this->viewer,
        ]);
    }
}
