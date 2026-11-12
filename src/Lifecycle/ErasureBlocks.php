<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use Illuminate\Database\Connection;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow;
use SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Stores\RowCodec;
use SineMacula\Laravel\AuditLog\Support\StoredTime;

/**
 * Decides which of an owner's keys an erasure must keep, from the entries each
 * key encrypted.
 *
 * An entry is believed only once verified; one that fails blocks its key.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ErasureBlocks
{
    /** @var int The most key uses one page reads. */
    public const int PAGE = 1000;

    /** @var string The alias of a key use's entry id beside the entry's columns. */
    private const string USED_ENTRY = 'audit_log_used_entry_id';

    /** @var int Seconds in a UTC day. */
    private const int SECONDS_PER_DAY = 86400;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\RecordSigner  $signer
     * @param  \SineMacula\Laravel\AuditLog\Stores\RowCodec  $codec
     */
    public function __construct(

        /** Verifies every entry read. */
        private RecordSigner $signer,

        /** Decodes every entry read. */
        private RowCodec $codec,
    ) {}

    /**
     * The blocks of the keys and the number of entries the unblocked keys
     * encrypted.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  list<\SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow>  $keys
     * @param  list<\SineMacula\Laravel\AuditLog\Lifecycle\Hold>  $holds
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\RetentionDecisions  $retention
     * @return array{0: list<\SineMacula\Laravel\AuditLog\Lifecycle\ErasureBlock>, 1: int}
     *
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\RetentionConflictException
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    public function for(Connection $connection, #[\SensitiveParameter] array $keys, array $holds, RetentionDecisions $retention): array
    {
        $blocks   = [];
        $affected = 0;

        foreach ($keys as $key) {
            [$reasons, $entries] = $this->reasonsFor($connection, $key, $holds, self::preservedFrom($key, $retention));

            if ($reasons === []) {
                $affected += $entries;

                continue;
            }

            $blocks[] = new ErasureBlock($key->id, $key->unit, $key->generation, $reasons);
        }

        return [$blocks, $affected];
    }

    /**
     * Every reason the key is blocked and how many present entries it
     * encrypted.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow  $key
     * @param  list<\SineMacula\Laravel\AuditLog\Lifecycle\Hold>  $holds
     * @param  ?string  $preservedFrom
     * @return array{0: list<string>, 1: int}
     *
     * @throws \InvalidArgumentException
     */
    private function reasonsFor(Connection $connection, #[\SensitiveParameter] SubjectKeyRow $key, array $holds, ?string $preservedFrom): array
    {
        $reasons = [];
        $entries = 0;
        $after   = null;

        do {
            $page = self::page($connection, $key->id, $after);

            foreach ($page as $row) {
                $after = (string) $row[self::USED_ENTRY];

                if ($row['id'] === null) {
                    continue;
                }

                $entries++;
                $reasons += array_fill_keys($this->reasonsOf($row, $key, $holds, $preservedFrom), true);
            }
        } while (count($page) === self::PAGE);

        return [array_map(strval(...), array_keys($reasons)), $entries];
    }

    /**
     * Why the entry blocks the key: `unverified` alone when it does not
     * authenticate, else each matching hold and its preservation.
     *
     * @param  array<string, scalar|null>  $row
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow  $key
     * @param  list<\SineMacula\Laravel\AuditLog\Lifecycle\Hold>  $holds
     * @param  ?string  $preservedFrom
     * @return list<string>
     */
    private function reasonsOf(#[\SensitiveParameter] array $row, #[\SensitiveParameter] SubjectKeyRow $key, array $holds, ?string $preservedFrom): array
    {
        $decoded = $this->authentic($row);

        if ($decoded === null) {
            return [ErasureBlock::UNVERIFIED];
        }

        $reasons = [];

        foreach ($holds as $hold) {
            if (!$hold->scope->matches($row)) {
                continue;
            }

            $reasons[] = ErasureBlock::HELD . $hold->id;
        }

        $occurredAt = $decoded['occurred_at'] ?? null;

        if ($preservedFrom !== null && (!is_string($occurredAt) || strcmp($occurredAt, $preservedFrom) >= 0)) {
            $reasons[] = ErasureBlock::PRESERVED . $key->category;
        }

        return $reasons;
    }

    /**
     * The entry's row decoded, or `null` when it does not authenticate.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, scalar|null>  $row
     * @return ?array<string, mixed>
     */
    private function authentic(#[\SensitiveParameter] array $row): ?array
    {
        try {
            $decoded = $this->codec->decode($row);

            return $this->signer->verifies($decoded) ? $decoded : null;
        } catch (\UnexpectedValueException|UnknownKeyException) {
            // An entry that cannot be authenticated blocks its key
            return null;
        }
    }

    /**
     * The instant from which the key's entries are still preserved: `''` when
     * preserved forever and `null` when not preserved.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SubjectKeyRow  $key
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\RetentionDecisions  $retention
     * @return ?string
     *
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\RetentionConflictException
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    private static function preservedFrom(#[\SensitiveParameter] SubjectKeyRow $key, RetentionDecisions $retention): ?string
    {
        $tenant = $key->tenantType === null || $key->tenantId === null ? null : Reference::of($key->tenantType, $key->tenantId);
        $days   = $retention->for($key->category, $tenant)->preserveDays;

        if ($days === null) {
            return null;
        }

        if ($days === PHP_INT_MAX) {
            return '';
        }

        $midnight = StoredTime::instant(StoredTime::toStorage($retention->midnight()));

        return StoredTime::format($midnight->subSeconds($days * self::SECONDS_PER_DAY));
    }

    /**
     * A keyset page of the key's uses, each with its entry's full row, whose
     * columns are all `null` once the entry is pruned.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  string  $keyId
     * @param  ?string  $after
     * @return list<array<string, scalar|null>>
     *
     * @throws \InvalidArgumentException
     */
    private static function page(Connection $connection, string $keyId, ?string $after): array
    {
        $uses    = KeyTables::keyUsesTable();
        $entries = EntrySettings::table();
        $entry   = $uses . '.entry_id';

        $query = $connection->table($uses)
            ->useWritePdo()
            ->leftJoin($entries, $entries . '.id', '=', $entry)
            ->where($uses . '.key_id', $keyId)
            ->orderBy($entry)
            ->limit(self::PAGE)
            ->select([$entry . ' as ' . self::USED_ENTRY, $entries . '.*']);

        if ($after !== null) {
            $query->where($entry, '>', $after);
        }

        /** @var list<array<string, scalar|null>> */
        return array_values(array_map(static fn (object $stored): array => (array) $stored, $query->get()->all()));
    }
}
