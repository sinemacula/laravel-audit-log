<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use Illuminate\Database\Connection;
use Illuminate\Database\Query\JoinClause;
use SineMacula\Laravel\AuditLog\Config\IntegerSetting;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Integrity\SealEnvelope;
use SineMacula\Laravel\AuditLog\Integrity\SealSettings;
use SineMacula\Laravel\AuditLog\Integrity\SealSigner;
use SineMacula\Laravel\AuditLog\Integrity\UnknownKeyException;

/**
 * The seals a prune walks, each authenticated with its membership before any
 * member is planned, so a forged seal gets no prune record.
 *
 * Every statement reads the writer, so a lagging replica never hides an entry
 * or a member.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PruneSeals
{
    /** @var list<string> The columns of a present member a plan and a hold read, each taken from the entry. */
    public const array PRESENT_COLUMNS = [
        'id', 'category', 'tenant_type', 'tenant_id', 'actor_type', 'actor_id', 'subject_type', 'subject_id', 'import_batch_id', 'occurred_at', 'event',
    ];

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealSigner  $signer
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealSettings  $settings
     */
    public function __construct(

        /** The signer a seal's signature is verified with. */
        private SealSigner $signer,

        /** The settings the log every seal must belong to is read from. */
        private SealSettings $settings,
    ) {}

    /**
     * The authenticated seal at the sequence, or `null` when there is none or
     * it fails authentication.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  int  $sequence
     * @return ?\SineMacula\Laravel\AuditLog\Lifecycle\PruneSeal
     *
     * @throws \InvalidArgumentException
     */
    public function load(Connection $connection, int $sequence): ?PruneSeal
    {
        $stored = $connection->table(IntegrityTables::checkpointsTable())->useWritePdo()->where('sequence', $sequence)->first();

        if ($stored === null) {
            return null;
        }

        $seal     = (array) $stored;
        $envelope = $this->authenticated($seal);

        if ($envelope === null) {
            return null;
        }

        $members = self::membersOf($connection, $envelope);

        return $members === null ? null : new PruneSeal($envelope, $envelope->digest(), $members);
    }

    /**
     * The seal's members still present, with the columns a plan and a hold
     * read, sorted bytewise by id.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\PruneSeal  $seal
     * @return list<array<string, scalar|null>>
     *
     * @throws \InvalidArgumentException
     */
    public function present(Connection $connection, PruneSeal $seal): array
    {
        $rows = $connection->table(IntegrityTables::membersTable() . ' as m')
            ->join(EntrySettings::table() . ' as e', static function (JoinClause $join): void {
                $join->on('e.id', '=', 'm.entry_id');
            })
            ->where('m.checkpoint_id', $seal->envelope->id)
            ->useWritePdo()
            ->get(array_map(static fn (string $column): string => 'e.' . $column, self::PRESENT_COLUMNS))
            ->all();

        /** @var list<array<string, scalar|null>> $present */
        $present = array_map(static fn (#[\SensitiveParameter] \stdClass $row): array => (array) $row, $rows);

        usort($present, static fn (array $left, array $right): int => strcmp((string) $left['id'], (string) $right['id']));

        return $present;
    }

    /**
     * The stored seal's envelope, or `null` when its own row fails
     * authentication.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $seal
     * @return ?\SineMacula\Laravel\AuditLog\Integrity\SealEnvelope
     *
     * @throws \InvalidArgumentException
     */
    private function authenticated(array $seal): ?SealEnvelope
    {
        $version   = IntegerSetting::parse($seal['algorithm_version'] ?? null);
        $signature = $seal['signature'] ?? null;

        if (!in_array($version, SealEnvelope::SUPPORTED_ALGORITHM_VERSIONS, true) || ($seal['signer'] ?? null) !== SealEnvelope::SIGNER || !is_string($signature)) {
            return null;
        }

        try {
            $envelope = SealEnvelope::fromRow($seal);
            $verified = $envelope->logId          === $this->settings->logId()
                && ($seal['seal_digest'] ?? null) === $envelope->digest()
                && $this->signer->verifies($envelope, $signature);
        } catch (\UnexpectedValueException|UnknownKeyException) {
            return null;
        }

        return $verified ? $envelope : null;
    }

    /**
     * Each member's HMAC by entry id, or `null` unless they match the seal's
     * count and members digest.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealEnvelope  $seal
     * @return ?array<string, string>
     *
     * @throws \InvalidArgumentException
     */
    private static function membersOf(Connection $connection, SealEnvelope $seal): ?array
    {
        $rows = $connection->table(IntegrityTables::membersTable())
            ->useWritePdo()
            ->where('checkpoint_id', $seal->id)
            ->get(['entry_id', 'hmac'])
            ->all();

        $pairs = [];

        foreach ($rows as $row) {
            if (!is_string($row->entry_id ?? null) || !is_string($row->hmac ?? null)) {
                return null;
            }

            $pairs[] = [$row->entry_id, $row->hmac];
        }

        try {
            $authentic = count($pairs) === $seal->memberCount && SealEnvelope::membersDigest($pairs) === $seal->membersDigest;
        } catch (\InvalidArgumentException) {
            return null;
        }

        return $authentic ? array_column($pairs, 1, 0) : null;
    }
}
