<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Keys;

use Illuminate\Database\Connection;
use Illuminate\Database\Query\Builder;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * The owner markers, read through the writer so a replica lagging an erasure
 * never lets a key be created for an erased owner.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class OwnerMarkers
{
    /**
     * The owner's latest marker by journal sequence, or `null` when it has
     * none.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @return ?\SineMacula\Laravel\AuditLog\Keys\OwnerMarker
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    public function latest(Connection $connection, #[\SensitiveParameter] Reference $owner): ?OwnerMarker
    {
        $row = self::markers($connection)
            ->useWritePdo()
            ->where('owner_type', $owner->type)
            ->where('owner_id', $owner->id)
            ->orderByDesc('journal_sequence')
            ->first();

        return $row === null ? null : OwnerMarker::fromRow((array) $row);
    }

    /**
     * Insert the marker.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  \SineMacula\Laravel\AuditLog\Keys\OwnerMarker  $marker
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function insert(Connection $connection, #[\SensitiveParameter] OwnerMarker $marker): void
    {
        self::markers($connection)->insert($marker->toRow());
    }

    /**
     * The owner markers table on the connection.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return \Illuminate\Database\Query\Builder
     *
     * @throws \InvalidArgumentException
     */
    private static function markers(Connection $connection): Builder
    {
        return $connection->table(KeyTables::ownerErasuresTable());
    }
}
