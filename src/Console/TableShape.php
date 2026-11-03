<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Console;

/**
 * The shape a shipped migration gives one of the package's tables, as the
 * schema checks of `audit-log:check` compare a table against it: the table's
 * label in a problem, each column the package writes with its type family, its
 * length or precision and its nullability, each index the migration creates by
 * its name's suffix, the primary key's columns, and the sentence that describes
 * a column the package does not write.
 *
 * There is one shape for each of six tables: the entries, the outbox, the
 * deliveries, the checkpoints, the checkpoint members and the integrity state.
 * Each is built by its named constructor, and none can be built otherwise.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class TableShape
{
    /** @var array<string, array{0: string, 1: ?int, 2: bool}> Each entries column the package writes, in order, with its type family, length or precision, and nullability. */
    private const array ENTRIES_COLUMNS = [
        'id'                => ['uuid', 36, false],
        'record_version'    => ['smallint', null, false],
        'event'             => ['string', 191, false],
        'event_version'     => ['smallint', null, false],
        'category'          => ['string', 64, false],
        'outcome'           => ['string', 16, false],
        'reason'            => ['string', 64, true],
        'actor_type'        => ['string', 191, true],
        'actor_id'          => ['string', 191, true],
        'subject_type'      => ['string', 191, true],
        'subject_id'        => ['string', 191, true],
        'principal_type'    => ['string', 191, true],
        'principal_id'      => ['string', 191, true],
        'tenant_type'       => ['string', 191, true],
        'tenant_id'         => ['string', 191, true],
        'credential_id'     => ['string', 191, true],
        'guard'             => ['string', 64, true],
        'session_id'        => ['string', 191, true],
        'request_id'        => ['string', 64, true],
        'trace_id'          => ['string', 32, true],
        'correlation_id'    => ['string', 191, true],
        'origin'            => ['string', 16, true],
        'provenance'        => ['string', 16, false],
        'source_id'         => ['string', 64, false],
        'source_region'     => ['string', 32, true],
        'source_record_id'  => ['string', 191, true],
        'import_batch_id'   => ['uuid', 36, true],
        'ip'                => ['string', 255, true],
        'user_agent'        => ['string', 512, true],
        'context'           => ['json', null, true],
        'properties'        => ['json', null, true],
        'occurred_at'       => ['datetime', 6, false],
        'recorded_at'       => ['datetime', 6, false],
        'integrity_version' => ['smallint', null, false],
        'key_id'            => ['string', 32, false],
        'hmac'              => ['string', 64, false],
    ];

    /** @var array<string, array{0: non-empty-list<string>, 1: bool}> Each index the entries migration creates, by its name's suffix, with its columns and uniqueness. */
    private const array ENTRIES_INDEXES = [
        '_actor_index'     => [['actor_type', 'actor_id', 'occurred_at'], false],
        '_subject_index'   => [['subject_type', 'subject_id', 'occurred_at'], false],
        '_principal_index' => [['principal_type', 'principal_id', 'occurred_at'], false],
        '_tenant_index'    => [['tenant_type', 'tenant_id', 'occurred_at'], false],
        '_event_index'     => [['event', 'occurred_at'], false],
        '_category_index'  => [['category', 'occurred_at'], false],
        '_correlate_index' => [['correlation_id'], false],
        '_occurred_index'  => [['occurred_at'], false],
        '_recorded_index'  => [['recorded_at', 'id'], false],
        '_source_unique'   => [['source_id', 'source_record_id'], true],
    ];

    /** @var array<string, array{0: string, 1: ?int, 2: bool}> Each outbox column the package writes, in order, with its type family, length or precision, and nullability. */
    private const array OUTBOX_COLUMNS = [
        'id'               => ['uuid', 36, false],
        'payload'          => ['longtext', null, false],
        'attempts'         => ['integer', null, false],
        'available_at'     => ['datetime', 6, false],
        'claimed_until'    => ['datetime', 6, true],
        'claimed_by'       => ['string', 64, true],
        'failed_at'        => ['datetime', 6, true],
        'last_error_class' => ['string', 191, true],
        'created_at'       => ['datetime', 6, false],
    ];

    /** @var array<string, array{0: string, 1: ?int, 2: bool}> Each deliveries column the package writes, in order, with its type family, length or precision, and nullability. */
    private const array DELIVERIES_COLUMNS = [
        'entry_id'           => ['uuid', 36, false],
        'destination'        => ['string', 64, false],
        'attempts'           => ['integer', null, false],
        'first_attempted_at' => ['datetime', 6, false],
        'delivered_at'       => ['datetime', 6, true],
        'last_error_class'   => ['string', 191, true],
    ];

    /** @var array<string, array{0: string, 1: ?int, 2: bool}> Each checkpoints column the package writes, in order, with its type family, length or precision, and nullability. */
    private const array CHECKPOINTS_COLUMNS = [
        'id'                 => ['uuid', 36, false],
        'sequence'           => ['bigint', null, false],
        'log_id'             => ['string', 64, false],
        'previous_id'        => ['uuid', 36, true],
        'previous_digest'    => ['string', 64, true],
        'member_count'       => ['integer', null, false],
        'members_digest'     => ['string', 64, false],
        'seal_digest'        => ['string', 64, false],
        'first_recorded_at'  => ['datetime', 6, false],
        'last_recorded_at'   => ['datetime', 6, false],
        'sealed_at'          => ['datetime', 6, false],
        'signer'             => ['string', 16, false],
        'key_id'             => ['string', 32, false],
        'algorithm_version'  => ['smallint', null, false],
        'signature'          => ['string', 64, false],
        'anchor'             => ['string', 64, true],
        'anchor_receipt'     => ['json', null, true],
        'anchored_at'        => ['datetime', 6, true],
        'anchor_error_class' => ['string', 191, true],
    ];

    /** @var array<string, array{0: non-empty-list<string>, 1: bool}> Each index the checkpoints migration creates, by its name's suffix, with its columns and uniqueness. */
    private const array CHECKPOINTS_INDEXES = [
        '_sequence_unique' => [['sequence'], true],
        '_anchored_index'  => [['anchored_at', 'sequence'], false],
    ];

    /** @var array<string, array{0: string, 1: ?int, 2: bool}> Each checkpoint members column the package writes, in order, with its type family, length or precision, and nullability. */
    private const array MEMBERS_COLUMNS = [
        'checkpoint_id' => ['uuid', 36, false],
        'entry_id'      => ['uuid', 36, false],
        'hmac'          => ['string', 64, false],
    ];

    /** @var array<string, array{0: string, 1: ?int, 2: bool}> Each integrity state column the package writes, in order, with its type family, length or precision, and nullability. */
    private const array STATE_COLUMNS = [
        'name'       => ['string', 64, false],
        'value'      => ['text', null, false],
        'updated_at' => ['datetime', 6, false],
    ];

    /** @var string How a column of an entries table the package does not write is described. */
    private const string UNKNOWN_ENTRIES_COLUMN = 'Column `%s` is not one the package writes, so no entry\'s HMAC covers it.';

    /** @var string How a column of a checkpoints or checkpoint members table the package does not write is described. */
    private const string UNKNOWN_SEAL_COLUMN = 'Column `%s` is not one the package writes, so no seal covers it.';

    /** @var string How a column of an outbox, deliveries or integrity state table the package does not write is described. */
    private const string UNKNOWN_DELIVERY_COLUMN = 'Column `%s` is not one the package writes.';

    /**
     * Constructor.
     *
     * @param  string  $label
     * @param  array<string, array{0: string, 1: ?int, 2: bool}>  $columns
     * @param  array<string, array{0: non-empty-list<string>, 1: bool}>  $indexes
     * @param  non-empty-list<string>  $primary
     * @param  string  $unknownColumn
     */
    private function __construct(

        /** What the table is called in a problem: `entries`, `outbox`, `deliveries`, `checkpoints`, `checkpoint members` or `integrity state`. */
        public string $label,

        /** Each column the package writes, in order, with its type family, its length or precision, and its nullability. */
        public array $columns,

        /** Each index the migration creates, by its name's suffix, with its columns in order and its uniqueness. */
        public array $indexes,

        /** The primary key's columns, in order. */
        public array $primary,

        /** The sentence describing a column the package does not write, with `%s` for its name. */
        public string $unknownColumn,
    ) {}

    /**
     * The shape the shipped migration gives the entries table.
     *
     * @return self
     */
    public static function entries(): self
    {
        return new self('entries', self::ENTRIES_COLUMNS, self::ENTRIES_INDEXES, ['id'], self::UNKNOWN_ENTRIES_COLUMN);
    }

    /**
     * The shape the shipped migration gives the outbox table: its rows are
     * claimed by an index over the failure time and the time a row falls due.
     *
     * @return self
     */
    public static function outbox(): self
    {
        return new self('outbox', self::OUTBOX_COLUMNS, ['_due_index' => [['failed_at', 'available_at'], false]], ['id'], self::UNKNOWN_DELIVERY_COLUMN);
    }

    /**
     * The shape the shipped migration gives the deliveries table: one receipt
     * for each entry and destination, which is its key, and no other index.
     *
     * @return self
     */
    public static function deliveries(): self
    {
        return new self('deliveries', self::DELIVERIES_COLUMNS, [], ['entry_id', 'destination'], self::UNKNOWN_DELIVERY_COLUMN);
    }

    /**
     * The shape the shipped migration gives the checkpoints table: one seal per
     * sequence, and the seals not yet anchored found in order.
     *
     * @return self
     */
    public static function checkpoints(): self
    {
        return new self('checkpoints', self::CHECKPOINTS_COLUMNS, self::CHECKPOINTS_INDEXES, ['id'], self::UNKNOWN_SEAL_COLUMN);
    }

    /**
     * The shape the shipped migration gives the checkpoint members table: keyed
     * by the seal and the entry, and an entry held by at most one seal.
     *
     * @return self
     */
    public static function members(): self
    {
        return new self('checkpoint members', self::MEMBERS_COLUMNS, ['_entry_unique' => [['entry_id'], true]], ['checkpoint_id', 'entry_id'], self::UNKNOWN_SEAL_COLUMN);
    }

    /**
     * The shape the shipped migration gives the integrity state table: one
     * value for each name, which is its key, and no other index.
     *
     * @return self
     */
    public static function state(): self
    {
        return new self('integrity state', self::STATE_COLUMNS, [], ['name'], self::UNKNOWN_DELIVERY_COLUMN);
    }
}
