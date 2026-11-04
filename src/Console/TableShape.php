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
 * There is one shape for each of fourteen tables: the entries, the artifacts,
 * the outbox, the deliveries, the checkpoints, the checkpoint members, the
 * integrity state, the lifecycle journal, the holds, the lifecycle lock, the
 * import batches, the subject keys, the owner erasures and the key uses. Each
 * is built by its named constructor, and none can be built otherwise.
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
        'source_digest'     => ['string', 64, true],
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
        '_actor_index'     => [['actor_type', 'actor_id', 'occurred_at', 'id'], false],
        '_subject_index'   => [['subject_type', 'subject_id', 'occurred_at', 'id'], false],
        '_principal_index' => [['principal_type', 'principal_id', 'occurred_at', 'id'], false],
        '_tenant_index'    => [['tenant_type', 'tenant_id', 'occurred_at', 'id'], false],
        '_event_index'     => [['event', 'occurred_at', 'id'], false],
        '_category_index'  => [['category', 'occurred_at', 'id'], false],
        '_correlate_index' => [['correlation_id'], false],
        '_occurred_index'  => [['occurred_at', 'id'], false],
        '_recorded_index'  => [['recorded_at', 'id'], false],
        '_source_unique'   => [['source_id', 'source_record_id'], true],
    ];

    /** @var array<string, array{0: string, 1: ?int, 2: bool}> Each artifacts column the package writes, in order, with its type family, length or precision, and nullability. */
    private const array ARTIFACTS_COLUMNS = [
        'id'           => ['uuid', 36, false],
        'entry_id'     => ['uuid', 36, false],
        'kind'         => ['string', 16, false],
        'member_count' => ['integer', null, false],
        'digest'       => ['string', 64, false],
        'members'      => ['longtext', null, false],
        'created_at'   => ['datetime', 6, false],
    ];

    /** @var array<string, array{0: non-empty-list<string>, 1: bool}> Each index the artifacts migration creates, by its name's suffix, with its columns and uniqueness. */
    private const array ARTIFACTS_INDEXES = [
        '_entry_unique' => [['entry_id'], true],
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
        'journal_sequence'   => ['bigint', null, true],
        'journal_head'       => ['string', 64, true],
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
        '_journal_index'   => [['journal_sequence'], false],
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

    /** @var array<string, array{0: string, 1: ?int, 2: bool}> Each lifecycle journal column the package writes, in order, with its type family, length or precision, and nullability. */
    private const array JOURNAL_COLUMNS = [
        'id'                 => ['uuid', 36, false],
        'sequence'           => ['bigint', null, false],
        'log_id'             => ['string', 64, false],
        'kind'               => ['string', 32, false],
        'operation_id'       => ['uuid', 36, false],
        'occurred_at'        => ['datetime', 6, false],
        'authority_type'     => ['string', 191, true],
        'authority_id'       => ['string', 191, true],
        'reason'             => ['string', 64, true],
        'external_reference' => ['string', 191, true],
        'seal_id'            => ['uuid', 36, true],
        'hold_id'            => ['uuid', 36, true],
        'payload'            => ['longtext', null, false],
        'payload_digest'     => ['string', 64, false],
        'previous_hmac'      => ['string', 64, true],
        'key_id'             => ['string', 32, false],
        'hmac'               => ['string', 64, false],
    ];

    /** @var array<string, array{0: non-empty-list<string>, 1: bool}> Each index the lifecycle journal migration creates, by its name's suffix, with its columns and uniqueness. */
    private const array JOURNAL_INDEXES = [
        '_sequence_unique' => [['sequence'], true],
        '_seal_index'      => [['seal_id'], false],
        '_hold_index'      => [['hold_id'], false],
        '_kind_index'      => [['kind', 'occurred_at'], false],
    ];

    /** @var array<string, array{0: string, 1: ?int, 2: bool}> Each holds column the package writes, in order, with its type family, length or precision, and nullability. */
    private const array HOLDS_COLUMNS = [
        'hold_id'            => ['uuid', 36, false],
        'scope'              => ['longtext', null, false],
        'scope_digest'       => ['string', 64, false],
        'basis'              => ['string', 32, false],
        'import_batch_id'    => ['uuid', 36, true],
        'placed_at'          => ['datetime', 6, false],
        'review_by'          => ['datetime', 6, true],
        'authority_type'     => ['string', 191, false],
        'authority_id'       => ['string', 191, false],
        'reason'             => ['string', 64, false],
        'external_reference' => ['string', 191, true],
        'operation_id'       => ['uuid', 36, false],
        'journal_sequence'   => ['bigint', null, false],
    ];

    /** @var array<string, array{0: non-empty-list<string>, 1: bool}> Each index the holds migration creates, by its name's suffix, with its columns and uniqueness. */
    private const array HOLDS_INDEXES = [
        '_review_index' => [['review_by'], false],
        '_batch_index'  => [['import_batch_id'], false],
    ];

    /** @var array<string, array{0: string, 1: ?int, 2: bool}> Each lifecycle lock column the package writes, in order, with its type family, length or precision, and nullability. */
    private const array LOCK_COLUMNS = [
        'id'        => ['smallint', null, false],
        'token'     => ['string', 64, true],
        'locked_at' => ['datetime', 6, true],
    ];

    /** @var array<string, array{0: string, 1: ?int, 2: bool}> Each import batches column the package writes, in order, with its type family, length or precision, and nullability. */
    private const array IMPORT_BATCHES_COLUMNS = [
        'id'                  => ['uuid', 36, false],
        'source_id'           => ['string', 64, false],
        'source_region'       => ['string', 32, true],
        'input_format'        => ['string', 32, false],
        'importer_type'       => ['string', 191, false],
        'importer_id'         => ['string', 191, false],
        'reason'              => ['string', 64, false],
        'external_reference'  => ['string', 191, true],
        'file_sha256'         => ['string', 64, false],
        'externally_verified' => ['boolean', null, false],
        'hold_id'             => ['uuid', 36, true],
        'status'              => ['string', 16, false],
        'lines_read'          => ['integer', null, false],
        'imported'            => ['integer', null, false],
        'duplicates'          => ['integer', null, false],
        'conflicts'           => ['integer', null, false],
        'rejected'            => ['integer', null, false],
        'conflict_ids'        => ['text', null, true],
        'started_at'          => ['datetime', 6, false],
        'updated_at'          => ['datetime', 6, false],
        'finished_at'         => ['datetime', 6, true],
    ];

    /** @var array<string, array{0: string, 1: ?int, 2: bool}> Each subject keys column the package writes, in order, with its type family, length or precision, and nullability. */
    private const array SUBJECT_KEYS_COLUMNS = [
        'id'          => ['uuid', 36, false],
        'owner_type'  => ['string', 191, false],
        'owner_id'    => ['string', 191, false],
        'tenant_type' => ['string', 191, true],
        'tenant_id'   => ['string', 191, true],
        'category'    => ['string', 64, false],
        'unit'        => ['string', 64, false],
        'generation'  => ['integer', null, false],
        'state'       => ['string', 16, false],
        'wrapped_key' => ['text', null, true],
        'wrap_key_id' => ['string', 191, true],
        'created_at'  => ['datetime', 6, false],
        'erasure_id'  => ['uuid', 36, true],
        'key_id'      => ['string', 32, false],
        'hmac'        => ['string', 64, false],
    ];

    /** @var array<string, array{0: non-empty-list<string>, 1: bool}> Each index the subject keys migration creates, by its name's suffix, with its columns and uniqueness. */
    private const array SUBJECT_KEYS_INDEXES = [
        '_unit_unique'   => [['unit', 'generation'], true],
        '_owner_index'   => [['owner_type', 'owner_id'], false],
        '_erasure_index' => [['erasure_id'], false],
    ];

    /** @var array<string, array{0: string, 1: ?int, 2: bool}> Each owner erasures column the package writes, in order, with its type family, length or precision, and nullability. */
    private const array OWNER_ERASURES_COLUMNS = [
        'id'               => ['uuid', 36, false],
        'owner_type'       => ['string', 191, false],
        'owner_id'         => ['string', 191, false],
        'transition'       => ['string', 16, false],
        'generation_floor' => ['integer', null, false],
        'journal_sequence' => ['bigint', null, false],
        'created_at'       => ['datetime', 6, false],
    ];

    /** @var array<string, array{0: non-empty-list<string>, 1: bool}> Each index the owner erasures migration creates, by its name's suffix, with its columns and uniqueness. */
    private const array OWNER_ERASURES_INDEXES = [
        '_owner_index' => [['owner_type', 'owner_id', 'journal_sequence'], false],
    ];

    /** @var array<string, array{0: string, 1: ?int, 2: bool}> Each key uses column the package writes, in order, with its type family, length or precision, and nullability. */
    private const array KEY_USES_COLUMNS = [
        'key_id'   => ['uuid', 36, false],
        'entry_id' => ['uuid', 36, false],
    ];

    /** @var string How a column of an entries table the package does not write is described. */
    private const string UNKNOWN_ENTRIES_COLUMN = 'Column `%s` is not one the package writes, so no entry\'s HMAC covers it.';

    /** @var string How a column of a checkpoints or checkpoint members table the package does not write is described. */
    private const string UNKNOWN_SEAL_COLUMN = 'Column `%s` is not one the package writes, so no seal covers it.';

    /** @var string How a column of any other table the package does not write is described. */
    private const string UNKNOWN_DELIVERY_COLUMN = 'Column `%s` is not one the package writes.';

    /** @var string How a column of a lifecycle journal table the package does not write is described. */
    private const string UNKNOWN_JOURNAL_COLUMN = 'Column `%s` is not one the package writes, so no journal row\'s HMAC covers it.';

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

        /** What the table is called in a problem: `entries`, `artifacts`, `outbox`, `deliveries`, `checkpoints`, `checkpoint members`, `integrity state`, `lifecycle journal`, `holds`, `lifecycle lock`, `import batches`, `subject keys`, `owner erasures` or `key uses`. */
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
     * The shape the shipped migration gives the artifacts table: keyed by the
     * artifact's id, and an entry with at most one artifact.
     *
     * @return self
     */
    public static function artifacts(): self
    {
        return new self('artifacts', self::ARTIFACTS_COLUMNS, self::ARTIFACTS_INDEXES, ['id'], self::UNKNOWN_DELIVERY_COLUMN);
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

    /**
     * The shape the shipped migration gives the lifecycle journal: keyed by the
     * row's id, one row per sequence, and its rows found by seal, by hold and
     * by kind.
     *
     * @return self
     */
    public static function journal(): self
    {
        return new self('lifecycle journal', self::JOURNAL_COLUMNS, self::JOURNAL_INDEXES, ['id'], self::UNKNOWN_JOURNAL_COLUMN);
    }

    /**
     * The shape the shipped migration gives the holds table: keyed by the
     * hold's id, and its holds found by review date and by import batch.
     *
     * @return self
     */
    public static function holds(): self
    {
        return new self('holds', self::HOLDS_COLUMNS, self::HOLDS_INDEXES, ['hold_id'], self::UNKNOWN_DELIVERY_COLUMN);
    }

    /**
     * The shape the shipped migration gives the lifecycle lock table: keyed by
     * its one row's id, and no other index.
     *
     * @return self
     */
    public static function lock(): self
    {
        return new self('lifecycle lock', self::LOCK_COLUMNS, [], ['id'], self::UNKNOWN_DELIVERY_COLUMN);
    }

    /**
     * The shape the shipped migration gives the import batches table: keyed by
     * the batch's id, and its batches found by status and by when each was last
     * written.
     *
     * @return self
     */
    public static function importBatches(): self
    {
        return new self('import batches', self::IMPORT_BATCHES_COLUMNS, ['_status_index' => [['status', 'updated_at'], false]], ['id'], self::UNKNOWN_DELIVERY_COLUMN);
    }

    /**
     * The shape the shipped migration gives the subject keys table: keyed by
     * the key's id, one key per unit and generation, and its keys found by
     * owner and by the erasure that destroyed them.
     *
     * @return self
     */
    public static function subjectKeys(): self
    {
        return new self('subject keys', self::SUBJECT_KEYS_COLUMNS, self::SUBJECT_KEYS_INDEXES, ['id'], self::UNKNOWN_DELIVERY_COLUMN);
    }

    /**
     * The shape the shipped migration gives the owner erasures table: keyed by
     * its journal row's id, and an owner's markers found in journal order.
     *
     * @return self
     */
    public static function ownerErasures(): self
    {
        return new self('owner erasures', self::OWNER_ERASURES_COLUMNS, self::OWNER_ERASURES_INDEXES, ['id'], self::UNKNOWN_DELIVERY_COLUMN);
    }

    /**
     * The shape the shipped migration gives the key uses table: keyed by the
     * key and the entry, and an entry's keys found by the entry alone.
     *
     * @return self
     */
    public static function keyUses(): self
    {
        return new self('key uses', self::KEY_USES_COLUMNS, ['_entry_index' => [['entry_id'], false]], ['key_id', 'entry_id'], self::UNKNOWN_DELIVERY_COLUMN);
    }
}
