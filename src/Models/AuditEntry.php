<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Models;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\AuditLog\Casts\UtcInstant;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;

/**
 * A stored audit entry, read through Eloquent and never written through it.
 *
 * Every model write is refused with `ImmutableEntryException` before any event
 * or statement. Builder writes bypass the model, so append-only is enforced by
 * the database's grants, and pruning deletes through the builder, never through
 * the model. Reading the model directly bypasses the trail's access policy and
 * read records.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
 *
 * @property string $id
 * @property int $record_version
 * @property string $event
 * @property int $event_version
 * @property string $category
 * @property string $outcome
 * @property ?string $reason
 * @property ?string $actor_type
 * @property ?string $actor_id
 * @property ?string $subject_type
 * @property ?string $subject_id
 * @property ?string $principal_type
 * @property ?string $principal_id
 * @property ?string $tenant_type
 * @property ?string $tenant_id
 * @property ?string $credential_id
 * @property ?string $guard
 * @property ?string $session_id
 * @property ?string $request_id
 * @property ?string $trace_id
 * @property ?string $correlation_id
 * @property ?string $origin
 * @property string $provenance
 * @property string $source_id
 * @property ?string $source_region
 * @property ?string $source_record_id
 * @property ?string $import_batch_id
 * @property ?string $source_digest
 * @property ?string $ip
 * @property ?string $user_agent
 * @property ?array<array-key, mixed> $context
 * @property ?array<array-key, mixed> $properties
 * @property \Carbon\CarbonImmutable $occurred_at
 * @property \Carbon\CarbonImmutable $recorded_at
 * @property int $integrity_version
 * @property string $key_id
 * @property string $hmac
 */
final class AuditEntry extends Model
{
    /** @var bool Whether the primary key auto-increments. */
    public $incrementing = false;

    /** @var bool Whether the entry has created and updated times: it has neither. */
    public $timestamps = false;

    /** @var string The type of the primary key. */
    protected $keyType = 'string';

    /** @var list<string> The attributes that are mass assignable: none, entries are written by the store. */
    protected $fillable = [];

    /**
     * Create an entry on the storage connection, in the configured table, both
     * set before Eloquent reads them.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, mixed>  $attributes
     *
     * @throws \InvalidArgumentException
     *
     * @phpstan-ignore sineMaculaLaravel.modelBehaviour
     */
    public function __construct(array $attributes = [])
    {
        $this->setTable(EntrySettings::table());
        $this->setConnection(StorageConnection::name());

        parent::__construct($attributes);
    }

    /**
     * Refuse to save the entry.
     *
     * @param  array<array-key, mixed>  $options
     * @return never
     *
     * @throws \SineMacula\Laravel\AuditLog\Models\ImmutableEntryException
     *
     * @phpstan-ignore sineMaculaLaravel.modelBehaviour (refused, not behaviour: an entry is evidence)
     */
    #[\Override]
    public function save(array $options = []): never
    {
        $this->refuse(__FUNCTION__);
    }

    /**
     * Refuse to save the entry without events.
     *
     * @param  array<array-key, mixed>  $options
     * @return never
     *
     * @throws \SineMacula\Laravel\AuditLog\Models\ImmutableEntryException
     *
     * @phpstan-ignore sineMaculaLaravel.modelBehaviour (refused, not behaviour: an entry is evidence)
     */
    #[\Override]
    public function saveQuietly(array $options = []): never
    {
        $this->refuse(__FUNCTION__);
    }

    /**
     * Refuse to insert the entry while ignoring a unique conflict, which would
     * otherwise insert it without calling `save()`. Laravel 12's model has no
     * such method, where `#[\Override]` would stop the class loading.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $options
     * @param  array<array-key, mixed>|string|null  $uniqueBy
     * @return never
     *
     * @throws \SineMacula\Laravel\AuditLog\Models\ImmutableEntryException
     *
     * @phpstan-ignore sineMaculaLaravel.modelBehaviour, method.missingOverride (refused, not behaviour: an entry is evidence; Laravel 12 has no parent method)
     */
    public function saveOrIgnore(array $options = [], array|string|null $uniqueBy = null): never
    {
        $this->refuse(__FUNCTION__);
    }

    /**
     * Refuse to update the entry, before any attribute is filled.
     *
     * @param  array<string, mixed>  $attributes
     * @param  array<array-key, mixed>  $options
     * @return never
     *
     * @throws \SineMacula\Laravel\AuditLog\Models\ImmutableEntryException
     *
     * @phpstan-ignore sineMaculaLaravel.modelBehaviour (refused, not behaviour: an entry is evidence)
     */
    #[\Override]
    public function update(array $attributes = [], array $options = []): never
    {
        $this->refuse(__FUNCTION__);
    }

    /**
     * Refuse to update the entry without events, before any attribute is
     * filled.
     *
     * @param  array<string, mixed>  $attributes
     * @param  array<array-key, mixed>  $options
     * @return never
     *
     * @throws \SineMacula\Laravel\AuditLog\Models\ImmutableEntryException
     *
     * @phpstan-ignore sineMaculaLaravel.modelBehaviour (refused, not behaviour: an entry is evidence)
     */
    #[\Override]
    public function updateQuietly(array $attributes = [], array $options = []): never
    {
        $this->refuse(__FUNCTION__);
    }

    /**
     * Refuse to save the entry and its relations.
     *
     * @return never
     *
     * @throws \SineMacula\Laravel\AuditLog\Models\ImmutableEntryException
     *
     * @phpstan-ignore sineMaculaLaravel.modelBehaviour (refused, not behaviour: an entry is evidence)
     */
    #[\Override]
    public function push(): never
    {
        $this->refuse(__FUNCTION__);
    }

    /**
     * Refuse to touch the entry.
     *
     * @param  array<array-key, mixed>|string|null  $attribute
     * @return never
     *
     * @throws \SineMacula\Laravel\AuditLog\Models\ImmutableEntryException
     *
     * @phpstan-ignore sineMaculaLaravel.modelBehaviour (refused, not behaviour: an entry is evidence)
     */
    #[\Override]
    public function touch(mixed $attribute = null): never
    {
        $this->refuse(__FUNCTION__);
    }

    /**
     * Refuse to delete the entry.
     *
     * @return never
     *
     * @throws \SineMacula\Laravel\AuditLog\Models\ImmutableEntryException
     *
     * @phpstan-ignore sineMaculaLaravel.modelBehaviour (refused, not behaviour: an entry is evidence)
     */
    #[\Override]
    public function delete(): never
    {
        $this->refuse(__FUNCTION__);
    }

    /**
     * Refuse to delete the entry without events.
     *
     * @return never
     *
     * @throws \SineMacula\Laravel\AuditLog\Models\ImmutableEntryException
     *
     * @phpstan-ignore sineMaculaLaravel.modelBehaviour (refused, not behaviour: an entry is evidence)
     */
    #[\Override]
    public function deleteQuietly(): never
    {
        $this->refuse(__FUNCTION__);
    }

    /**
     * Refuse to force the entry's deletion.
     *
     * @return never
     *
     * @throws \SineMacula\Laravel\AuditLog\Models\ImmutableEntryException
     *
     * @phpstan-ignore sineMaculaLaravel.modelBehaviour (refused, not behaviour: an entry is evidence)
     */
    #[\Override]
    public function forceDelete(): never
    {
        $this->refuse(__FUNCTION__);
    }

    /**
     * The attributes that should be cast: the versions as integers, the JSON
     * columns as arrays and the times as UTC instants.
     *
     * @return array<string, string>
     */
    #[\Override]
    protected function casts(): array
    {
        return [
            'record_version'    => 'integer',
            'event_version'     => 'integer',
            'context'           => 'array',
            'properties'        => 'array',
            'occurred_at'       => UtcInstant::class,
            'recorded_at'       => UtcInstant::class,
            'integrity_version' => 'integer',
        ];
    }

    /**
     * Refuse to increment or decrement a column, which bypasses `save()` and,
     * on an entry never stored, would update every row.
     *
     * @param  string  $column
     * @param  float|int  $amount
     * @param  array<array-key, mixed>  $extra
     * @param  string  $method
     * @return never
     *
     * @throws \SineMacula\Laravel\AuditLog\Models\ImmutableEntryException
     */
    #[\Override]
    protected function incrementOrDecrement(mixed $column, mixed $amount, mixed $extra, mixed $method): never
    {
        $this->refuse(__FUNCTION__);
    }

    /**
     * Refuse to increment or decrement several columns, which bypasses `save()`
     * and, on an entry never stored, would update every row. Laravel 12's model
     * has no such method, where `#[\Override]` would stop the class loading.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<string, float|int>  $columns
     * @param  array<string, mixed>  $extra
     * @param  string  $method
     * @return never
     *
     * @throws \SineMacula\Laravel\AuditLog\Models\ImmutableEntryException
     *
     * @phpstan-ignore method.missingOverride (Laravel 12 has no parent method)
     */
    protected function incrementOrDecrementEach(array $columns, array $extra, string $method): never
    {
        $this->refuse(__FUNCTION__);
    }

    /**
     * Refuse the write the named method would make.
     *
     * @param  string  $method
     * @return never
     *
     * @throws \SineMacula\Laravel\AuditLog\Models\ImmutableEntryException
     */
    private function refuse(string $method): never
    {
        throw ImmutableEntryException::refusing($method);
    }
}
