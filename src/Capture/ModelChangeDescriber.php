<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Capture;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\AuditLog\Capture\Enums\ModelEvent;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * Describes a watched model's change on a capture's builder: its code, the
 * model as its subject, the watched fields' values, and delivery after the
 * model's own connection commits, so a change rolled back is never recorded.
 *
 * Before any value is read, every watched field is checked on the instance
 * itself: one it hides, or casts encrypted, is refused unless the watch gives
 * it an explicit handling, so a value the model keeps from view is never
 * recorded as read. Values are read raw, from the attributes, the changes and
 * the values before them, and never through an accessor, an appended attribute
 * or a cast.
 *
 * A creation keeps the watched fields as they were set, and an update the
 * watched fields it changed, each before and after, or nothing when it changed
 * none. An update that clears a soft-deleted model's deleted-at column is a
 * restore, which keeps the fields and the changes alongside it. A deletion and
 * a force deletion keep the fields as they are stored, never values set and not
 * saved, and name the model by the key it is stored under, as Eloquent deletes
 * by; the deletion a force deletion runs through is not recorded, before any
 * field is checked, so a force deletion is one record and at most one failure.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ModelChangeDescriber
{
    /** @var string The key a record keeps the changes under. */
    private const string CHANGES = 'changes';

    /** @var string The type of the cast Laravel encrypts a value with, before any argument. */
    private const string ENCRYPTED_CAST = 'encrypted';

    /** @var string The beginning of the short name of each cast class Laravel encrypts a value with. */
    private const string ENCRYPTED_CAST_CLASS_PREFIX = 'AsEncrypted';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Describe the change of the watched model on the builder, and return it,
     * or `null` when the change records nothing: an update of no watched field,
     * or the deletion a force deletion runs through. An update and a restore
     * are both told from the update itself.
     *
     * @param  \SineMacula\Laravel\AuditLog\Capture\ModelWatch  $watch
     * @param  \SineMacula\Laravel\AuditLog\Capture\Enums\ModelEvent  $change
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingRecord  $record
     * @return ?\SineMacula\Laravel\AuditLog\Records\PendingRecord
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public static function describe(ModelWatch $watch, ModelEvent $change, #[\SensitiveParameter] Model $model, #[\SensitiveParameter] PendingRecord $record): ?PendingRecord
    {
        if ($change === ModelEvent::DELETED && self::isForceDeleting($model)) {
            return null;
        }

        self::refuseUnsafeFields($watch, $model);

        $recorded = match ($change) {
            ModelEvent::UPDATED, ModelEvent::RESTORED => self::isRestore($model) ? ModelEvent::RESTORED : ModelEvent::UPDATED,
            default                                   => $change,
        };

        $properties = self::propertiesOf($watch, $recorded, $model);

        if ($properties === null) {
            return null;
        }

        return $record->event($watch->codeOf($recorded))
            ->on(self::subjectOf($recorded, $model))
            ->withProperties($properties)
            ->afterCommit(self::connectionOf($watch, $model));
    }

    /**
     * What the change keeps: the watched fields as set for a creation, as
     * stored for a deletion, both those and the changes for a restore, and the
     * changes alone for an update, which keeps nothing, `null`, when it changed
     * no watched field.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \SineMacula\Laravel\AuditLog\Capture\ModelWatch  $watch
     * @param  \SineMacula\Laravel\AuditLog\Capture\Enums\ModelEvent  $recorded
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return ?array<string, mixed>
     */
    private static function propertiesOf(ModelWatch $watch, ModelEvent $recorded, #[\SensitiveParameter] Model $model): ?array
    {
        return match ($recorded) {
            ModelEvent::CREATED                            => self::fieldsIn($watch, $model->getAttributes()),
            ModelEvent::DELETED, ModelEvent::FORCE_DELETED => self::fieldsIn($watch, $model->getRawOriginal()),
            ModelEvent::RESTORED                           => self::restoreOf($watch, $model),
            ModelEvent::UPDATED                            => self::updateOf($watch, $model),
        };
    }

    /**
     * The subject of the change: the model by its key, and for a deletion or a
     * force deletion by the key it is stored under, which Eloquent deletes by,
     * never a key set and not saved. A field the watch encrypts is then sealed
     * for the row that was removed.
     *
     * @param  \SineMacula\Laravel\AuditLog\Capture\Enums\ModelEvent  $recorded
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return \SineMacula\Laravel\AuditLog\Records\Reference
     *
     * @throws \InvalidArgumentException
     */
    private static function subjectOf(ModelEvent $recorded, #[\SensitiveParameter] Model $model): Reference
    {
        if ($recorded !== ModelEvent::DELETED && $recorded !== ModelEvent::FORCE_DELETED) {
            return Reference::to($model);
        }

        $keyName   = $model->getKeyName();
        $persisted = clone $model;

        $persisted->setRawAttributes([$keyName => $model->getRawOriginal($keyName) ?? $model->getAttributes()[$keyName] ?? null]);

        return Reference::to($persisted);
    }

    /**
     * What a restore keeps: the watched fields as they now are, and beside them
     * the watched fields it changed, when it changed any.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \SineMacula\Laravel\AuditLog\Capture\ModelWatch  $watch
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return array<string, mixed>
     */
    private static function restoreOf(ModelWatch $watch, #[\SensitiveParameter] Model $model): array
    {
        $snapshot = self::fieldsIn($watch, $model->getAttributes());
        $changes  = self::changesOf($watch, $model);

        return $changes === [] ? $snapshot : [...$snapshot, self::CHANGES => $changes];
    }

    /**
     * What an update keeps: the watched fields it changed, or `null` when it
     * changed none.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \SineMacula\Laravel\AuditLog\Capture\ModelWatch  $watch
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return ?array<string, array<string, array{before: mixed, after: mixed}>>
     */
    private static function updateOf(ModelWatch $watch, #[\SensitiveParameter] Model $model): ?array
    {
        $changes = self::changesOf($watch, $model);

        return $changes === [] ? null : [self::CHANGES => $changes];
    }

    /**
     * Refuse the capture when a watched field the watch keeps as it is read is
     * hidden or cast encrypted on the instance.
     *
     * @param  \SineMacula\Laravel\AuditLog\Capture\ModelWatch  $watch
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return void
     *
     * @throws \LogicException
     */
    private static function refuseUnsafeFields(ModelWatch $watch, #[\SensitiveParameter] Model $model): void
    {
        $hidden  = $model->getHidden();
        $visible = $model->getVisible();
        $casts   = $model->getCasts();

        foreach (array_keys($watch->fields) as $field) {
            if ($watch->isExplicit($field)) {
                continue;
            }

            $isHidden = in_array($field, $hidden, true) || ($visible !== [] && !in_array($field, $visible, true));

            if ($isHidden || self::isEncryptedCast($casts[$field] ?? null)) {
                $message = 'The field `%s` of `%s` is hidden or encrypted on this instance, so it needs an explicit handling to be watched.';

                throw new \LogicException(sprintf($message, $field, $watch->class));
            }
        }
    }

    /**
     * Whether the cast encrypts the value: the `encrypted` cast with or without
     * its argument, or a cast class whose short name begins `AsEncrypted`, each
     * read without its arguments.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $cast
     * @return bool
     */
    private static function isEncryptedCast(mixed $cast): bool
    {
        if (!is_string($cast)) {
            return false;
        }

        $type = trim(explode(':', $cast, 2)[0]);

        if (strtolower($type) === self::ENCRYPTED_CAST) {
            return true;
        }

        $segments = explode('\\', $type);

        return str_starts_with(end($segments), self::ENCRYPTED_CAST_CLASS_PREFIX);
    }

    /**
     * Whether the update cleared a soft-deleted model's deleted-at column: the
     * model soft deletes, and the column changed from a value to `null`.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return bool
     */
    private static function isRestore(#[\SensitiveParameter] Model $model): bool
    {
        if (!method_exists($model, 'getDeletedAtColumn')) {
            return false;
        }

        $column  = $model->getDeletedAtColumn();
        $changes = $model->getChanges();

        return is_string($column)
            && array_key_exists($column, $changes)
            && $changes[$column] === null
            && ($model->getPrevious()[$column] ?? null) !== null;
    }

    /**
     * Whether the model is being deleted for good, so its deletion is the force
     * deletion's, recorded under its own code.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return bool
     */
    private static function isForceDeleting(#[\SensitiveParameter] Model $model): bool
    {
        return method_exists($model, 'isForceDeleting') && $model->isForceDeleting() === true;
    }

    /**
     * The watched fields the attributes hold, in the watch's order, each as
     * held.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \SineMacula\Laravel\AuditLog\Capture\ModelWatch  $watch
     * @param  array<string, mixed>  $attributes
     * @return array<string, mixed>
     */
    private static function fieldsIn(ModelWatch $watch, #[\SensitiveParameter] array $attributes): array
    {
        return array_intersect_key(array_replace($watch->fields, $attributes), $watch->fields, $attributes);
    }

    /**
     * The watched fields the update changed, in the watch's order, each with
     * its stored value before the change and its value after.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \SineMacula\Laravel\AuditLog\Capture\ModelWatch  $watch
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return array<string, array{before: mixed, after: mixed}>
     */
    private static function changesOf(ModelWatch $watch, #[\SensitiveParameter] Model $model): array
    {
        $previous = $model->getPrevious();
        $changes  = [];

        foreach (self::fieldsIn($watch, $model->getChanges()) as $field => $after) {
            $changes[$field] = ['before' => $previous[$field] ?? null, 'after' => $after];
        }

        return $changes;
    }

    /**
     * The name of the model's connection, whose commit its change waits for:
     * the default connection's for a model that names none.
     *
     * @param  \SineMacula\Laravel\AuditLog\Capture\ModelWatch  $watch
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return string
     *
     * @throws \LogicException
     */
    private static function connectionOf(ModelWatch $watch, #[\SensitiveParameter] Model $model): string
    {
        return $model->getConnection()->getName()
            ?? throw new \LogicException(sprintf('The connection of `%s` has no name, so its change cannot wait for its commit.', $watch->class));
    }
}
