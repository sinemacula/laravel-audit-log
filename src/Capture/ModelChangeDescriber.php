<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Capture;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\AuditLog\Capture\Enums\ModelEvent;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * Describes a watched model's change on a capture's builder, delivered after
 * the model's connection commits.
 *
 * Values are read raw, never through an accessor or cast, and a field hidden or
 * cast encrypted on the instance is refused unless explicitly handled.
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

    /** @var string The cast type Laravel encrypts a value with. */
    private const string ENCRYPTED_CAST = 'encrypted';

    /** @var string Short-name prefix of Laravel's encrypting cast classes. */
    private const string ENCRYPTED_CAST_CLASS_PREFIX = 'AsEncrypted';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Describe the change on the builder, or `null` when it records nothing: an
     * update of no watched field, or a force deletion's inner deletion.
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
     * The properties the change keeps, or `null` for an update of no watched
     * field.
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
     * The change's subject; a deletion is named by its stored key, which
     * Eloquent deletes by, never an unsaved one.
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
     * What a restore keeps: the watched fields, and beside them the changes
     * when there are any.
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
     * What an update keeps: the watched fields it changed, or `null` when none.
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
     * Refuse a watched field kept as read that is hidden or cast encrypted on
     * the instance.
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
     * Whether the cast encrypts: `encrypted`, or a cast class whose short name
     * begins `AsEncrypted`, read without arguments.
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
     * Whether the update cleared a soft-deleted model's deleted-at column.
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
     * deletion's.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return bool
     */
    private static function isForceDeleting(#[\SensitiveParameter] Model $model): bool
    {
        return method_exists($model, 'isForceDeleting') && $model->isForceDeleting() === true;
    }

    /**
     * The watched fields the attributes hold, in the watch's order.
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
     * its stored value before and its value after.
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
     * The name of the model's connection, whose commit the change waits for.
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
