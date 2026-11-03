<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Stores;

use SineMacula\Laravel\AuditLog\Contracts\AcceptsAttachments;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Contracts\DurableAuditStore;
use SineMacula\Laravel\AuditLog\Database\FailureClassifier;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;

/**
 * An audit store that delivers each record to several destinations, in order,
 * each under a stable id: the database and a log, say.
 *
 * Every destination is tried, and receives the same finalised record, a bulk
 * record's attachment included, so a database destination keeps the bundle. One
 * that fails does not stop the others or undo what they kept: its failure's
 * class is kept and the next is tried, and once all have been tried a single
 * `StackDeliveryException` names each destination that failed. A destination id
 * is 1 to 64 lower-case letters, digits, dots, underscores or hyphens, starting
 * with a letter or a digit; it names the destination in receipts and
 * diagnostics, so it must stay the same while records are being delivered.
 *
 * The stack is durable when its first destination is, since a return of the
 * first is the acknowledgement. It joins a transaction only when every
 * destination does on that connection: a stack of the database and a log writes
 * its line for a business change that may then roll back, so it is not atomic,
 * and a transactional record needs the outbox to use it. It keeps attachments
 * only when every destination says it does, so a bulk record is never handed to
 * a stack of which one destination would lose its manifest. A stack cannot hold
 * another stack.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class StackAuditStore implements AcceptsAttachments, DurableAuditStore
{
    /** @var string What a destination id must match. */
    public const string DESTINATION_PATTERN = '/\A[a-z0-9][a-z0-9._-]{0,63}\z/';

    /** @var non-empty-array<string, \SineMacula\Laravel\AuditLog\Contracts\AuditStore> The destinations, in the order they are tried, by id. */
    private array $destinations;

    /**
     * Constructor.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $destinations
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(array $destinations)
    {
        $this->destinations = self::checked($destinations);
    }

    /**
     * Deliver the record to every destination, in order, and throw once all
     * have been tried when any of them failed.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  $record
     * @return void
     *
     * @throws \SineMacula\Laravel\AuditLog\Stores\StackDeliveryException
     */
    #[\Override]
    public function store(#[\SensitiveParameter] FinalisedRecord $record): void
    {
        $caught = [];

        foreach ($this->destinations as $id => $destination) {
            try {
                $destination->store($record);
            } catch (\Throwable $failure) {
                $caught[$id] = $failure;
            }
        }

        if ($caught !== []) {
            throw self::deliveryFailure($record->record->id, $caught);
        }
    }

    /**
     * The destinations, in the order they are tried, by id.
     *
     * @return non-empty-array<string, \SineMacula\Laravel\AuditLog\Contracts\AuditStore>
     *
     * @internal
     */
    public function destinations(): array
    {
        return $this->destinations;
    }

    /**
     * Whether a return is a durable acknowledgement: whatever the first
     * destination says, and never when it does not say.
     *
     * @return bool
     */
    #[\Override]
    public function isDurable(): bool
    {
        $first = $this->destinations[array_key_first($this->destinations)];

        return $first instanceof DurableAuditStore && $first->isDurable();
    }

    /**
     * Whether a write joins a transaction on the connection: only when every
     * destination says it does.
     *
     * @param  string  $connection
     * @return bool
     */
    #[\Override]
    public function participatesIn(string $connection): bool
    {
        foreach ($this->destinations as $destination) {
            if (!$destination instanceof DurableAuditStore || !$destination->participatesIn($connection)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Whether the stack keeps a record's attachment with its entry: only when
     * every destination implements `Contracts\AcceptsAttachments` and says it
     * does.
     *
     * @return bool
     */
    #[\Override]
    public function acceptsAttachments(): bool
    {
        foreach ($this->destinations as $destination) {
            if (!$destination instanceof AcceptsAttachments || !$destination->acceptsAttachments()) {
                return false;
            }
        }

        return true;
    }

    /**
     * The exception naming each destination that failed, keeping of each
     * failure only its class and what it was: the failure can hold the record.
     *
     * @param  string  $id
     * @param  non-empty-array<string, \Throwable>  $caught
     * @return \SineMacula\Laravel\AuditLog\Stores\StackDeliveryException
     */
    private static function deliveryFailure(string $id, #[\SensitiveParameter] array $caught): StackDeliveryException
    {
        $classifier  = new FailureClassifier;
        $concurrency = false;
        $lost        = false;
        $aborted     = false;
        $fatal       = [];

        foreach ($caught as $failure) {
            $isConcurrency = $classifier->isConcurrencyError($failure);
            $isLost        = $classifier->isLostConnection($failure);

            $concurrency = $concurrency || $isConcurrency;
            $lost        = $lost        || $isLost;
            $aborted     = $aborted     || $classifier->isAbortedHost($failure);

            if (!$isConcurrency && !$isLost) {
                continue;
            }

            $fatal[] = $classifier->connectionOf($failure);
        }

        return new StackDeliveryException($id, array_map(get_debug_type(...), $caught), $concurrency, $lost, $aborted, $fatal);
    }

    /**
     * The destinations given, once each has been checked: a map, not empty and
     * not a list, whose every id matches the pattern and whose every member is
     * an audit store that is not itself a stack.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $destinations
     * @return non-empty-array<string, \SineMacula\Laravel\AuditLog\Contracts\AuditStore>
     *
     * @throws \InvalidArgumentException
     */
    private static function checked(array $destinations): array
    {
        if ($destinations === []) {
            throw new \InvalidArgumentException('A stack store needs at least one destination.');
        }

        if (array_is_list($destinations)) {
            throw new \InvalidArgumentException('A stack store\'s destinations must be keyed by their ids, not listed.');
        }

        $checked = [];

        foreach ($destinations as $id => $destination) {
            $id = self::checkedId($id);

            $checked[$id] = self::checkedStore($id, $destination);
        }

        return $checked;
    }

    /**
     * The destination id, refused unless it is a string matching the pattern. A
     * decimal integer is refused too: PHP keys an array by it as a number, so
     * it could never come back as the string it was given.
     *
     * @param  int|string  $id
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private static function checkedId(int|string $id): string
    {
        if (!is_string($id) || preg_match(self::DESTINATION_PATTERN, $id) !== 1) {
            $message = 'A stack store\'s destination id must be 1 to 64 lower-case letters, digits, dots, underscores or hyphens, '
                . 'starting with a letter or a digit, and not a decimal integer.';

            throw new \InvalidArgumentException($message);
        }

        return $id;
    }

    /**
     * The destination, refused unless it is an audit store that is not itself a
     * stack.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $id
     * @param  mixed  $destination
     * @return \SineMacula\Laravel\AuditLog\Contracts\AuditStore
     *
     * @throws \InvalidArgumentException
     */
    private static function checkedStore(string $id, mixed $destination): AuditStore
    {
        if (!$destination instanceof AuditStore) {
            throw new \InvalidArgumentException(sprintf('The stack store\'s destination [%s] must be an audit store, not %s.', $id, get_debug_type($destination)));
        }

        if ($destination instanceof self) {
            throw new \InvalidArgumentException(sprintf('The stack store\'s destination [%s] is a stack store; a stack cannot hold another.', $id));
        }

        return $destination;
    }
}
