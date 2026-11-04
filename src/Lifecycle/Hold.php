<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use Illuminate\Contracts\Support\Arrayable;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Support\MachineCode;
use SineMacula\Laravel\AuditLog\Support\StoredTime;
use SineMacula\Laravel\AuditLog\Support\TextSanitizer;

/**
 * An active hold, as the verified journal records it: its id, the entries its
 * scope keeps, the basis it was placed on and the date it is due for review,
 * when and by whom it was placed and why, the operation that placed it, and the
 * sequence of the journal row that records it.
 *
 * A hold keeps every entry its scope matches from being pruned, whatever its
 * basis, until it is released; overlapping holds each count. The package
 * records the basis and the review date and decides nothing from either: a
 * review date that has passed is reported, never acted on.
 *
 * Every field is checked as it is built: the ids lower-case UUIDs, the times
 * instants in the package's form, the reason a machine-readable code, the
 * external reference `null` or 1 to 191 characters of clean text, and the
 * sequence from 1, each refused with an `InvalidArgumentException` naming the
 * field.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @implements \Illuminate\Contracts\Support\Arrayable<string, array<string, bool|int|list<array{0: string, 1: string}>|list<string>|string|null>|int|string|null>
 */
final readonly class Hold implements Arrayable
{
    /** @var string Pattern of a hold's and an operation's id: a lower-case UUID. */
    private const string UUID_PATTERN = '/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/';

    /**
     * Constructor.
     *
     * @param  string  $id
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\HoldScope  $scope
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis  $basis
     * @param  ?string  $reviewBy
     * @param  string  $placedAt
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $operator
     * @param  string  $reason
     * @param  ?string  $externalReference
     * @param  string  $operationId
     * @param  int  $journalSequence
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The hold's id, a lower-case UUID the package minted. */
        public string $id,

        /** The entries the hold keeps. */
        #[\SensitiveParameter]
        public HoldScope $scope,

        /** Why the hold was placed, as its operator states it. */
        public HoldBasis $basis,

        /** The instant the hold is due for review, or `null` for none. */
        public ?string $reviewBy,

        /** The instant the hold was placed: its journal row's. */
        public string $placedAt,

        /** Who placed the hold, as the caller asserted it. */
        public Reference $operator,

        /** Why, as a machine-readable reason code. */
        public string $reason,

        /** The ticket or case the hold answers to, if any. */
        public ?string $externalReference,

        /** The operation that placed the hold. */
        public string $operationId,

        /** The sequence of the journal row that records the hold. */
        public int $journalSequence,
    ) {
        foreach (['id' => $id, 'operation id' => $operationId] as $field => $value) {
            if (preg_match(self::UUID_PATTERN, $value) !== 1) {
                throw new \InvalidArgumentException(sprintf('A hold\'s %s must be a lower-case UUID.', $field));
            }
        }

        foreach (['review date' => $reviewBy, 'placing time' => $placedAt] as $field => $value) {
            if ($value !== null && !StoredTime::isInstant($value)) {
                throw new \InvalidArgumentException(sprintf('A hold\'s %s must be ISO-8601 UTC with microseconds.', $field));
            }
        }

        MachineCode::of($reason, 'A reason');

        if ($externalReference !== null && !self::isExternalReference($externalReference)) {
            $message = 'A hold\'s external reference must be from 1 to %d characters, with no control characters.';

            throw new \InvalidArgumentException(sprintf($message, Authority::MAX_EXTERNAL_REFERENCE_CHARACTERS));
        }

        if ($journalSequence < 1) {
            throw new \InvalidArgumentException('A hold\'s journal sequence must be at least 1.');
        }
    }

    /**
     * Whether the hold's review date has passed at the instant given: it has
     * one, and it is before the instant. A hold with no review date is never
     * past it.
     *
     * @param  string  $now
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    public function isPastReview(string $now): bool
    {
        if (!StoredTime::isInstant($now)) {
            throw new \InvalidArgumentException('The instant a hold\'s review is judged at must be ISO-8601 UTC with microseconds.');
        }

        return $this->reviewBy !== null && strcmp($this->reviewBy, $now) < 0;
    }

    /**
     * The hold as a listing shows it: its id, its scope's canonical form, its
     * basis, its review date, when and by whom it was placed and why, the
     * operation that placed it and its journal row's sequence.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return array{id: string, scope: array{v: int, tenants: ?list<array{0: string, 1: string}>, tenantless: bool, about: ?list<array{0: string, 1: string}>, categories: ?list<string>, from: ?string, to: ?string, import_batch: ?string}, basis: string, review_by: ?string, placed_at: string, operator: array{type: string, id: string}, reason: string, external_reference: ?string, operation_id: string, journal_sequence: int}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    #[\Override]
    public function toArray(): array
    {
        return [
            'id'                 => $this->id,
            'scope'              => $this->scope->toArray(),
            'basis'              => $this->basis->value,
            'review_by'          => $this->reviewBy,
            'placed_at'          => $this->placedAt,
            'operator'           => $this->operator->toArray(),
            'reason'             => $this->reason,
            'external_reference' => $this->externalReference,
            'operation_id'       => $this->operationId,
            'journal_sequence'   => $this->journalSequence,
        ];
    }

    /**
     * Whether the text is an external reference: from 1 to 191 characters and
     * already clean.
     *
     * @param  string  $text
     * @return bool
     */
    private static function isExternalReference(string $text): bool
    {
        return $text !== '' && mb_strlen($text, 'UTF-8') <= Authority::MAX_EXTERNAL_REFERENCE_CHARACTERS && TextSanitizer::isClean($text);
    }
}
