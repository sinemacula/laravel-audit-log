<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Records;

use SineMacula\Laravel\AuditLog\Records\Enums\EnvelopeFailure;

/**
 * Thrown when an envelope kept outside the entries table, in the outbox or a
 * spill line, is refused as it is written or read back, saying why as one of
 * the distinct failures.
 *
 * Its message is fixed for each failure and holds nothing of the envelope, and
 * it has no previous exception, so neither a console nor a log reaches what the
 * envelope held. It keeps the envelope's id only when that id is a lower-case
 * UUID, so hostile bytes in an envelope never reach a console either.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class EnvelopeRejectedException extends \UnexpectedValueException
{
    /** @var string A UUID in the one form every record id takes. */
    private const string UUID_PATTERN = '/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/';

    /** @var ?string The envelope's id when it is a lower-case UUID, and `null` otherwise or when it has none. */
    public readonly ?string $id;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\EnvelopeFailure  $failure
     * @param  ?string  $id
     */
    public function __construct(

        /** Why the envelope was refused. */
        public readonly EnvelopeFailure $failure,

        // The envelope's id as it was read, kept only when it is a lower-case
        // UUID.
        ?string $id = null,
    ) {
        $this->id = $id !== null && preg_match(self::UUID_PATTERN, $id) === 1 ? $id : null;

        parent::__construct(self::messageFor($failure));
    }

    /**
     * The fixed message of the failure.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Enums\EnvelopeFailure  $failure
     * @return string
     */
    private static function messageFor(EnvelopeFailure $failure): string
    {
        return match ($failure) {
            EnvelopeFailure::SIGNATURE_MISMATCH  => 'The audit envelope\'s signature does not match its content.',
            EnvelopeFailure::UNKNOWN_KEY         => 'The audit envelope names an integrity key the key ring does not hold, so it cannot be verified.',
            EnvelopeFailure::UNSUPPORTED_VERSION => 'The audit envelope is in a record or integrity version this release does not read.',
            EnvelopeFailure::MALFORMED           => 'The audit envelope is not a well-formed audit record.',
            EnvelopeFailure::TRUNCATED           => 'The audit envelope is truncated.',
            EnvelopeFailure::UNSIGNED            => 'The audit envelope is unsigned, so it cannot be verified.',
            EnvelopeFailure::ID_MISMATCH         => 'The audit envelope\'s id is not the id it was kept under.',
            EnvelopeFailure::OVERSIZE            => 'The audit envelope is larger than any audit record can be.',
        };
    }
}
