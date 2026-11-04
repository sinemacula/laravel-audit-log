<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;

/**
 * The evidence the record of a lifecycle operation must keep exactly: its
 * properties, a map of scalars, lists and maps in the order of the operation's
 * code, which name the operation by its `operation_id` first, so
 * `audit-log:reconcile` can tell a recorded operation from one that is not.
 *
 * Evidence is never minimised away: `assertKeptBy()` refuses a record whose
 * properties do not encode canonically to exactly the evidence's, or that carry
 * the package's metadata at all, since a lifecycle record carries no artifact.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class LifecycleEvidence
{
    /** @var string The property that names the operation. */
    public const string OPERATION_KEY = 'operation_id';

    /** @var string The key the package's metadata sits under in a record's properties. */
    private const string METADATA_KEY = '_audit';

    /** @var string Why a record that does not keep the evidence is refused. */
    private const string ALTERED = 'A lifecycle record must keep its evidence exactly.';

    /** @var string The operation the evidence names. */
    public string $operationId;

    /**
     * Constructor.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  array<string, array<array-key, array<array-key, scalar|null>|scalar|null>|scalar|null>  $properties
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The properties the record keeps, in the order of the operation's code, the operation's id among them. */
        #[\SensitiveParameter]
        public array $properties,
    ) {
        $operationId = $properties[self::OPERATION_KEY] ?? null;

        if (!is_string($operationId) || $operationId === '') {
            throw new \InvalidArgumentException(sprintf('The evidence of a lifecycle record names its operation under `%s`.', self::OPERATION_KEY));
        }

        $this->operationId = $operationId;
    }

    /**
     * Refuse the record unless it keeps the evidence exactly: its properties
     * encode canonically to the very bytes of the evidence's, and it carries
     * none of the package's metadata.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\AuditRecord  $record
     * @return void
     *
     * @throws \LogicException
     */
    public function assertKeptBy(#[\SensitiveParameter] AuditRecord $record): void
    {
        $properties = $record->properties ?? [];

        if (array_key_exists(self::METADATA_KEY, $properties) || !self::encodesAlike($properties, $this->properties)) {
            throw new \LogicException(self::ALTERED);
        }
    }

    /**
     * Whether the two maps have the same canonical encoding; a value with none
     * is never alike.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $kept
     * @param  array<array-key, mixed>  $evidence
     * @return bool
     */
    private static function encodesAlike(#[\SensitiveParameter] array $kept, #[\SensitiveParameter] array $evidence): bool
    {
        try {
            return CanonicalEncoder::encode($kept) === CanonicalEncoder::encode($evidence);
        } catch (\UnexpectedValueException) {
            // A value with no canonical form was not kept as given
            return false;
        }
    }
}
