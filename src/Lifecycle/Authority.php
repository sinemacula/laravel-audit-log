<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use Illuminate\Contracts\Support\Arrayable;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Support\MachineCode;
use SineMacula\Laravel\AuditLog\Support\TextSanitizer;

/**
 * Who acted on the log and why, as the caller asserts it; the package records
 * the authority and authorises nothing.
 *
 * Each field is validated, never cleaned or cut, and a refusal names the field,
 * never its value.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @implements \Illuminate\Contracts\Support\Arrayable<string, ?string>
 */
final readonly class Authority implements Arrayable
{
    /** @var int Longest external reference, in characters. */
    public const int MAX_EXTERNAL_REFERENCE_CHARACTERS = 191;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $operator
     * @param  string  $reason
     * @param  ?string  $externalReference
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** Who acted, as the caller asserts it. */
        public Reference $operator,

        /** Why, as a machine-readable reason code. */
        public string $reason,

        /** The ticket or case the operation answers to, if any. */
        public ?string $externalReference = null,
    ) {
        MachineCode::of($reason, 'A reason');

        if ($externalReference !== null && !self::isExternalReference($externalReference)) {
            $message = 'An authority\'s external reference must be from 1 to %d characters, with no control characters.';

            throw new \InvalidArgumentException(sprintf($message, self::MAX_EXTERNAL_REFERENCE_CHARACTERS));
        }
    }

    /**
     * The authority as the journal and a record keep it.
     *
     * @return array{type: string, id: string, reason: string, external_reference: ?string}
     */
    #[\Override]
    public function toArray(): array
    {
        return [
            'type'               => $this->operator->type,
            'id'                 => $this->operator->id,
            'reason'             => $this->reason,
            'external_reference' => $this->externalReference,
        ];
    }

    /**
     * Whether the text is a clean external reference of 1 to 191 characters.
     *
     * @param  string  $text
     * @return bool
     */
    private static function isExternalReference(string $text): bool
    {
        return $text !== '' && mb_strlen($text, 'UTF-8') <= self::MAX_EXTERNAL_REFERENCE_CHARACTERS && TextSanitizer::isClean($text);
    }
}
