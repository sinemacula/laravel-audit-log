<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Privacy;

use SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Integrity\SealSettings;
use SineMacula\Laravel\AuditLog\Privacy\Enums\IdentifierMode;
use SineMacula\Laravel\AuditLog\Privacy\Enums\IpMode;
use SineMacula\Laravel\AuditLog\Records\EnvelopeKeys;
use SineMacula\Laravel\AuditLog\Records\PendingSnapshot;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * Turns a pending record's raw values into what it stores, at capture, so
 * nothing raw rests in a deferred callback, an event or a row.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RecordMinimiser
{
    /** @var string The diagnostic path of a note that was not stored. */
    private const string NOTE_PATH = '_audit.note';

    /** @var list<string> The path a note is sealed at. */
    private const array NOTE_SEGMENTS = ['properties', '_audit', 'note'];

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Privacy\RedactionSettings  $settings
     * @param  \SineMacula\Laravel\AuditLog\Privacy\Redactor  $redactor
     * @param  \SineMacula\Laravel\AuditLog\Privacy\IpMinimiser  $ipMinimiser
     * @param  \SineMacula\Laravel\AuditLog\Privacy\IdentifierHasher  $hasher
     * @param  \SineMacula\Laravel\AuditLog\Privacy\EnvelopeSealer  $sealer
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealSettings  $seals
     */
    public function __construct(

        /** Where the budgets and modes are read from on every capture. */
        private RedactionSettings $settings,

        /** What replaces the values of secret-shaped keys. */
        private Redactor $redactor,

        /** What decides how much of the client's address is stored. */
        private IpMinimiser $ipMinimiser,

        /** What hashes the identifier and a pseudonymised field. */
        private IdentifierHasher $hasher,

        /** What seals the note and encrypted fields, for this one capture. */
        private EnvelopeSealer $sealer,

        /** Where the log id is read from on every capture. */
        private SealSettings $seals,
    ) {}

    /**
     * What the snapshot's record stores as the entry the caller minted;
     * settings are read first so a malformed one fails any record.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingSnapshot  $snapshot
     * @param  \SineMacula\Laravel\AuditLog\Definitions\EventDefinition  $definition
     * @param  string  $entryId
     * @return \SineMacula\Laravel\AuditLog\Privacy\Minimised
     *
     * @throws \JsonException
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    public function minimise(#[\SensitiveParameter] PendingSnapshot $snapshot, EventDefinition $definition, string $entryId): Minimised
    {
        $this->settings->keys();

        $maxBytes        = $this->settings->maxBytes();
        $maxContextBytes = $this->settings->maxContextBytes();
        $identifierMode  = $this->settings->identifierMode();
        $ipMode          = $this->settings->ipMode();
        $omissions       = new OmissionLog;

        $context = self::withoutEnvelopes(KeyCeiling::context($snapshot->context ?? [], $omissions), [], static function (array $path) use ($omissions): void {
            $omissions->add(PathMasker::context($path));
        });
        $context = ByteBudget::context(FieldPolicy::capped($this->redactor->redact($context)), $maxContextBytes, $omissions);

        self::logCollisions($snapshot, $definition, $omissions);

        $redacted = self::withoutEnvelopes(KeyCeiling::properties($snapshot->properties ?? [], $omissions), [], static function (array $path) use ($omissions, $definition): void {
            $omissions->add(PathMasker::property($path, $definition));
        });
        $redacted = $this->redactor->redact($redacted);
        $owners   = self::ownersOf($snapshot, $definition, $redacted, $ipMode);
        $scope    = new SealingScope($entryId, $owners === [] ? null : $this->seals->logId(), $snapshot->tenant, $definition->category, $owners);

        $address        = $this->ipMinimiser->minimise($snapshot->ip, $snapshot->actor, $this->sealer, $omissions, $scope);
        $note           = $this->storableNote($snapshot, $omissions, $scope);
        $identifierHash = $identifierMode === IdentifierMode::DROP || $snapshot->identifier === null ? null : $this->hasher->identifier($snapshot->identifier);
        $values         = FieldPolicy::apply($redacted, $definition, $snapshot->actor, $snapshot->subject, $this->hasher, $this->sealer, $omissions, $scope);

        return new Minimised(ByteBudget::properties($values, $note, $identifierHash, $definition, $maxBytes, $omissions, $snapshot->manifest?->descriptor()), $context, $address);
    }

    /**
     * Every owner the record encrypts for: encrypted fields' owners, the note's
     * owner, and the actor when the address is encrypted.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingSnapshot  $snapshot
     * @param  \SineMacula\Laravel\AuditLog\Definitions\EventDefinition  $definition
     * @param  array<array-key, mixed>  $redacted
     * @param  \SineMacula\Laravel\AuditLog\Privacy\Enums\IpMode  $ipMode
     * @return list<\SineMacula\Laravel\AuditLog\Records\Reference>
     *
     * @throws \InvalidArgumentException
     */
    private static function ownersOf(#[\SensitiveParameter] PendingSnapshot $snapshot, EventDefinition $definition, #[\SensitiveParameter] array $redacted, IpMode $ipMode): array
    {
        $owners = FieldPolicy::ownersOf($redacted, $definition, $snapshot->actor, $snapshot->subject);

        if ($snapshot->note !== null) {
            $owners[] = self::noteOwner($snapshot);
        }

        if ($ipMode === IpMode::ENCRYPT) {
            $owners[] = $snapshot->actor;
        }

        return array_values(array_filter($owners, static fn (?Reference $owner): bool => $owner !== null));
    }

    /**
     * The values with every exact envelope member removed and reported, so only
     * the record's sealer makes the envelopes it stores.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  array<array-key, mixed>  $values
     * @param  list<int|string>  $path
     * @param  \Closure(list<int|string>): void  $removed
     * @return array<array-key, mixed>
     */
    private static function withoutEnvelopes(#[\SensitiveParameter] array $values, #[\SensitiveParameter] array $path, \Closure $removed): array
    {
        if ($path === [] && EnvelopeKeys::isEnvelope($values)) {
            foreach (array_keys($values) as $key) {
                $removed([$key]);
            }

            return [];
        }

        $isList = array_is_list($values);

        foreach ($values as $key => $value) {
            if (!is_array($value)) {
                continue;
            }

            if (EnvelopeKeys::isEnvelope($value)) {
                unset($values[$key]);
                $removed([...$path, $key]);

                continue;
            }

            $values[$key] = self::withoutEnvelopes($value, [...$path, $key], $removed);
        }

        return $isList ? array_values($values) : $values;
    }

    /**
     * Log each collision the builder carried, and count those past what it
     * carried.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingSnapshot  $snapshot
     * @param  \SineMacula\Laravel\AuditLog\Definitions\EventDefinition  $definition
     * @param  \SineMacula\Laravel\AuditLog\Privacy\OmissionLog  $omissions
     * @return void
     *
     * @throws \JsonException
     * @throws \InvalidArgumentException
     */
    private static function logCollisions(#[\SensitiveParameter] PendingSnapshot $snapshot, EventDefinition $definition, OmissionLog $omissions): void
    {
        foreach ($snapshot->collisions as $segments) {
            $omissions->add(PathMasker::property($segments, $definition));
        }

        foreach ($snapshot->contextCollisions as $segments) {
            $omissions->add(PathMasker::context($segments));
        }

        $omissions->addCount($snapshot->collisionCount - count($snapshot->collisions));
        $omissions->addCount($snapshot->contextCollisionCount - count($snapshot->contextCollisions));
    }

    /**
     * What the record stores of the note: the plaintext without an owner,
     * otherwise its envelope; an owned note that cannot be sealed is dropped.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingSnapshot  $snapshot
     * @param  \SineMacula\Laravel\AuditLog\Privacy\OmissionLog  $omissions
     * @param  \SineMacula\Laravel\AuditLog\Privacy\SealingScope  $scope
     * @return array{v: int, k: string, c: string}|string|null
     *
     * @throws \JsonException
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    private function storableNote(#[\SensitiveParameter] PendingSnapshot $snapshot, OmissionLog $omissions, SealingScope $scope): array|string|null
    {
        if ($snapshot->note === null || $snapshot->noteOwner === null) {
            return $snapshot->note;
        }

        // A string's typed plaintext is cut until it fits, so it is never null
        $owner    = self::noteOwner($snapshot);
        $envelope = $owner === null ? null : $this->sealer->seal($owner, (string) TypedPlaintext::encode($snapshot->note), $scope->at(self::NOTE_SEGMENTS));

        if ($envelope === null) {
            $omissions->add(self::NOTE_PATH);
        }

        return $envelope;
    }

    /**
     * The party whose key the note is sealed under, or `null` when absent or
     * the note has no owner.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingSnapshot  $snapshot
     * @return ?\SineMacula\Laravel\AuditLog\Records\Reference
     */
    private static function noteOwner(#[\SensitiveParameter] PendingSnapshot $snapshot): ?Reference
    {
        return match ($snapshot->noteOwner) {
            KeyOwner::ACTOR   => $snapshot->actor,
            KeyOwner::SUBJECT => $snapshot->subject,
            default           => $snapshot->noteOwner,
        };
    }
}
