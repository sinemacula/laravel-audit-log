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
 * Turns a pending record's raw values into what its record stores, at capture,
 * so nothing raw rests in a deferred callback, an event or a row.
 *
 * Every setting it depends on is read first, so a malformed one fails the write
 * whatever the record holds, apart from the key, read only once a hash is
 * needed, and the log id, read only once the record has an owner to seal for. A
 * key past the ceiling leaves with its branch before the context or the
 * properties are redacted, so nothing after reads it. A value of the context or
 * the properties that is exactly an encryption envelope, at any depth, is
 * removed and logged under its masked path before anything is sealed: only the
 * record's own sealer makes the envelopes it stores, so its key uses never name
 * a key one of them was copied from. The context is redacted, capped and
 * budgeted, and no field rule touches it. The collisions the builder carried
 * are masked and the properties redacted.
 *
 * Every value is sealed for the entry the record will be stored as, whose id
 * the caller mints before minimising, so an envelope opens only in its own
 * entry and at its own path. The record's owners are gathered before anything
 * is sealed: the owners of the definition's encrypted fields, the note's owner
 * and, under the `encrypt` IP mode, the actor, so the first value sealed can
 * fetch every key the record needs. They are sealed for the record's tenant and
 * its definition's category, which are the stored entry's.
 *
 * The address is minimised, an owned note is sealed under its owner at
 * `["properties","_audit","note"]` and the identifier is hashed. The properties
 * are put through the event definition's rules and budgeted last, so the one
 * omission log, which everything above added to, lands in
 * `properties._audit.omitted`. An artifact's manifest descriptor, its artifact
 * id, kind, digest and count, is the package's own: it lands in
 * `properties._audit.manifest`, outside every field rule, and is never omitted.
 *
 * Nothing is caught: an encrypter's failure is contained by its sealer, and any
 * other failure fails the write, with a message that names keys and types and
 * never a value. It holds a sealer, which remembers a failure for one capture,
 * so it is built per capture and never bound as a singleton.
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

        /** Where the id of the log every entry is signed into is read from on every capture. */
        private SealSettings $seals,
    ) {}

    /**
     * What the record of the snapshot stores under its event's definition, as
     * the entry of the id given, a lower-case UUID the caller minted.
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
     * Every owner the record encrypts for: the owners of the definition's
     * encrypted fields among the redacted properties, the note's owner when the
     * note has one, and the actor when the address is encrypted.
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
     * The values with every member that is exactly an encryption envelope
     * removed, at any depth, each removal given to the callback at its path as
     * given; values that are themselves an envelope lose all three members. A
     * list stays a list, reindexed.
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
     * Log each collision the builder carried under its masked path, and count
     * those past the ones it carried, whose paths it no longer has.
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
     * What the record stores of the note: nothing without one, the plaintext
     * without an owner, and otherwise its envelope under that owner. An owned
     * note with no owner present, or that cannot be sealed, is dropped and
     * diagnosed, never stored in plaintext.
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
     * The party whose key the note is sealed under: the record's actor or
     * subject, which may be absent, the reference it was given, or none for a
     * note without an owner.
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
