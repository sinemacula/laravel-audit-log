<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Privacy;

use SineMacula\Laravel\AuditLog\Definitions\Enums\KeyOwner;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Privacy\Enums\IdentifierMode;
use SineMacula\Laravel\AuditLog\Records\PendingSnapshot;
use SineMacula\Laravel\AuditLog\Records\Reference;

/**
 * Turns a pending record's raw values into what its record stores, at capture,
 * so nothing raw rests in a deferred callback, an event or a row.
 *
 * Every setting it depends on is read first, so a malformed one fails the write
 * whatever the record holds, apart from the IP mode, which the IP minimiser
 * reads, and the key, read only once a hash is needed. A key past the ceiling
 * leaves with its branch before the context or the properties are redacted, so
 * nothing after reads it. The context is redacted, capped and budgeted, and no
 * field rule touches it. The collisions the builder carried are masked, the
 * address is minimised, an owned note is sealed under its owner and the
 * identifier is hashed. The properties are redacted, put through the event
 * definition's rules and budgeted last, so the one omission log, which
 * everything above added to, lands in `properties._audit.omitted`. A bulk
 * operation's manifest descriptor, its artifact id, digest and count, is the
 * package's own: it lands in `properties._audit.manifest`, outside every field
 * rule, and is never omitted.
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

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Privacy\RedactionSettings  $settings
     * @param  \SineMacula\Laravel\AuditLog\Privacy\Redactor  $redactor
     * @param  \SineMacula\Laravel\AuditLog\Privacy\IpMinimiser  $ipMinimiser
     * @param  \SineMacula\Laravel\AuditLog\Privacy\IdentifierHasher  $hasher
     * @param  \SineMacula\Laravel\AuditLog\Privacy\EnvelopeSealer  $sealer
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
    ) {}

    /**
     * What the record of the snapshot stores under its event's definition.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingSnapshot  $snapshot
     * @param  \SineMacula\Laravel\AuditLog\Definitions\EventDefinition  $definition
     * @return \SineMacula\Laravel\AuditLog\Privacy\Minimised
     *
     * @throws \JsonException
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    public function minimise(#[\SensitiveParameter] PendingSnapshot $snapshot, EventDefinition $definition): Minimised
    {
        $this->settings->keys();

        $maxBytes        = $this->settings->maxBytes();
        $maxContextBytes = $this->settings->maxContextBytes();
        $identifierMode  = $this->settings->identifierMode();
        $omissions       = new OmissionLog;

        $context = ByteBudget::context(FieldPolicy::capped($this->redactor->redact(KeyCeiling::context($snapshot->context ?? [], $omissions))), $maxContextBytes, $omissions);

        self::logCollisions($snapshot, $definition, $omissions);

        $address        = $this->ipMinimiser->minimise($snapshot->ip, $snapshot->actor, $this->sealer, $omissions);
        $note           = $this->storableNote($snapshot, $omissions);
        $identifierHash = $identifierMode === IdentifierMode::DROP || $snapshot->identifier === null ? null : $this->hasher->identifier($snapshot->identifier);

        $redacted = $this->redactor->redact(KeyCeiling::properties($snapshot->properties ?? [], $omissions));
        $values   = FieldPolicy::apply($redacted, $definition, $snapshot->actor, $snapshot->subject, $this->hasher, $this->sealer, $omissions);

        return new Minimised(ByteBudget::properties($values, $note, $identifierHash, $definition, $maxBytes, $omissions, $snapshot->manifest?->descriptor()), $context, $address);
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
     * @return array{v: int, k: string, c: string}|string|null
     *
     * @throws \JsonException
     * @throws \InvalidArgumentException
     */
    private function storableNote(#[\SensitiveParameter] PendingSnapshot $snapshot, OmissionLog $omissions): array|string|null
    {
        if ($snapshot->note === null || $snapshot->noteOwner === null) {
            return $snapshot->note;
        }

        $owner    = self::noteOwner($snapshot);
        $envelope = $owner === null ? null : $this->sealer->seal($owner, $snapshot->note);

        if ($envelope === null) {
            $omissions->add(self::NOTE_PATH);
        }

        return $envelope;
    }

    /**
     * The party whose key the note is sealed under: the record's actor or
     * subject, which may be absent, or the reference it was given.
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
