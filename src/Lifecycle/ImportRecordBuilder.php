<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Lifecycle;

use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Support\Str;
use SineMacula\Laravel\AuditLog\Definitions\DefinitionSettings;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Definitions\EventDefinition;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportRejection;
use SineMacula\Laravel\AuditLog\Privacy\EnvelopeSealer;
use SineMacula\Laravel\AuditLog\Privacy\NoFieldEncrypter;
use SineMacula\Laravel\AuditLog\Privacy\RecordMinimiser;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\Contribution;
use SineMacula\Laravel\AuditLog\Records\Enums\Outcome;
use SineMacula\Laravel\AuditLog\Records\EventCode;
use SineMacula\Laravel\AuditLog\Records\ImportedSource;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;

/**
 * Builds the imported record of an import line, as the capture pipeline builds
 * a captured one, less what an import cannot carry.
 *
 * A code registered in the catalogue is built under its definition, its field
 * rules, minimisation and encryption included. An unregistered code is
 * `UNREGISTERED_CODE` while `audit-log.definitions.require_registered` holds,
 * and is otherwise built under the permissive default in the line's category,
 * or `general`. The line's references, outcome and reason, correlation id and
 * properties describe a builder, its IP address and context are filled as a
 * contributor would fill them, and the builder is minimised and built into an
 * imported record of the source given. Its id is drawn at the import's time
 * before it is minimised, since every encrypted value is sealed for the entry
 * it belongs to. Any value the builder or the record refuses makes the line
 * `INVALID_FIELD`, a property under the reserved `_audit` prefix among them.
 *
 * No contributor runs: an import carries no ambient context, and nothing of the
 * request, the command or the job doing the import is the record's. A dry run
 * minimises over a sealer of the encrypter that encrypts nothing, so it creates
 * no key and seals no value, and an encrypted field is diagnosed as dropped
 * exactly as an owner without a key would be.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ImportRecordBuilder
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The container the catalogue, the settings and the minimiser are resolved from on every build. */
        private Container $container,
    ) {}

    /**
     * The imported record of the line, from the source given and drawn at the
     * import's time, or why the line is rejected; a dry run encrypts nothing.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportLine  $line
     * @param  \SineMacula\Laravel\AuditLog\Records\ImportedSource  $source
     * @param  \DateTimeInterface  $importedAt
     * @param  bool  $dryRun
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportRejection|\SineMacula\Laravel\AuditLog\Records\AuditRecord
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \JsonException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     */
    public function build(#[\SensitiveParameter] ImportLine $line, ImportedSource $source, \DateTimeInterface $importedAt, bool $dryRun): AuditRecord|ImportRejection
    {
        try {
            $code       = EventCode::of($line->event);
            $definition = $this->definitionOf($code, $line->category);

            if ($definition === null) {
                return ImportRejection::UNREGISTERED_CODE;
            }

            $pending   = self::described($line, $code);
            $id        = Str::uuid7($importedAt)->toString();
            $minimised = $this->minimiser($dryRun)->minimise($pending->snapshot(), $definition, $id);

            return AuditRecord::fromImport($pending, $minimised, $definition->version, $definition->category, $line->occurredAt, $line->origin, $source, $id);
        } catch (\InvalidArgumentException) {
            return ImportRejection::INVALID_FIELD;
        }
    }

    /**
     * The definition the code is built under: the registered one, the
     * permissive default in the category given or `general`, or `null` when the
     * code is not registered and unregistered codes are refused.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\EventCode  $code
     * @param  ?string  $category
     * @return ?\SineMacula\Laravel\AuditLog\Definitions\EventDefinition
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private function definitionOf(EventCode $code, ?string $category): ?EventDefinition
    {
        $catalogue = $this->container->make(EventCatalogue::class);

        if ($catalogue->isRegistered($code)) {
            return $catalogue->definitionFor($code);
        }

        if ($this->container->make(DefinitionSettings::class)->requiresRegistered()) {
            return null;
        }

        return EventDefinition::permissive($code)->category($category ?? EventDefinition::DEFAULT_CATEGORY);
    }

    /**
     * The minimiser of this build: over a sealer of the encrypter that encrypts
     * nothing for a dry run, and over the bound encrypter otherwise.
     *
     * @param  bool  $dryRun
     * @return \SineMacula\Laravel\AuditLog\Privacy\RecordMinimiser
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function minimiser(bool $dryRun): RecordMinimiser
    {
        if (!$dryRun) {
            return $this->container->make(RecordMinimiser::class);
        }

        $sealer = new EnvelopeSealer(new NoFieldEncrypter, $this->container->make(ExceptionHandler::class));

        return $this->container->make(RecordMinimiser::class, ['sealer' => $sealer]);
    }

    /**
     * A builder describing the line: its code, references, outcome and reason,
     * correlation id and properties given, and its IP address and context
     * filled as a contributor fills them.
     *
     * @param  \SineMacula\Laravel\AuditLog\Lifecycle\ImportLine  $line
     * @param  \SineMacula\Laravel\AuditLog\Records\EventCode  $code
     * @return \SineMacula\Laravel\AuditLog\Records\PendingRecord
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private static function described(#[\SensitiveParameter] ImportLine $line, EventCode $code): PendingRecord
    {
        $pending = (new PendingRecord)->event($code->value)->by($line->actor)->asPrincipal($line->principal)->forTenant($line->tenant);

        if ($line->subject !== null) {
            $pending->on($line->subject);
        }

        if ($line->correlationId !== null) {
            $pending->correlatedWith($line->correlationId);
        }

        if ($line->properties !== null) {
            $pending->withProperties($line->properties);
        }

        match ($line->outcome) {
            Outcome::SUCCESS => $pending->succeeded(),
            Outcome::FAILURE => $pending->failed($line->reason),
            Outcome::DENIED  => $pending->denied($line->reason),
        };

        $contribution = new Contribution($pending);

        $contribution->fillClient($line->ip, null);

        if ($line->context !== null) {
            $contribution->fillContext($line->context);
        }

        return $pending;
    }
}
