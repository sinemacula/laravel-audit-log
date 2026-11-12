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
 * Builds the imported record of an import line as the capture pipeline builds a
 * captured one, less what an import cannot carry.
 *
 * No contributor runs, since nothing of the process doing the import is the
 * record's; the id is drawn before minimising, as values are sealed per entry.
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

        /** Resolves the catalogue, the settings and the minimiser on every build. */
        private Container $container,
    ) {}

    /**
     * The imported record of the line, or why it is rejected; a dry run
     * encrypts nothing.
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
     * The registered definition, else the permissive default, or `null` when
     * unregistered codes are refused.
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
     * The minimiser, sealing with no encrypter on a dry run so no key is made.
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
     * A builder describing the line, its client and context filled as a
     * contributor fills them.
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
