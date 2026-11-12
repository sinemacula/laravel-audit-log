<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog;

use Illuminate\Container\Container;
use Illuminate\Contracts\Encryption\StringEncrypter;
use Illuminate\Support\Str;
use SineMacula\Laravel\AuditLog\Capture\CapturedEvents;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry;
use SineMacula\Laravel\AuditLog\Definitions\DefinitionSettings;
use SineMacula\Laravel\AuditLog\Definitions\EventCatalogue;
use SineMacula\Laravel\AuditLog\Delivery\CaptureSignal;
use SineMacula\Laravel\AuditLog\Delivery\PackageWrite;
use SineMacula\Laravel\AuditLog\Delivery\RecordDelivery;
use SineMacula\Laravel\AuditLog\Privacy\RecordMinimiser;
use SineMacula\Laravel\AuditLog\Records\Attachment;
use SineMacula\Laravel\AuditLog\Records\AuditRecord;
use SineMacula\Laravel\AuditLog\Records\Contribution;
use SineMacula\Laravel\AuditLog\Records\Enums\Timing;
use SineMacula\Laravel\AuditLog\Records\EventCode;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Records\PendingSnapshot;
use SineMacula\Laravel\AuditLog\Records\SourceSettings;

/**
 * The pipeline every recorded or captured activity runs: its definition and
 * timing are checked, the contributors fill its gaps, it is minimised, a bulk
 * manifest is sealed, and the built record is delivered.
 *
 * Nothing is consumed until the record is minimised and any manifest sealed, so
 * a refusal before then stores nothing and leaves the builder usable. It holds
 * only frozen registration data, so it outlives requests safely.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RecordPipeline
{
    /** @var string Why an explicit write is refused while an event mapper runs. */
    private const string WRITE_WHILE_MAPPING = 'A record is never written while an event mapper runs; the mapper returns its builder and the capture writes it.';

    /** @var string Why a builder with no code is refused. */
    private const string NO_CODE = 'A pending record needs an event code before it is recorded; set one with `event()`.';

    /** @var string Why a reserved code without a package write is refused. */
    private const string RESERVED_CODE = 'A code under the reserved prefix is written only by the package\'s own activity.';

    /** @var string Why a package write of any other code is refused. */
    private const string PACKAGE_WRITE_OF_ANOTHER_CODE = 'A package write records a code under the reserved prefix, and no other.';

    /** @var string Why a package write that is not fail-closed and immediate, or is a capture, is refused. */
    private const string LOOSE_PACKAGE_WRITE = 'A package write is written immediately and fail-closed, and is never a capture.';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\AuditLog\Definitions\EventCatalogue  $catalogue
     * @param  \SineMacula\Laravel\AuditLog\Contributors\ContributorRegistry  $contributors
     */
    public function __construct(

        /** The definitions registered while the application booted. */
        private EventCatalogue $catalogue,

        /** The contributors registered while the application booted, by class name. */
        private ContributorRegistry $contributors,
    ) {}

    /**
     * Write the builder's record and return it. The id is minted before
     * minimising because each encrypted value is sealed for its entry.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingRecord  $pending
     * @param  ?\SineMacula\Laravel\AuditLog\Delivery\CaptureSignal  $capture
     * @param  ?\SineMacula\Laravel\AuditLog\Delivery\PackageWrite  $package
     * @return \SineMacula\Laravel\AuditLog\Records\AuditRecord
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Illuminate\Contracts\Encryption\EncryptException
     * @throws \InvalidArgumentException
     * @throws \JsonException
     * @throws \LogicException
     * @throws \UnexpectedValueException
     * @throws \Illuminate\Database\DeadlockException
     * @throws \SineMacula\Laravel\AuditLog\Stores\AuditWriteFailedException
     */
    public function write(
        #[\SensitiveParameter] PendingRecord $pending,
        #[\SensitiveParameter] ?CaptureSignal $capture = null,
        #[\SensitiveParameter] ?PackageWrite $package = null,
    ): AuditRecord {
        $container = Container::getInstance();

        if ($capture === null && $container->make(CapturedEvents::class)->isMapping()) {
            self::refuse(self::WRITE_WHILE_MAPPING);
        }

        $snapshot = $pending->snapshot();

        if ($snapshot->code === null) {
            self::refuse(self::NO_CODE);
        }

        self::checkPackageWrite($snapshot, $snapshot->code, $capture, $package);

        $definition = $this->catalogue->definitionFor($snapshot->code, $container->make(DefinitionSettings::class)->requiresRegistered());
        $delivery   = $container->make(RecordDelivery::class);
        $timing     = $snapshot->timing ?? ($capture === null ? Timing::AFTER_COMMIT : Timing::IMMEDIATE);

        $delivery->check($timing, $snapshot->connection, $snapshot->failClosed, $capture);

        $contribution = new Contribution($pending);

        foreach ($this->contributors->classes() as $contributor) {
            $container->make($contributor)->contribute($contribution);
        }

        $filled     = $pending->snapshot();
        $occurredAt = $container->make(Clock::class)->now();
        $id         = $filled->id ?? Str::uuid7($occurredAt)->toString();
        $minimised  = $container->make(RecordMinimiser::class)->minimise($filled, $definition, $id);
        $attachment = $snapshot->manifest === null ? null : Attachment::sealed($snapshot->manifest, $container->make(StringEncrypter::class));
        $source     = $container->make(SourceSettings::class);
        $record     = AuditRecord::fromPending($pending, $minimised, $id, $definition->version, $definition->category, $occurredAt, $source->id(), $source->region(), $attachment);

        $package?->check($record);

        $delivery->deliver($record, $timing, $snapshot->connection, $snapshot->failClosed, $capture, $package);

        return $record;
    }

    /**
     * Refuse a reserved code without a package write, and a package write of
     * any other code, or one that is not fail-closed and immediate, or comes
     * with a capture's signal, before anything is consumed.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingSnapshot  $snapshot
     * @param  \SineMacula\Laravel\AuditLog\Records\EventCode  $code
     * @param  ?\SineMacula\Laravel\AuditLog\Delivery\CaptureSignal  $capture
     * @param  ?\SineMacula\Laravel\AuditLog\Delivery\PackageWrite  $package
     * @return void
     *
     * @throws \LogicException
     */
    private static function checkPackageWrite(
        #[\SensitiveParameter] PendingSnapshot $snapshot,
        EventCode $code,
        #[\SensitiveParameter] ?CaptureSignal $capture,
        #[\SensitiveParameter] ?PackageWrite $package,
    ): void {
        $reserved = str_starts_with($code->value, EventCode::RESERVED_PREFIX);

        if ($package === null) {

            if ($reserved) {
                self::refuse(self::RESERVED_CODE);
            }

            return;
        }

        if (!$reserved) {
            self::refuse(self::PACKAGE_WRITE_OF_ANOTHER_CODE);
        }

        if ($capture === null && $snapshot->failClosed && $snapshot->timing === Timing::IMMEDIATE) {
            return;
        }

        self::refuse(self::LOOSE_PACKAGE_WRITE);
    }

    /**
     * Refuse the write, before anything is consumed.
     *
     * @param  string  $message
     * @return never
     *
     * @throws \LogicException
     */
    private static function refuse(string $message): never
    {
        throw new \LogicException($message);
    }
}
