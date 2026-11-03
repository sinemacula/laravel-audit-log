<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Facades;

use Illuminate\Support\Facades\Facade;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Testing\FakeAuditStore;

/**
 * Package `AuditLog` facade: the recorder, with an `@method` line for every
 * method it declares, so IDEs and static analysis see them.
 *
 * `fake()` is the facade's own and not the recorder's, as Laravel's
 * `Mail::fake()` is, so production code names nothing of the testing helpers.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @see \SineMacula\Laravel\AuditLog\Recorder
 *
 * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
 *
 * @formatter:off
 *
 * @phpcs:disable Generic.Files.LineLength.TooLong
 *
 * @method static \SineMacula\Laravel\AuditLog\Records\AuditRecord record(\BackedEnum|string $code, \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\AuditLog\Records\Reference|null $subject = null, array<array-key, mixed> $properties = [], \SineMacula\Laravel\AuditLog\Records\Enums\Outcome $outcome = \SineMacula\Laravel\AuditLog\Records\Enums\Outcome::SUCCESS, \BackedEnum|string|null $reason = null)
 * @method static \SineMacula\Laravel\AuditLog\Records\PendingRecord event(\BackedEnum|string $code)
 * @method static \SineMacula\Laravel\AuditLog\Records\PendingRecord accessed(\BackedEnum|string $code, \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\AuditLog\Records\Reference $subject, \BackedEnum|string $purpose, \BackedEnum|string $channel)
 * @method static void define(\SineMacula\Laravel\AuditLog\Definitions\EventDefinition|string $definition)
 * @method static void contribute(string $contributor)
 * @method static void map(string $classOrInterface, string $mapper, list<string> $except = [])
 * @method static \SineMacula\Laravel\AuditLog\Records\AuditRecord|null capture(object $event)
 * @method static void watch(string $model, string $as, array<int|string, \SineMacula\Laravel\AuditLog\Definitions\Enums\FieldHandling|string> $fields)
 * @method static \SineMacula\Laravel\AuditLog\Records\PendingRecord bulk(\BackedEnum|string $code, iterable<array-key, \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\AuditLog\Records\Reference> $subjects)
 *
 * @phpcs:enable Generic.Files.LineLength.TooLong
 *
 * @formatter:on
 */
final class AuditLog extends Facade
{
    /**
     * Resolve the recorder directly from the container, type-narrowed.
     *
     * @return \SineMacula\Laravel\AuditLog\Recorder
     *
     * @throws \LogicException
     */
    public static function recorder(): Recorder
    {
        $recorder = self::getFacadeApplication()?->make(Recorder::class);

        if (!$recorder instanceof Recorder) {

            $message = 'The `Recorder` container binding did not resolve to a'
                . ' Recorder instance - check that AuditLogServiceProvider'
                . ' is registered.';

            throw new \LogicException($message);
        }

        return $recorder;
    }

    /**
     * Bind a fresh fake as the application's store and return it. Records still
     * pass through the contributors, deferral and finalisation.
     *
     * @return \SineMacula\Laravel\AuditLog\Testing\FakeAuditStore
     */
    public static function fake(): FakeAuditStore
    {
        return FakeAuditStore::fake(self::getFacadeApplication());
    }

    /**
     * The container key the facade resolves.
     *
     * @return string
     */
    #[\Override]
    protected static function getFacadeAccessor(): string
    {
        return Recorder::class;
    }
}
