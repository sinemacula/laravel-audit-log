<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Listeners;

use Illuminate\Auth\Access\Events\GateEvaluated;
use Illuminate\Auth\Access\Response;
use Illuminate\Container\Container;
use SineMacula\Laravel\AuditLog\Capture\CaptureCoordinator;
use SineMacula\Laravel\AuditLog\Capture\CaptureSettings;
use SineMacula\Laravel\AuditLog\Capture\Enums\CapturedActivity;
use SineMacula\Laravel\AuditLog\Capture\GateArguments;
use SineMacula\Laravel\AuditLog\Capture\UserReference;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Support\TextSanitizer;

/**
 * Records the Gate's denials that `audit-log.capture.gate.*` turns on and
 * selects, after the transaction so a rollback keeps their record.
 *
 * Resolves everything per check, since under Octane the container that built
 * the listener is the worker's, not the request's.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RecordGateDenial
{
    /**
     * Record the Gate's evaluation when it is a denial that capture selects.
     *
     * @param  \Illuminate\Auth\Access\Events\GateEvaluated  $event
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Illuminate\Database\DeadlockException
     * @throws \RuntimeException
     */
    public function handle(#[\SensitiveParameter] GateEvaluated $event): void
    {
        if (self::isPlainlyAllowed($event->result)) {
            return;
        }

        $container = Container::getInstance();
        $describe  = static function (#[\SensitiveParameter] PendingRecord $pending) use ($container, $event): ?PendingRecord {
            $settings  = $container->make(CaptureSettings::class);
            $ability   = $event->ability;
            $arguments = $event->arguments;

            if (!$settings->isGateEnabled() || !$settings->selectsAbility($ability) || !self::isDenial($event->result)) {
                return null;
            }

            return $pending->event(CapturedActivity::GATE_DENIED)
                ->by(UserReference::of($event->user))
                ->withProperties([
                    'ability'        => TextSanitizer::clean($ability, CaptureSettings::ABILITY_MAX_BYTES),
                    'arguments'      => GateArguments::of($arguments),
                    'argument_count' => GateArguments::count($arguments),
                ])
                ->denied(self::reasonOf($settings, $event->result))
                ->afterTransaction();
        };

        $container->make(CaptureCoordinator::class)->captured($event, self::class, $describe);
    }

    /**
     * Whether the result is truthy and not a `Response`, so it is left alone
     * before any setting is read.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $result
     * @return bool
     */
    private static function isPlainlyAllowed(#[\SensitiveParameter] mixed $result): bool
    {
        return !$result instanceof Response && !self::isDenial($result);
    }

    /**
     * Whether the Gate's result denies: a falsy result, or a denied response.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $result
     * @return bool
     */
    private static function isDenial(#[\SensitiveParameter] mixed $result): bool
    {
        return $result instanceof Response ? $result->denied() : !$result;
    }

    /**
     * The denied response's code when the reason codes list it, since a token
     * can look like a code; its message is never read.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  \SineMacula\Laravel\AuditLog\Capture\CaptureSettings  $settings
     * @param  mixed  $result
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    private static function reasonOf(CaptureSettings $settings, #[\SensitiveParameter] mixed $result): ?string
    {
        if (!$result instanceof Response) {
            return null;
        }

        $code = $result->code();
        $code = is_int($code) ? (string) $code : $code;

        return is_string($code) && in_array($code, $settings->reasonCodes(), true) ? $code : null;
    }
}
