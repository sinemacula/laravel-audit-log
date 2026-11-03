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
 * Records the Gate's denials, when `audit-log.capture.gate.enabled` turns them
 * on, for the abilities `audit-log.capture.gate.only_abilities` and
 * `audit-log.capture.gate.except_abilities` select.
 *
 * A denial is what the Gate itself treats as one: `false`, `null` or any other
 * falsy result, or a `Response` that is denied. A check with any other truthy
 * result is left alone at once, before any setting is read. A `Response` is
 * asked whether it denies only inside the capture, once capture is on and the
 * ability is selected, so with capture off it is never asked, and a response
 * that fails to say is a contained failure. Every denial evaluated is recorded,
 * the same one twice included. The actor is the user the Gate
 * checked, or explicitly no one for a guest, never whoever a guard holds now;
 * the Gate names no guard, so none is recorded. The ability is cleaned and cut
 * to 191 bytes, and the arguments are kept only as model references, class
 * names or a marker, with their full count. A denied response's code is kept as
 * the reason only when `audit-log.capture.gate.reason_codes` lists it, since a
 * token can look like a code; its message is free text and never read.
 *
 * A malformed setting or a failure to record is contained by the capture, so
 * the Gate's check returns its result as before.
 *
 * It holds nothing: the capture and its settings come from the application
 * serving the check when it is handled, not from the container that built the
 * listener, which under Octane is the application the worker booted rather than
 * the request's sandbox.
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
                ->denied(self::reasonOf($settings, $event->result));
        };

        $container->make(CaptureCoordinator::class)->captured($event, self::class, $describe);
    }

    /**
     * Whether the Gate's result allows without asking anything of it: a truthy
     * result that is not a `Response`, which is left alone before any setting
     * is read.
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
     * The reason a denial is recorded with: the denied response's code, a
     * string or an integer, when the reason codes list it; otherwise none.
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
