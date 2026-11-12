<?php

declare(strict_types = 1);

namespace Tests\Unit\Facades;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Recorder;

/**
 * Guards the facade's `@method` lines against drift from the recorder's public
 * methods and their signatures.
 *
 * Only the recorder's methods are covered: the facade's real statics, such as
 * `fake()`, have no line.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class AuditLogMethodLinesTest extends TestCase
{
    /**
     * Every line names a method the recorder has.
     *
     * @return void
     */
    public function testEveryMethodLineMatchesARecorderMethod(): void
    {
        $lines = array_keys(self::methodLines((string) (new \ReflectionClass(AuditLog::class))->getDocComment()));

        self::assertNotSame([], $lines);

        foreach ($lines as $name) {
            self::assertArrayHasKey($name, self::recorderMethods(), "The facade declares {$name}(), which the recorder does not have.");
        }
    }

    /**
     * Every public method of the recorder has a line.
     *
     * @return void
     */
    public function testEveryRecorderMethodHasAMethodLine(): void
    {
        $lines   = array_keys(self::methodLines((string) (new \ReflectionClass(AuditLog::class))->getDocComment()));
        $methods = array_keys(self::recorderMethods());

        sort($lines);
        sort($methods);

        self::assertSame($methods, $lines);
    }

    /**
     * Each line states the method's return type and every parameter's type,
     * name and default, in order.
     *
     * @return void
     */
    public function testEveryMethodLineMatchesItsSignature(): void
    {
        $lines = self::methodLines((string) (new \ReflectionClass(AuditLog::class))->getDocComment());

        foreach (self::recorderMethods() as $name => $signature) {
            self::assertSame($signature, $lines[$name] ?? null, "The facade's line for {$name}() does not match the recorder.");
        }
    }

    /**
     * The scanner reads each `@method static` line, normalised, and passes over
     * everything else.
     *
     * @return void
     */
    public function testTheScannerReadsMethodLines(): void
    {
        $docblock = <<<'EOD'
            /**
             * A facade, whose method record() is mentioned in prose.
             *
             * @see \Example\Thing
             *
             * @method static \Example\Result run(string|\BackedEnum $code, ?int $count = null, array<array-key, int> $map = [], \Example\Level $level = \Example\Level::HIGH)
             * @method static void stop()
             * @method \Example\Ignored instance()
             */
            EOD;

        self::assertSame([
            'run' => [
                'return'     => 'Example\Result',
                'parameters' => [
                    ['type' => 'BackedEnum|string', 'name' => 'code', 'default' => null],
                    ['type' => 'int|null', 'name' => 'count', 'default' => 'null'],
                    ['type' => 'array', 'name' => 'map', 'default' => '[]'],
                    ['type' => 'Example\Level', 'name' => 'level', 'default' => 'Example\Level::HIGH'],
                ],
            ],
            'stop' => ['return' => 'void', 'parameters' => []],
        ], self::methodLines($docblock));
    }

    /**
     * The public methods the recorder declares, by name, each as its signature.
     *
     * @return array<string, array{return: string, parameters: list<array{type: string, name: string, default: ?string}>}>
     */
    private static function recorderMethods(): array
    {
        $methods = [];

        foreach ((new \ReflectionClass(Recorder::class))->getMethods(\ReflectionMethod::IS_PUBLIC) as $method) {

            if ($method->isConstructor()) {
                continue;
            }

            $methods[$method->getName()] = [
                'return'     => self::normalised((string) $method->getReturnType()),
                'parameters' => array_map(self::parameter(...), $method->getParameters()),
            ];
        }

        return $methods;
    }

    /**
     * The parameter's type, name and default, as a `@method` line would say
     * them.
     *
     * @param  \ReflectionParameter  $parameter
     * @return array{type: string, name: string, default: ?string}
     */
    private static function parameter(\ReflectionParameter $parameter): array
    {
        return [
            'type'    => self::normalised((string) $parameter->getType()),
            'name'    => $parameter->getName(),
            'default' => $parameter->isDefaultValueAvailable() ? self::defaultOf($parameter) : null,
        ];
    }

    /**
     * The parameter's default as a `@method` line would say it.
     *
     * @param  \ReflectionParameter  $parameter
     * @return string
     */
    private static function defaultOf(\ReflectionParameter $parameter): string
    {
        $default = $parameter->getDefaultValue();

        return match (true) {
            $default instanceof \UnitEnum => $default::class . '::' . $default->name,
            default                       => strtolower((string) json_encode($default)),
        };
    }

    /**
     * Each `@method static` line of the docblock, by method name.
     *
     * @param  string  $docblock
     * @return array<string, array{return: string, parameters: list<array{type: string, name: string, default: ?string}>}>
     */
    private static function methodLines(string $docblock): array
    {
        preg_match_all('/^\s*\* @method static (\S+) (\w+)\((.*)\)$/m', $docblock, $matches, PREG_SET_ORDER);

        $lines = [];

        foreach ($matches as [, $return, $name, $parameters]) {
            $lines[$name] = [
                'return'     => self::normalised($return),
                'parameters' => $parameters === '' ? [] : array_map(self::parsed(...), (array) preg_split('/, (?![^<]*>)/', $parameters)),
            ];
        }

        return $lines;
    }

    /**
     * One parameter of a `@method` line.
     *
     * @param  false|string  $parameter
     * @return array{type: string, name: string, default: ?string}
     */
    private static function parsed(false|string $parameter): array
    {
        preg_match('/\A(?<type>.+) \$(?<name>\w+)(?: = (?<default>.+))?\z/', (string) $parameter, $parts);

        return [
            'type'    => self::normalised($parts['type'] ?? ''),
            'name'    => $parts['name'] ?? '',
            'default' => isset($parts['default']) ? ltrim($parts['default'], '\\') : null,
        ];
    }

    /**
     * The type normalised so two spellings compare equal: `?T` as `T|null`, a
     * list as an array, its parts in order.
     *
     * @param  string  $type
     * @return string
     */
    private static function normalised(string $type): string
    {
        $bare  = (string) preg_replace('/<.*>/', '', str_starts_with($type, '?') ? substr($type, 1) . '|null' : $type);
        $parts = array_map(static fn (string $part): string => in_array($part, ['list', 'non-empty-list'], true) ? 'array' : ltrim($part, '\\'), explode('|', $bare));

        sort($parts);

        return implode('|', $parts);
    }
}
