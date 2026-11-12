<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Stores;

use Illuminate\Database\QueryException;
use SineMacula\Laravel\AuditLog\Stores\Enums\FailedOperation;

/**
 * What may be said of a failed write without saying anything of the record: it
 * never reads the message, SQL, bindings or previous exception.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class WriteDiagnostics
{
    /** @var int Longest exception class kept, in bytes. */
    public const int CLASS_MAX_BYTES = 191;

    /** @var string What a SQLSTATE is: five digits or capital letters. */
    private const string SQL_STATE = '/\A[0-9A-Z]{5}\z/';

    /** @var string What a driver code given as a string must be to be kept: digits that fit an integer. */
    private const string DRIVER_CODE = '/\A[0-9]{1,18}\z/';

    /**
     * Constructor.
     *
     * @param  ?string  $recordId
     * @param  ?string  $eventCode
     * @param  \SineMacula\Laravel\AuditLog\Stores\Enums\FailedOperation  $operation
     * @param  string  $store
     * @param  string  $exceptionClass
     * @param  ?string  $sqlState
     * @param  ?int  $driverCode
     * @param  ?string  $connection
     * @param  ?string  $destination
     */
    public function __construct(

        /** The id of the record that was not written, or `null` when no one record was being worked. */
        public ?string $recordId,

        /** The record's event code, or `null` when it could not be read. */
        public ?string $eventCode,

        /** The step of the write path that failed. */
        public FailedOperation $operation,

        /** The class of the store the write failed on. */
        public string $store,

        /** The class of the exception the write failed with. */
        public string $exceptionClass,

        /** The failure's SQLSTATE, or `null` when it is not a database failure or gave none. */
        public ?string $sqlState,

        /** The driver's numeric error code, or `null` when it gave none. */
        public ?int $driverCode,

        /** The alias of the connection the write failed on, never its host or port. */
        public ?string $connection,

        /** The failed destination's id, comma-separated when several in a stack failed. */
        public ?string $destination,
    ) {}

    /**
     * The failure's diagnostics; a query exception's own connection wins, and
     * `get_debug_type()` names an anonymous class without its file.
     *
     * @param  \Throwable  $failure
     * @param  ?string  $recordId
     * @param  ?string  $eventCode
     * @param  \SineMacula\Laravel\AuditLog\Stores\Enums\FailedOperation  $operation
     * @param  string  $store
     * @param  ?string  $connection
     * @param  ?string  $destination
     * @return self
     */
    public static function of(
        #[\SensitiveParameter] \Throwable $failure,
        ?string $recordId,
        ?string $eventCode,
        FailedOperation $operation,
        string $store,
        ?string $connection = null,
        ?string $destination = null,
    ): self {
        $errorInfo = $failure instanceof \PDOException ? $failure->errorInfo : null;
        $alias     = $connection;

        if ($failure instanceof QueryException) {
            // Laravel documents a string, but a thrower can give anything
            // @phpstan-ignore function.alreadyNarrowedType
            $alias = is_string($failure->connectionName) ? $failure->connectionName : $connection;
        }

        return new self(
            $recordId,
            $eventCode,
            $operation,
            $store,
            mb_strcut(get_debug_type($failure), 0, self::CLASS_MAX_BYTES, 'UTF-8'),
            self::sqlStateOf($failure, $errorInfo),
            self::driverCodeOf($errorInfo),
            $alias,
            $destination,
        );
    }

    /**
     * A database failure's SQLSTATE, from its error information or else its
     * code.
     *
     * @param  \Throwable  $failure
     * @param  ?array<array-key, scalar|null>  $errorInfo
     * @return ?string
     */
    private static function sqlStateOf(#[\SensitiveParameter] \Throwable $failure, #[\SensitiveParameter] ?array $errorInfo): ?string
    {
        if (!$failure instanceof \PDOException) {
            return null;
        }

        foreach ([$errorInfo[0] ?? null, $failure->getCode()] as $candidate) {
            if (is_string($candidate) && preg_match(self::SQL_STATE, $candidate) === 1) {
                return $candidate;
            }
        }

        return null;
    }

    /**
     * A database failure's driver code, when an integer or a string of digits.
     *
     * @param  ?array<array-key, scalar|null>  $errorInfo
     * @return ?int
     */
    private static function driverCodeOf(#[\SensitiveParameter] ?array $errorInfo): ?int
    {
        $code = $errorInfo[1] ?? null;

        return match (true) {
            is_int($code)                                                  => $code,
            is_string($code) && preg_match(self::DRIVER_CODE, $code) === 1 => (int) $code,
            default                                                        => null,
        };
    }
}
