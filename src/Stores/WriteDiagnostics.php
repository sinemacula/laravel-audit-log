<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Stores;

use Illuminate\Database\QueryException;
use SineMacula\Laravel\AuditLog\Stores\Enums\FailedOperation;

/**
 * What may be said about a failed write without saying anything of the record:
 * the record's id and code, the operation that failed, the store and the
 * exception's class, and, for a database failure, its SQLSTATE, its numeric
 * driver code and the connection's alias. A failure that stopped a drain before
 * any one record was read has no id.
 *
 * It is the only reader of a caught write failure, and reads nothing else of
 * it: never its message, its SQL, its bindings or the driver's message, any of
 * which can hold the record's values, and never its previous exception. A class
 * is named by `get_debug_type()`, so an anonymous class is named by what it
 * extends and never by the file that declares it.
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

        /** The id of the destination that failed, for a delivery to one of several; several ids separated by commas when a stack's destinations failed together. */
        public ?string $destination,
    ) {}

    /**
     * The diagnostics of the failure, read from its class, its SQLSTATE, its
     * driver code and its connection's alias alone. A query exception's own
     * connection replaces the one given.
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
            // Laravel documents a string, but the alias is whatever the code
            // that threw the query exception gave it.
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
     * A database failure's SQLSTATE: the first element of its error
     * information, or else its code, whichever is a SQLSTATE first.
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
     * A database failure's driver code, the second element of its error
     * information, when it is an integer or a string of digits.
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
