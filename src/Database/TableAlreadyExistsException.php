<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\AuditLog\Database;

/**
 * Thrown when the table the shipped migration creates already exists.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class TableAlreadyExistsException extends \RuntimeException {}
