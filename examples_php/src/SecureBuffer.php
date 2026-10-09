<?php

declare(strict_types = 1);

namespace Zupt;

use \FFI;

/**
 * Native buffer whose allocated bytes are wiped on zeroize/destruction.
 *
 * PHP strings created before or after this object are managed by the PHP runtime
 * and cannot be guaranteed to be erased.
 */

final class SecureBuffer
{
    private FFI\CData $buffer;
    private int $length;
    private bool $zeroized = false;

    public function __construct(string|int $source)
    {
        if (is_int($source)) {
            if ($source < 0) {
                throw new InvalidArgumentException('O tamanho do buffer não pode ser negativo.');
            }
            $this->length = $source;
            $this->buffer = FFI::new('uint8_t[' . max(1, $source) . ']');
            if ($source > 0) {
                FFI::memset($this->buffer, 0, $source);
            }
            $this->zeroized = true;
            return;
        }

        $this->length = strlen($source);
        $this->buffer = FFI::new('uint8_t[' . max(1, $this->length) . ']');
        if ($this->length > 0) {
            FFI::memcpy($this->buffer, $source, $this->length);
            $this->zeroized = false;
        } else {
            $this->zeroized = true;
        }
    }

    public function size(): int
    {
        return $this->length;
    }

    public function pointer(): FFI\CData
    {
        return $this->buffer;
    }

    public function toString(): string
    {
        return $this->length === 0 ? '' : FFI::string($this->buffer, $this->length);
    }

    public function copyFromPointer(FFI\CData $source, int $length): void
    {
        if ($length < 0 || $length > $this->length) {
            throw new InvalidArgumentException('Tamanho inválido para cópia no SecureBuffer.');
        }

        if ($length > 0) {
            FFI::memcpy($this->buffer, $source, $length);
            $this->zeroized = false;
        }
    }

    public function zeroize(): void
    {
        if ($this->length > 0 && !$this->zeroized) {
            FFI::memset($this->buffer, 0, $this->length);
        }
        $this->zeroized = true;
    }

    public function isZeroized(): bool
    {
        if (!$this->zeroized) {
            return false;
        }

        for ($index = 0; $index < $this->length; $index++) {
            if ($this->buffer[$index] !== 0) {
                return false;
            }
        }
        return true;
    }

    public function __destruct()
    {
        $this->zeroize();
    }

    private function __clone(): void
    {
    }
}
