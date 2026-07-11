<?php

declare(strict_types=1);

/**
 * PHP FFI wrapper for libzupt.
 *
 * SPDX-License-Identifier: MIT
 */
final class ZuptFFI
{
    public const MLKEM_PUBLIC_KEY_SIZE = 1184;
    public const MLKEM_PRIVATE_KEY_SIZE = 2400;
    public const X25519_KEY_SIZE = 32;
    public const HYBRID_PUBLIC_KEY_SIZE = 1224;
    public const HYBRID_PRIVATE_KEY_SIZE = 3656;
    public const HYBRID_ENCRYPTION_HEADER_SIZE = 1137;
    public const AES_NONCE_SIZE = 16;

    private const CDEF = <<<'CDEF'
        int zupt_hybrid_keygen_c(uint8_t *pub_key, uint8_t *priv_key);
        int zupt_hybrid_export_pubkey_c(const uint8_t *priv_key, uint8_t *pub_key);

        uint8_t *zupt_read_file(const char *path, size_t *size);
        int zupt_write_file(const char *path, const uint8_t *data, size_t size);

        uint8_t *zupt_hybrid_encrypt(
            const uint8_t *pub_key,
            size_t pub_key_len,
            const uint8_t *plaintext,
            size_t plaintext_len,
            uint8_t *enc_header,
            size_t *enc_header_len,
            size_t *ciphertext_len
        );

        uint8_t *zupt_hybrid_decrypt(
            const uint8_t *priv_key,
            size_t priv_key_len,
            const uint8_t *ciphertext,
            size_t ciphertext_len,
            const uint8_t *enc_header,
            size_t enc_header_len,
            size_t *plaintext_len
        );

        void zupt_random_bytes(uint8_t *buf, size_t len);
        void zupt_sha256(const uint8_t *data, size_t len, uint8_t out[32]);
        void zupt_sha3_512(const uint8_t *data, size_t len, uint8_t out[64]);

        void free(void *ptr);
    CDEF;

    private FFI $ffi;
    private string $libraryPath;

    public function __construct(?string $libraryPath = null)
    {
        if (!extension_loaded('FFI')) {
            throw new RuntimeException('A extensão PHP FFI não está carregada.');
        }

        if (PHP_OS_FAMILY === 'Windows') {
            throw new RuntimeException(
                'Estes exemplos usam free() do runtime Unix. Execute em Linux/macOS ou adicione uma função zupt_free() à ABI para Windows.'
            );
        }

        [$this->ffi, $this->libraryPath] = $this->loadLibrary($libraryPath);
    }

    public function getLibraryPath(): string
    {
        return $this->libraryPath;
    }

    /** @return array{publicKey:string, secretKey:string} */
    public function generateKeyPair(): array
    {
        $publicKey = $this->ffi->new('uint8_t[' . self::HYBRID_PUBLIC_KEY_SIZE . ']');
        $privateKey = $this->ffi->new('uint8_t[' . self::HYBRID_PRIVATE_KEY_SIZE . ']');

        $result = $this->ffi->zupt_hybrid_keygen_c($publicKey, $privateKey);
        if ($result !== 0) {
            throw new RuntimeException('Falha ao gerar o par de chaves híbridas.');
        }

        return [
            'publicKey' => FFI::string($publicKey, self::HYBRID_PUBLIC_KEY_SIZE),
            'secretKey' => FFI::string($privateKey, self::HYBRID_PRIVATE_KEY_SIZE),
        ];
    }

    public function exportPublicKey(string $privateKey): string
    {
        $this->assertLength($privateKey, self::HYBRID_PRIVATE_KEY_SIZE, 'chave privada');

        $privateBuffer = $this->stringToBuffer($privateKey);
        $publicBuffer = $this->ffi->new('uint8_t[' . self::HYBRID_PUBLIC_KEY_SIZE . ']');

        $result = $this->ffi->zupt_hybrid_export_pubkey_c($privateBuffer, $publicBuffer);
        if ($result !== 0) {
            throw new RuntimeException('Falha ao exportar a chave pública.');
        }

        return FFI::string($publicBuffer, self::HYBRID_PUBLIC_KEY_SIZE);
    }

    /**
     * @param array{publicKey:string, secretKey:string} $keyPair
     */
    public function saveKeyPair(array $keyPair, string $privatePath, ?string $publicPath = null): void
    {
        $this->assertLength($keyPair['publicKey'] ?? '', self::HYBRID_PUBLIC_KEY_SIZE, 'chave pública');
        $this->assertLength($keyPair['secretKey'] ?? '', self::HYBRID_PRIVATE_KEY_SIZE, 'chave privada');

        $this->writeBinaryFile($privatePath, $keyPair['secretKey'], 0600);
        if ($publicPath !== null) {
            $this->writeBinaryFile($publicPath, $keyPair['publicKey'], 0644);
        }
    }

    /** @return array{publicKey:string, secretKey:string} */
    public function loadKeyPair(string $privatePath): array
    {
        $privateKey = $this->readBinaryFile($privatePath);
        $this->assertLength($privateKey, self::HYBRID_PRIVATE_KEY_SIZE, 'arquivo de chave privada');

        return [
            'publicKey' => $this->exportPublicKey($privateKey),
            'secretKey' => $privateKey,
        ];
    }

    public function loadPublicKey(string $publicPath): string
    {
        $publicKey = $this->readBinaryFile($publicPath);
        $this->assertLength($publicKey, self::HYBRID_PUBLIC_KEY_SIZE, 'arquivo de chave pública');

        return $publicKey;
    }

    /** @return array{ciphertext:string, encHeader:string} */
    public function encrypt(string $publicKey, string $plaintext): array
    {
        if ($plaintext === '') {
            throw new InvalidArgumentException('A API atual da libzupt não retorna um buffer para plaintext vazio.');
        }

        $plaintextBuffer = $this->stringToBuffer($plaintext);
        return $this->encryptPointer($publicKey, $plaintextBuffer, strlen($plaintext));
    }

    /** @return array{ciphertext:string, encHeader:string} */
    public function encryptSecure(string $publicKey, ZuptSecureBuffer $plaintext): array
    {
        if ($plaintext->size() === 0) {
            throw new InvalidArgumentException('O SecureBuffer não pode estar vazio.');
        }

        return $this->encryptPointer($publicKey, $plaintext->pointer(), $plaintext->size());
    }

    public function decrypt(
        string $privateKey,
        string $ciphertext,
        string $encHeader
    ): string {
        [$pointer, $length] = $this->decryptPointer($privateKey, $ciphertext, $encHeader);

        try {
            return FFI::string($pointer, $length);
        } finally {
            if ($length > 0) {
                FFI::memset($pointer, 0, $length);
            }
            $this->ffi->free($pointer);
        }
    }

    public function decryptSecure(
        string $privateKey,
        string $ciphertext,
        string $encHeader
    ): ZuptSecureBuffer {
        [$pointer, $length] = $this->decryptPointer($privateKey, $ciphertext, $encHeader);

        try {
            $buffer = new ZuptSecureBuffer($length);
            $buffer->copyFromPointer($pointer, $length);
            return $buffer;
        } finally {
            if ($length > 0) {
                FFI::memset($pointer, 0, $length);
            }
            $this->ffi->free($pointer);
        }
    }

    /** @return array{ciphertext:string, encHeader:string} */
    public function encryptFile(
        string $publicKey,
        string $inputPath,
        string $ciphertextPath,
        string $headerPath
    ): array {
        $plaintext = $this->readBinaryFile($inputPath);
        $encrypted = $this->encrypt($publicKey, $plaintext);

        $this->writeBinaryFile($ciphertextPath, $encrypted['ciphertext'], 0600);
        $this->writeBinaryFile($headerPath, $encrypted['encHeader'], 0600);

        return $encrypted;
    }

    public function decryptFile(
        string $privateKey,
        string $ciphertextPath,
        string $headerPath,
        string $outputPath
    ): string {
        $ciphertext = $this->readBinaryFile($ciphertextPath);
        $encHeader = $this->readBinaryFile($headerPath);
        $plaintext = $this->decrypt($privateKey, $ciphertext, $encHeader);

        $this->writeBinaryFile($outputPath, $plaintext, 0600);
        return $plaintext;
    }

    public function randomBytes(int $length): string
    {
        if ($length < 1) {
            throw new InvalidArgumentException('O tamanho deve ser maior que zero.');
        }

        $buffer = $this->ffi->new("uint8_t[$length]");
        $this->ffi->zupt_random_bytes($buffer, $length);
        return FFI::string($buffer, $length);
    }

    public function sha256(string $data): string
    {
        $input = $this->stringToBuffer($data);
        $output = $this->ffi->new('uint8_t[32]');
        $this->ffi->zupt_sha256($input, strlen($data), $output);
        return FFI::string($output, 32);
    }

    public function sha3_512(string $data): string
    {
        $input = $this->stringToBuffer($data);
        $output = $this->ffi->new('uint8_t[64]');
        $this->ffi->zupt_sha3_512($input, strlen($data), $output);
        return FFI::string($output, 64);
    }

    /**
     * @return array{ciphertext:string, encHeader:string}
     */
    private function encryptPointer(string $publicKey, FFI\CData $plaintext, int $plaintextLength): array
    {
        $this->assertLength($publicKey, self::HYBRID_PUBLIC_KEY_SIZE, 'chave pública');

        $publicKeyBuffer = $this->stringToBuffer($publicKey);
        $header = $this->ffi->new('uint8_t[' . self::HYBRID_ENCRYPTION_HEADER_SIZE . ']');
        $headerLength = $this->ffi->new('size_t[1]');
        $ciphertextLength = $this->ffi->new('size_t[1]');
        $headerLength[0] = self::HYBRID_ENCRYPTION_HEADER_SIZE;
        $ciphertextLength[0] = 0;

        $ciphertext = $this->ffi->zupt_hybrid_encrypt(
            $publicKeyBuffer,
            self::HYBRID_PUBLIC_KEY_SIZE,
            $plaintext,
            $plaintextLength,
            $header,
            $headerLength,
            $ciphertextLength
        );

        if ($ciphertext === null || FFI::isNull($ciphertext)) {
            throw new RuntimeException('Falha na criptografia híbrida da libzupt.');
        }

        $cipherLength = (int) $ciphertextLength[0];
        $actualHeaderLength = (int) $headerLength[0];

        try {
            if ($actualHeaderLength !== self::HYBRID_ENCRYPTION_HEADER_SIZE) {
                throw new RuntimeException(
                    "Header inesperado: {$actualHeaderLength} bytes; esperado: " . self::HYBRID_ENCRYPTION_HEADER_SIZE
                );
            }

            return [
                'ciphertext' => FFI::string($ciphertext, $cipherLength),
                'encHeader' => FFI::string($header, $actualHeaderLength),
            ];
        } finally {
            $this->ffi->free($ciphertext);
        }
    }

    /** @return array{0:FFI\CData,1:int} */
    private function decryptPointer(
        string $privateKey,
        string $ciphertext,
        string $encHeader
    ): array {
        $this->assertLength($privateKey, self::HYBRID_PRIVATE_KEY_SIZE, 'chave privada');
        $this->assertLength($encHeader, self::HYBRID_ENCRYPTION_HEADER_SIZE, 'header de criptografia');

        if ($ciphertext === '') {
            throw new InvalidArgumentException('O ciphertext não pode estar vazio.');
        }

        $privateKeyBuffer = $this->stringToBuffer($privateKey);
        $ciphertextBuffer = $this->stringToBuffer($ciphertext);
        $headerBuffer = $this->stringToBuffer($encHeader);
        $plaintextLength = $this->ffi->new('size_t[1]');
        $plaintextLength[0] = 0;

        $plaintext = $this->ffi->zupt_hybrid_decrypt(
            $privateKeyBuffer,
            self::HYBRID_PRIVATE_KEY_SIZE,
            $ciphertextBuffer,
            strlen($ciphertext),
            $headerBuffer,
            self::HYBRID_ENCRYPTION_HEADER_SIZE,
            $plaintextLength
        );

        if ($plaintext === null || FFI::isNull($plaintext)) {
            throw new RuntimeException(
                'Falha na descriptografia: chave incorreta, dados corrompidos ou autenticação inválida.'
            );
        }

        return [$plaintext, (int) $plaintextLength[0]];
    }

    private function stringToBuffer(string $data): FFI\CData
    {
        $length = strlen($data);
        $buffer = $this->ffi->new('uint8_t[' . max(1, $length) . ']');
        if ($length > 0) {
            FFI::memcpy($buffer, $data, $length);
        }
        return $buffer;
    }

    private function assertLength(string $data, int $expected, string $label): void
    {
        $actual = strlen($data);
        if ($actual !== $expected) {
            throw new InvalidArgumentException(
                sprintf('Tamanho inválido para %s: %d bytes; esperado: %d bytes.', $label, $actual, $expected)
            );
        }
    }

    private function readBinaryFile(string $path): string
    {
        if (!is_file($path)) {
            throw new RuntimeException("Arquivo não encontrado: {$path}");
        }

        $data = file_get_contents($path);
        if ($data === false) {
            throw new RuntimeException("Não foi possível ler o arquivo: {$path}");
        }

        return $data;
    }

    private function writeBinaryFile(string $path, string $data, int $permissions): void
    {
        $directory = dirname($path);
        if (!is_dir($directory) && !mkdir($directory, 0700, true) && !is_dir($directory)) {
            throw new RuntimeException("Não foi possível criar o diretório: {$directory}");
        }

        $bytes = file_put_contents($path, $data, LOCK_EX);
        if ($bytes === false || $bytes !== strlen($data)) {
            throw new RuntimeException("Não foi possível gravar o arquivo: {$path}");
        }

        @chmod($path, $permissions);
    }

    /** @return array{0:FFI,1:string} */
    private function loadLibrary(?string $explicitPath): array
    {
        $candidates = [];

        if ($explicitPath !== null && $explicitPath !== '') {
            $candidates[] = $explicitPath;
        }

        $environmentPath = getenv('LIBZUPT_PATH');
        if (is_string($environmentPath) && $environmentPath !== '') {
            $candidates[] = $environmentPath;
        }

        $projectRoot = dirname(__DIR__);
        foreach ([
            $projectRoot . '/build/libzupt.so',
            $projectRoot . '/build/libzupt.so.1',
            $projectRoot . '/build/libzupt.dylib',
            '/usr/local/lib64/libzupt.so',
            '/usr/local/lib/libzupt.so',
            '/usr/lib64/libzupt.so',
            '/usr/lib/libzupt.so',
            'libzupt.so.1',
            'libzupt.so',
            'libzupt.dylib',
        ] as $candidate) {
            $candidates[] = $candidate;
        }

        $candidates = array_values(array_unique($candidates));
        $errors = [];

        foreach ($candidates as $candidate) {
            if (str_contains($candidate, DIRECTORY_SEPARATOR) && !is_file($candidate)) {
                continue;
            }

            try {
                return [FFI::cdef(self::CDEF, $candidate), $candidate];
            } catch (Throwable $error) {
                $errors[] = $candidate . ': ' . $error->getMessage();
            }
        }

        $details = $errors === [] ? 'nenhum candidato existente foi encontrado' : implode("\n", $errors);
        throw new RuntimeException(
            "Não foi possível carregar a libzupt. Defina LIBZUPT_PATH=/caminho/libzupt.so.\n{$details}"
        );
    }
}

/**
 * Native buffer whose allocated bytes are wiped on zeroize/destruction.
 *
 * PHP strings created before or after this object are managed by the PHP runtime
 * and cannot be guaranteed to be erased.
 */
final class ZuptSecureBuffer
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
