#!/usr/bin/env php
<?php

declare(strict_types=1);
require_once __DIR__ . '/Zupt.php';

$directory = sys_get_temp_dir() . '/libzupt_php_file_' . bin2hex(random_bytes(4));

try {
    $zupt = new ZuptFFI();
    if (!mkdir($directory, 0700, true) && !is_dir($directory)) {
        throw new RuntimeException("Não foi possível criar {$directory}");
    }

    $inputPath = $directory . '/secret.txt';
    $cipherPath = $directory . '/secret.txt.enc';
    $headerPath = $directory . '/secret.txt.header';
    $outputPath = $directory . '/secret.decrypted.txt';

    $original = "This is a secret text file.\n"
        . "Line 2: Contains sensitive information.\n"
        . "Line 3: End of file.\n";
    file_put_contents($inputPath, $original, LOCK_EX);

    echo str_repeat('=', 60), PHP_EOL;
    echo "libzupt - Exemplo de arquivo PHP/FFI", PHP_EOL;
    echo str_repeat('=', 60), PHP_EOL, PHP_EOL;

    echo "1. Gerando chaves...", PHP_EOL;
    $keyPair = $zupt->generateKeyPair();

    echo "2. Arquivo criado: {$inputPath}", PHP_EOL;
    echo $original, PHP_EOL;

    echo "3. Criptografando arquivo...", PHP_EOL;
    $encrypted = $zupt->encryptFile(
        $keyPair['publicKey'],
        $inputPath,
        $cipherPath,
        $headerPath
    );
    echo '   Ciphertext: ', strlen($encrypted['ciphertext']), " bytes", PHP_EOL;
    echo '   Header: ', strlen($encrypted['encHeader']), " bytes", PHP_EOL;

    echo "4. Descriptografando arquivo...", PHP_EOL;
    $decrypted = $zupt->decryptFile(
        $keyPair['secretKey'],
        $cipherPath,
        $headerPath,
        $outputPath
    );
    echo "   Arquivo restaurado: {$outputPath}", PHP_EOL;

    if (!hash_equals($original, $decrypted)) {
        throw new RuntimeException('O arquivo restaurado difere do original.');
    }

    echo "5. Verificação: SUCESSO", PHP_EOL;
    echo PHP_EOL, str_repeat('=', 60), PHP_EOL;
    echo "Exemplo de arquivo concluído!", PHP_EOL;
    echo str_repeat('=', 60), PHP_EOL;
} catch (Throwable $error) {
    fwrite(STDERR, 'ERRO: ' . $error->getMessage() . PHP_EOL);
    exit(1);
} finally {
    if (is_dir($directory)) {
        foreach (glob($directory . '/*') ?: [] as $file) {
            @unlink($file);
        }
        @rmdir($directory);
    }
}
