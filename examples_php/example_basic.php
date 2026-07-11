#!/usr/bin/env php
<?php

declare(strict_types=1);
require_once __DIR__ . '/Zupt.php';

try {
    $zupt = new ZuptFFI();

    echo str_repeat('=', 60), PHP_EOL;
    echo "libzupt - Exemplo básico PHP/FFI", PHP_EOL;
    echo str_repeat('=', 60), PHP_EOL, PHP_EOL;
    echo "Biblioteca: {$zupt->getLibraryPath()}", PHP_EOL, PHP_EOL;

    echo "1. Gerando par de chaves...", PHP_EOL;
    $keyPair = $zupt->generateKeyPair();
    echo '   Chave pública: ', strlen($keyPair['publicKey']), " bytes", PHP_EOL;
    echo '   Chave privada: ', strlen($keyPair['secretKey']), " bytes", PHP_EOL, PHP_EOL;

    $message = 'Hello, Post-Quantum World! This is a secret message.';
    echo "2. Criptografando: {$message}", PHP_EOL;
    $encrypted = $zupt->encrypt($keyPair['publicKey'], $message);
    echo '   Ciphertext: ', strlen($encrypted['ciphertext']), " bytes", PHP_EOL;
    echo '   Header: ', strlen($encrypted['encHeader']), " bytes", PHP_EOL, PHP_EOL;

    echo "3. Descriptografando...", PHP_EOL;
    $decrypted = $zupt->decrypt(
        $keyPair['secretKey'],
        $encrypted['ciphertext'],
        $encrypted['encHeader']
    );
    echo "   Resultado: {$decrypted}", PHP_EOL, PHP_EOL;

    if (!hash_equals($message, $decrypted)) {
        throw new RuntimeException('A mensagem descriptografada não corresponde à original.');
    }
    echo "4. Verificação: SUCESSO", PHP_EOL, PHP_EOL;

    echo "5. Testando uma chave incorreta...", PHP_EOL;
    $wrongKeyPair = $zupt->generateKeyPair();
    $wrongKeyRejected = false;
    try {
        $zupt->decrypt(
            $wrongKeyPair['secretKey'],
            $encrypted['ciphertext'],
            $encrypted['encHeader']
        );
    } catch (RuntimeException $error) {
        $wrongKeyRejected = true;
        echo "   Rejeitada corretamente: {$error->getMessage()}", PHP_EOL;
    }

    if (!$wrongKeyRejected) {
        throw new RuntimeException('A descriptografia com chave incorreta deveria ter falhado.');
    }

    echo PHP_EOL, str_repeat('=', 60), PHP_EOL;
    echo "Exemplo concluído com sucesso!", PHP_EOL;
    echo str_repeat('=', 60), PHP_EOL;
} catch (Throwable $error) {
    fwrite(STDERR, 'ERRO: ' . $error->getMessage() . PHP_EOL);
    exit(1);
}
