#!/usr/bin/env php
<?php

declare(strict_types=1);
require_once __DIR__ . '/Zupt.php';

$directory = sys_get_temp_dir() . '/libzupt_php_keys_' . bin2hex(random_bytes(4));

try {
    $zupt = new ZuptFFI();
    if (!mkdir($directory, 0700, true) && !is_dir($directory)) {
        throw new RuntimeException("Não foi possível criar {$directory}");
    }

    $privatePath = $directory . '/private.zupt-key';
    $publicPath = $directory . '/public.zupt-key';

    echo str_repeat('=', 60), PHP_EOL;
    echo "libzupt - Geração e gerenciamento de chaves PHP/FFI", PHP_EOL;
    echo str_repeat('=', 60), PHP_EOL, PHP_EOL;

    echo "1. Gerando par de chaves...", PHP_EOL;
    $keyPair = $zupt->generateKeyPair();
    echo '   Pública: ', strlen($keyPair['publicKey']), " bytes", PHP_EOL;
    echo '   Privada: ', strlen($keyPair['secretKey']), " bytes", PHP_EOL, PHP_EOL;

    echo "2. Salvando chaves...", PHP_EOL;
    $zupt->saveKeyPair($keyPair, $privatePath, $publicPath);
    echo "   Privada: {$privatePath}", PHP_EOL;
    echo "   Pública: {$publicPath}", PHP_EOL, PHP_EOL;

    echo "3. Exportando a chave pública a partir da privada...", PHP_EOL;
    $exportedPublic = $zupt->exportPublicKey($keyPair['secretKey']);
    if (!hash_equals($keyPair['publicKey'], $exportedPublic)) {
        throw new RuntimeException('A chave pública exportada não corresponde à original.');
    }
    echo "   Chave pública exportada corretamente.", PHP_EOL, PHP_EOL;

    echo "4. Carregando o par de chaves...", PHP_EOL;
    $loadedPair = $zupt->loadKeyPair($privatePath);
    if (!hash_equals($keyPair['publicKey'], $loadedPair['publicKey'])
        || !hash_equals($keyPair['secretKey'], $loadedPair['secretKey'])) {
        throw new RuntimeException('As chaves carregadas não correspondem às originais.');
    }
    echo "   Par de chaves validado.", PHP_EOL, PHP_EOL;

    echo "5. Carregando apenas a chave pública...", PHP_EOL;
    $loadedPublic = $zupt->loadPublicKey($publicPath);
    if (!hash_equals($keyPair['publicKey'], $loadedPublic)) {
        throw new RuntimeException('A chave pública carregada não corresponde à original.');
    }
    echo "   Chave pública validada.", PHP_EOL, PHP_EOL;

    echo "6. Tamanhos da ABI:", PHP_EOL;
    echo '   ML-KEM pública: ', ZuptFFI::MLKEM_PUBLIC_KEY_SIZE, " bytes", PHP_EOL;
    echo '   ML-KEM privada: ', ZuptFFI::MLKEM_PRIVATE_KEY_SIZE, " bytes", PHP_EOL;
    echo '   X25519: ', ZuptFFI::X25519_KEY_SIZE, " bytes", PHP_EOL;
    echo '   Híbrida pública: ', ZuptFFI::HYBRID_PUBLIC_KEY_SIZE, " bytes", PHP_EOL;
    echo '   Híbrida privada: ', ZuptFFI::HYBRID_PRIVATE_KEY_SIZE, " bytes", PHP_EOL;
    echo '   Header: ', ZuptFFI::HYBRID_ENCRYPTION_HEADER_SIZE, " bytes", PHP_EOL;

    echo PHP_EOL, str_repeat('=', 60), PHP_EOL;
    echo "Exemplo de chaves concluído!", PHP_EOL;
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
