# libzupt 2.0 — documentação em português

A libzupt oferece criptografia híbrida para arquivos e dados em memória, com
núcleo C11/C++17 e exemplos/bindings para Python, Go, Rust, Java, Node.js,
.NET e PHP. A versão 2.0.0 muda o formato e exige novas chaves.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DLIBZUPT_BUILD_PYTHON=OFF
cmake --build build --config Release --parallel 2
ctest --test-dir build -C Release --output-on-failure
```

O ML-KEM-768 foi alinhado ao FIPS 203 final. O novo envelope autentica cabeçalho,
tamanho total e todos os registros, incluindo a remoção de blocos finais
completos. O AES portátil usa uma S-box algébrica; builds compatíveis usam
AES-NI por detecção da CPU. Esses resultados não equivalem a certificação FIPS
140-3, auditoria independente ou prova completa contra canais laterais.

| Objeto da API | Tamanho / versão |
| --- | --- |
| Biblioteca | 2.0.0 |
| Chave pública | 1.224 bytes; versão 2 |
| Chave privada | 3.656 bytes; versão 2 |
| Cabeçalho | 1.137 bytes; identificador 0x03 |
| Envelope de mensagem vazia | 96 bytes |

Guarde o ciphertext e seu cabeçalho juntos. Uma falha de autenticação não é
uma mensagem vazia. Para restaurar um arquivo v1, mantenha a chave e o cabeçalho
originais e obtenha o SHA-256 do texto original completo de uma fonte confiável
independente. A ferramenta de migração confere esse hash antes de escrever
qualquer novo ciphertext; não grava o texto recuperado em arquivo temporário.

[API](../../DOCUMENTATION.md) · [Formato](../FORMAT.md) ·
[Migração](../MIGRATION.md) · [Segurança](../../SECURITY.md) ·
[Testes](../TESTING.md) · [Publicação](../RELEASING.md) · [Reavaliação](../RETEST.md)

A matriz configurada de CI precisa executar e passar antes de uma plataforma
ser divulgada como validada. Testes locais Linux não validam automaticamente
Windows, macOS, ARM64 ou todos os bindings. A nota externa depende da avaliação
do laboratório e não pode ser garantida pelo projeto.
