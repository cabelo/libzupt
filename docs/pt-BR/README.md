# Documentação do libzupt

[English](../en/README.md) · [Referência da API](../../DOCUMENTATION.md) · [Alterações](../../CHANGES.md)

## Compilar e testar

Use CMake 3.15 ou mais recente e um compilador C11/C++17. A biblioteca principal
não baixa dependências durante a compilação. Os bindings Python e os demais
exemplos de linguagens têm ferramentas e instruções próprias em seus diretórios.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DLIBZUPT_BUILD_PYTHON=OFF
cmake --build build --parallel 2
ctest --test-dir build --output-on-failure
cmake --install build --prefix "$PWD/install"
```

A opção CMake para Python atualmente adiciona o diretório de exemplos, mas não
compila a extensão Python. Siga as instruções de `examples_python` para essa etapa.
A CI Linux testa GCC e Clang. No Windows, a CI valida apenas a compilação;
os testes de arquivos existentes usam caminhos POSIX. Compilar no Windows não
equivale a validar a execução nesse sistema.

## Usar a biblioteca instalada

```cmake
cmake_minimum_required(VERSION 3.15)
project(exemplo LANGUAGES CXX)
find_package(libzupt 1.0.14 CONFIG REQUIRED)
add_executable(exemplo main.cpp)
target_link_libraries(exemplo PRIVATE libzupt::zupt_shared)
# Para vinculação estática, use libzupt::zupt_static.
```

Configure o consumidor com `-DCMAKE_PREFIX_PATH=/caminho/da/instalacao`.
Os dois targets fornecem o diretório de headers e a exigência de C++17.
`zupt::getVersion()` retorna a versão da biblioteca definida em
`libzupt_version.h`. Os testes em `tests/package` verificam ambos os targets
após mover a instalação.

```cpp
#include <zupt.hpp>

int main() {
    const auto chaves = zupt::KeyGenerator().generateKeyPair();
    zupt::Encryptor encryptor(chaves.public_key);
    const std::vector<uint8_t> mensagem = {1, 2, 3};
    const auto cifrado = encryptor.encryptMemory(mensagem);
    const auto restaurado = zupt::Decryptor(chaves.secret_key).decryptMemory(
        cifrado.first, cifrado.second);
    return restaurado == mensagem ? 0 : 1;
}
```

Guarde o ciphertext junto com seu header de criptografia correspondente.
Trate `zupt::ZuptError` como falha; nunca substitua um erro por texto vazio.

## Formato dos dados e limites de segurança

A API C++ usa chaves públicas de 1.224 bytes, chaves privadas de 3.656 bytes e
headers de criptografia de 1.137 bytes. Esses buffers de chave não incluem
checksum adicional. Os helpers antigos de arquivos de baixo nível usam outro
layout, com checksum; seus arquivos não substituem os buffers da API C++.

Cada registro cifrado contém tamanho do payload em 4 bytes little-endian,
nonce de 16 bytes, payload cifrado e HMAC de 32 bytes. O payload máximo é 4 MiB.
Na versão 1.0.14, uma mensagem vazia produz um registro autenticado de 52 bytes.
Ciphertexts antigos de zero bytes são rejeitados porque não têm autenticação.
Para migrar, criptografe novamente o conteúdo vazio original confiável; não
interprete uma falha de descriptografia como mensagem vazia. Leitores antigos
podem rejeitar o novo registro vazio autenticado. O formato dos registros de
mensagens não vazias produzidas anteriormente foi preservado.

A descriptografia verifica o MAC e o nonce esperado para a posição de cada bloco.
Rejeita reordenação/repetição de blocos, alteração do nonce do header, tamanhos
inválidos e registros vazios anexados a mensagens não vazias.
**O formato não autentica o tamanho total nem um marcador de fim da mensagem.**
Remover blocos inteiros do final ainda pode deixar um prefixo válido. Aplicações
que exigem completude devem autenticar o tamanho ou digest esperado por outro
canal ou contêiner confiável. Esta versão não declara proteção contra todo
truncamento, certificação criptográfica nem auditoria completa de todos os
bindings e implementações das primitivas.

`SecureBuffer` limpa a memória ao ser destruído e antes de receber outra alocação
por movimento; o buffer de origem fica vazio. Conversões para `std::vector` ou
`std::string` criam cópias comuns, sem limpeza automática. Em POSIX, `saveKeyPair`
usa um único descritor verificado com modo 0600 e rejeita links simbólicos,
hard links e arquivos não regulares. Guarde chaves em diretório controlado pelo
proprietário. No Windows, o chamador deve configurar as ACLs do arquivo/diretório.

## Publicação e estatísticas do projeto

Use a próxima versão sequencial e mantenha `include/libzupt_version.h`, a tag e
a entrada mais recente de `CHANGES.md` alinhados. Assine todos os novos commits
com GPG e crie uma tag assinada, por exemplo:
`git tag -s v1.0.14 -m "Release libzupt 1.0.14"`.
Verifique com `git verify-commit HEAD` e `git verify-tag v1.0.14`.

Execute os testes acima e os testes do pacote instalado antes de empacotar:

```sh
cmake -S tests/package -B consumer -DCMAKE_PREFIX_PATH="$PWD/install"
cmake --build consumer --parallel 2
ctest --test-dir consumer --output-on-failure
python3 scripts/package-release.py v1.0.14 ../libzupt-1.0.14-release
```

O script exige o compressor `zupt` instalado localmente, verifica a tag assinada
e a versão, exporta o código da tag e cria pacotes de fontes `.tar.gz` e `.zupt`
fora do checkout. Usa nível 9 e modo solid, inclui as mudanças atuais no comentário,
testa/extrai o arquivo, compara o tar restaurado e gera `SHA256SUMS`.
O `.zupt` contém um tar de fontes: extraia o arquivo e depois descompacte o tar.
Trata-se de código-fonte, não de biblioteca pré-compilada. Nenhum token ou chave
de assinatura é incluído nos pacotes.

O workflow de tags valida a compilação e disponibiliza artefatos binários Linux.
Ele não publica como bot. Autentique o `gh` localmente como o mantenedor que fará
a publicação, confira `gh api user --jq .login` e configure a autenticação Git
HTTPS com `gh auth setup-git`. Envie a branch e a tag assinadas, aguarde a validação
e publique com o token do mantenedor:

```sh
gh release create v1.0.14 --verify-tag --title "libzupt 1.0.14" \
  --notes-file ../libzupt-1.0.14-release/release-notes.txt \
  ../libzupt-1.0.14-release/libzupt-1.0.14-src.tar.gz \
  ../libzupt-1.0.14-release/libzupt-1.0.14-src.zupt \
  ../libzupt-1.0.14-release/SHA256SUMS
```

Os resumos da CI mostram commit, plataforma/compilador e resultados reais do CTest.
Os pacotes informam tamanho em bytes e SHA-256. Mantenha estatísticas geradas,
saídas de compilação e notas de auditoria fora do controle de versão; nunca
apresente verificações não executadas como aprovadas.
