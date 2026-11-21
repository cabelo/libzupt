/*
 * libzupt - Python bindings with pybind11
 * SPDX-License-Identifier: MIT
 */

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/iostream.h>

#include "zupt.hpp"

/**
 * @file  examples_python/zupt_pybind.cpp
 * @brief Binding Python da camada C++ da libzupt, usando pybind11.
 * @details Este TU compila o módulo nativo `zupt` (target CMake
 *          `zupt_python_bindings`, `OUTPUT_NAME zupt` em
 *          `examples_python/CMakeLists.txt`) e espelha a API de
 *          `include/zupt.hpp` sem adicionar lógica própria de criptografia.
 *          São exportados: o enum `ErrorCode`, a exceção `ZuptError`,
 *          onze constantes de tamanho, as classes `SecureBuffer`, `KeyPair`,
 *          `KeyGenerator`, `Encryptor` e `Decryptor`, e as funções de módulo
 *          `random_bytes`, `sha256`, `sha3_512` e `secure_wipe`.
 *
 *          <b>Fronteira de tipos</b>: a maioria dos dados binários entra e sai
 *          como `bytes` (via `py::bytes`), convertida para `std::string` e
 *          reinterpretada como `const uint8_t*`. `pybind11/stl.h` converte
 *          automaticamente `std::vector<uint8_t>` para `list` de `int`, de modo
 *          que nem todo dado binário chega como `bytes`: o que o método devolve
 *          sem conversão explícita para `py::bytes` chega como `list` de inteiros
 *          (por exemplo `KeyPair.public_key`, `load_public_key`, `encrypt_secure`
 *          e `decrypt_memory`). Ver os blocos de cada método e o arquivo de
 *          achados.
 *
 *          <b>Erros</b>: este TU não captura exceções de libzupt fora dos dois
 *          `catch (...)` dos construtores de `SecureBuffer` e de `decrypt`.
 *          `zupt::ZuptError` é registrada por `py::register_exception` e o
 *          pybind11 a converte em exceção Python da classe `zupt.ZuptError`,
 *          derivada de `RuntimeError`. Qualquer outra exceção C++ não
 *          registrada se converte em `RuntimeError` genérico do pybind11, e
 *          `py::error_already_set` (erro já pendente em Python) é devolvida ao
 *          interpretador.
 *
 *          <b>Propriedade de memória</b>: as classes C++ são gerenciadas pelo
 *          pybind11, que destrói o objeto C++ quando o objeto Python morre
 *          (referência forte do Python para a instância C++). `SecureBuffer`
 *          zera o próprio conteúdo no destrutor. Os ponteiros expostos por
 *          `data_ptr` e `data_ptr_const` são ponteiros internos e ficam
 *          inválidos quando o objeto Python é destruído ou movido.
 */

/**
 * @namespace py
 * @brief Alias de namespace para `pybind11`, usado em todo o arquivo.
 * @details É apenas um apelido; não introduz símbolos próprios.
 */
namespace py = pybind11;

/**
 * @brief Macro de definição do módulo nativo `zupt`.
 * @details `PYBIND11_MODULE(zupt, m)` expande para a função de registro
 *          chamada pelo interpretador no `import zupt`. O primeiro argumento
 *          (`zupt`) deve coincidir com o nome do módulo importável (o
 *          `OUTPUT_NAME` do target CMake); o segundo é a referência ao objeto
 *          de módulo. Todo o restante deste arquivo acontece dentro desta
 *          função: registro de tipos, constantes e funções livres.
 *          <b>Ordem de registro</b>: primeiro o enum `ErrorCode`, depois a
 *          exceção, depois as constantes, depois as classes e por fim as
 *          funções e atributos de versão. A ordem não é apenas cosmética: um
 *          tipo referenciado por assinatura de função precisa estar registrado
 *          antes do uso, o que aqui é garantido porque as classes precedem as
 *          funções que usam `SecureBuffer`.
 *          <b>Erros de registro</b>: `m.def`/`py::class_` lançam se o nome já
 *          existe ou se há incompatibilidade de tipo; não há tratamento de erro
 *          e o `import` simplesmente falha.
 * - `m`: Objeto de módulo Python em construção (`py::module_&`). * @note O docstring do módulo é definido como
 *       "libzupt - Hybrid Post-Quantum Encryption Library".
 */
PYBIND11_MODULE(zupt, m) {
    m.doc() = "libzupt - Hybrid Post-Quantum Encryption Library";

    // Error codes
    /**
     * @brief Espelho Python do enum `zupt::ErrorCode`.
     * @details Registra as 12 constantes com os mesmos nomes usados em C++ e
     *          aplica `export_values()`, o que coloca cada constante também no
     *          namespace do módulo (`zupt.ERR_IO`, além de
     *          `zupt.ErrorCode.ERR_IO`). Os valores numéricos são os da
     *          definição em `include/zupt.hpp`: `OK = 0` e os demais negativos,
     *          de `ERR_IO = -1` até `ERR_AUTH_FAIL = -11`.
     *          <b>Mapeamento</b>:
     *          - `OK` (0): sucesso;
     *          - `ERR_IO` (-1): falha de abrir/ler/escrever/arquivo;
     *          - `ERR_CORRUPT` (-2): estrutura interna inconsistente;
     *          - `ERR_BAD_MAGIC` (-3): assinatura de formato ausente/diferente;
     *          - `ERR_BAD_VERSION` (-4): versão de formato não suportada;
     *          - `ERR_BAD_CHECKSUM` (-5): soma de verificação divergente;
     *          - `ERR_NOMEM` (-6): alocação falhou;
     *          - `ERR_OVERFLOW` (-7): tamanho acima do suportado;
     *          - `ERR_INVALID` (-8): argumento/buffer inválido;
     *          - `ERR_NOT_FOUND` (-9): item inexistente;
     *          - `ERR_UNSUPPORTED` (-10): operação não suportada nesta build;
     *          - `ERR_AUTH_FAIL` (-11): MAC/GCM do envelope não validou.
     *          @note Nenhum caminho deste binding entrega um `ErrorCode`
     *          numérico ao chamador: a camada C++ sinaliza falha por exceção e
     *          `py::register_exception` não expõe o método `code()` de
     *          `zupt::ZuptError`, de modo que em Python a exceção carrega apenas
     *          a mensagem. As constantes registradas aqui, portanto, só têm uso
     *          comparativo explícito (ver arquivo de achados).
     *          \see include/zupt.hpp (enum `zupt::ErrorCode`)
     */
    py::enum_<zupt::ErrorCode>(m, "ErrorCode")
        .value("OK", zupt::ErrorCode::OK)
        .value("ERR_IO", zupt::ErrorCode::ERR_IO)
        .value("ERR_CORRUPT", zupt::ErrorCode::ERR_CORRUPT)
        .value("ERR_BAD_MAGIC", zupt::ErrorCode::ERR_BAD_MAGIC)
        .value("ERR_BAD_VERSION", zupt::ErrorCode::ERR_BAD_VERSION)
        .value("ERR_BAD_CHECKSUM", zupt::ErrorCode::ERR_BAD_CHECKSUM)
        .value("ERR_NOMEM", zupt::ErrorCode::ERR_NOMEM)
        .value("ERR_OVERFLOW", zupt::ErrorCode::ERR_OVERFLOW)
        .value("ERR_INVALID", zupt::ErrorCode::ERR_INVALID)
        .value("ERR_NOT_FOUND", zupt::ErrorCode::ERR_NOT_FOUND)
        .value("ERR_UNSUPPORTED", zupt::ErrorCode::ERR_UNSUPPORTED)
        .value("ERR_AUTH_FAIL", zupt::ErrorCode::ERR_AUTH_FAIL)
        .export_values();

    // A real Python exception type, also catchable as RuntimeError.
    /**
     * @brief Registra `zupt.ZuptError` como tipo de exceção Python.
     * @details `py::register_exception` cria, no módulo, uma classe de exceção
     *          que o pybind11 usa para lançar `std::exception` derivada de
     *          `zupt::ZuptError`. O terceiro argumento, `PyExc_RuntimeError`, é
     *          a base da nova classe: `except RuntimeError` continua
     *          capturando as falhas de libzupt. O texto da exceção é o que
     *          `std::runtime_error::what()` devolve.
     *          \warning o atributo `code()` de `zupt::ZuptError` não é
     *          transportado para Python: o registro não gera bindings da classe,
     *          apenas da exceção. Em Python, o código de erro (enum
     *          `ErrorCode` acima) não é consultável.
     */
    py::register_exception<zupt::ZuptError>(m, "ZuptError", PyExc_RuntimeError);

    // Constants
    /**
     * @brief Expõe as constantes `constexpr` de `include/zupt.hpp` como
     *        atributos de módulo.
     * @details Cada linha atribui um `size_t` do C++ a um atributo Python, que
     *          o pybind11 converte em `int` imutável. Os valores são:
     *          `MLKEM_PUBLICKEYBYTES = 1184`, `MLKEM_SECRETKEYBYTES = 2400`,
     *          `MLKEM_CIPHERTEXTBYTES = 1088`, `MLKEM_SSBYTES = 32`,
     *          `X25519_KEYBYTES = 32`, `HYBRID_PUB_KEY_SIZE = 1224`,
     *          `HYBRID_PRIV_KEY_SIZE = 3656`, `HYBRID_ENC_HEADER_SIZE = 1137`,
     *          `AES_KEY_SIZE = 32`, `AES_NONCE_SIZE = 16` e `HMAC_SIZE = 32`.
     *          @note a atribuição cria cópias: mudar o valor em Python não afeta
     *          a biblioteca, e a biblioteca não valida que o chamador use os
     *          tamanhos corretos — o erro aparece mais tarde, como exceção.
     */
    m.attr("MLKEM_PUBLICKEYBYTES") = zupt::MLKEM_PUBLICKEYBYTES;
    m.attr("MLKEM_SECRETKEYBYTES") = zupt::MLKEM_SECRETKEYBYTES;
    m.attr("MLKEM_CIPHERTEXTBYTES") = zupt::MLKEM_CIPHERTEXTBYTES;
    m.attr("MLKEM_SSBYTES") = zupt::MLKEM_SSBYTES;
    m.attr("X25519_KEYBYTES") = zupt::X25519_KEYBYTES;
    m.attr("HYBRID_PUB_KEY_SIZE") = zupt::HYBRID_PUB_KEY_SIZE;
    m.attr("HYBRID_PRIV_KEY_SIZE") = zupt::HYBRID_PRIV_KEY_SIZE;
    m.attr("HYBRID_ENC_HEADER_SIZE") = zupt::HYBRID_ENC_HEADER_SIZE;
    m.attr("AES_KEY_SIZE") = zupt::AES_KEY_SIZE;
    m.attr("AES_NONCE_SIZE") = zupt::AES_NONCE_SIZE;
    m.attr("HMAC_SIZE") = zupt::HMAC_SIZE;

    // SecureBuffer class
    /**
     * @brief Registra a classe C++ `zupt::SecureBuffer` como `SecureBuffer` em Python.
     * @details Sem `py::buffer_protocol`: o objeto não é conversível de/para
     *          `memoryview` nem aceita `numpy`, de modo que toda entrada e saída
     *          binária passa pelos métodos `to_bytes`, `to_string`, `__len__` e
     *          pelos dois construtores. O pybind11 é quem destrói o objeto C++
     *          quando a referência Python morre, e o destrutor de
     *          `zupt::SecureBuffer` chama `zeroize()`.
     *          \note não há `__eq__`, `__bool__` nem `__getstate__` registrados:
     *          dois objetos nunca comparam iguais por valor, e o objeto não é
     *          serializável com `pickle` (o pybind11 gera erro para tipos sem
     *          suporte).
     *          \see include/zupt.hpp (classe `zupt::SecureBuffer`)
     */
    py::class_<zupt::SecureBuffer>(m, "SecureBuffer")
        /**
         * @brief Construtor `SecureBuffer(size)`.
         * @details Encaminha para `zupt::SecureBuffer(size_t)`, que aloca o
         *          buffer sem inicializar o conteúdo: os `size` bytes ficam com
         *          valores indefinidos até serem escritos. A conversão do
         *          argumento é feita pelo pybind11, que rejeita valores
         *          negativos e acima de `sys.maxsize` com `OverflowError` ou
         *          `TypeError`. Falha de alocação se manifesta como
         *          `std::bad_alloc` convertido pelo pybind11 em exceção
         *          `RuntimeError` (nenhuma conversão própria para `MemoryError`
         *          é registrada neste arquivo).
         * - `size`: Quantidade de bytes a alocar.         */
        .def(py::init<size_t>())
        /**
         * @brief Construtor flexível `SecureBuffer(data)`.
         * @details Lambda de fábrica com dois ramos encadeados por `try` /
         *          `catch (...)`:
         * - primeiro ramo: `data.cast<py::bytes>()` seguido de
         *   `.cast<std::string>()`, com os bytes passados a
         *   `zupt::SecureBuffer(const uint8_t*, size_t)` por
         *   `reinterpret_cast`;
         * - segundo ramo (somente se o primeiro lançou qualquer
         *   coisa): `data.cast<py::list>()` e elemento a elemento
         *   `py::cast<uint8_t>`, o que rejeita valores fora de
         *   `0..255`, seguido de `zupt::SecureBuffer(std::vector)`.
         *          <b>Cópia</b>: os dois caminhos copiam os bytes para o buffer
         *          interno; o objeto Python de origem pode ser alterado depois
         *          sem afetar o `SecureBuffer`.
         *          \warning o `catch (...)` engolfa todas as causas: um erro
         *          Python já pendente (por exemplo `MemoryError`) ou um
         *          `bytes` válido que falhe na etapa seguinte cai no ramo de
         *          lista e produz mensagem enganosa.
         *          \warning o `std::string` intermediário do primeiro ramo não
         *          é zerado, de modo que permanece uma cópia do material em
         *          claro no heap até a liberação da string C++.
         * - `data`: Conteúdo inicial: o código aceita `bytes` (primeiro ramo)         *             ou sequência de inteiros convertível a `list` (segundo
         *             ramo).
         */
        .def(py::init([](py::object data) {
            // Try to handle bytes first
            try {
                py::bytes data_bytes = data.cast<py::bytes>();
                std::string data_str = data_bytes.cast<std::string>();
                return new zupt::SecureBuffer(
                    reinterpret_cast<const uint8_t*>(data_str.data()),
                    data_str.size()
                );
            } catch (...) {
                // Fall back to list of integers
                py::list data_list = data.cast<py::list>();
                std::vector<uint8_t> vec(data_list.size());
                for (size_t i = 0; i < data_list.size(); ++i) {
                    vec[i] = py::cast<uint8_t>(data_list[i]);
                }
                return new zupt::SecureBuffer(vec);
            }
        }))
        /**
         * @brief `size()` — devolve o tamanho do buffer em bytes.
         * @details Encaminhamento direto para `zupt::SecureBuffer::size()`, que
         *          devolve `size_` (zero depois de um movimento). Equivalente a
         *          `len(objeto)`, pois `__len__` aponta para o mesmo método.
         * @return Inteiro com o tamanho em bytes.
         */
        .def("size", &zupt::SecureBuffer::size)
        /**
         * @brief `data_ptr()` — devolve o ponteiro interno como inteiro.
         * @details O cast `(uint8_t*(zupt::SecureBuffer::*)())` seleciona a
         *          sobrecarga não-const de `data()`. O pybind11 converte o
         *          `uint8_t*` retornado em um `int` de endereço.
         *          \warning expor o endereço interno da chave/Texto em claro é
         *          um vazamento de endereço e permite interação com outras
         *          APIs que aceitam inteiros como ponteiros (por exemplo
         *          `secure_wipe` deste mesmo módulo). O endereço vale apenas
         *          enquanto o objeto Python estiver vivo e não for movido.
         * @return Endereço de memória do buffer interno como inteiro.
         */
        .def("data_ptr", (uint8_t*(zupt::SecureBuffer::*)()) &zupt::SecureBuffer::data)
        /**
         * @brief `data_ptr_const()` — mesmo ponteiro, via sobrecarga const.
         * @details O cast
         *          `(const uint8_t*(zupt::SecureBuffer::*)() const)` seleciona a
         *          sobrecarga `const` de `data()`. Em Python não há diferença
         *          observável de mutabilidade: o retorno é apenas um inteiro, e
         *          o resultado é o mesmo endereço devolvido por `data_ptr()`.
         * @return Endereço de memória do buffer interno como inteiro.
         * @see data_ptr
         */
        .def("data_ptr_const", (const uint8_t*(zupt::SecureBuffer::*)() const) &zupt::SecureBuffer::data)
        /**
         * @brief `to_bytes()` — cópia do conteúdo como `bytes`.
         * @details Lambda que constrói `py::bytes` a partir de
         *          `self.data()` e `self.size()`, o que copia os bytes para um
         *          novo objeto imutável de Python. O conteúdo devolvido é
         *          independente do buffer interno.
         *          \warning o objeto `bytes` devolvido é exatamente o texto em
         *          claro e não pode ser zerado pelo chamador; `zeroize()` ou a
         *          destruição do `SecureBuffer` não o alcança.
         * @return Objeto `bytes` com os `size()` bytes do buffer.
         */
        .def("to_bytes", [](const zupt::SecureBuffer& self) {
            return py::bytes(reinterpret_cast<const char*>(self.data()), self.size());
        })
        /**
         * @brief `to_string()` — mesmo conteúdo que `to_bytes()`.
         * @details Encaminhamento para `zupt::SecureBuffer::toString()`, que
         *          copia os bytes para um `std::string`; o pybind11 converte esse
         *          `std::string` em `str` de Python decodificando como UTF-8.
         *          \warning conteúdo binário aleatório quase sempre não é UTF-8
         *          válido, então o uso normal desta função lança `UnicodeDecodeError`.
         *          Para bytes use `to_bytes()`.
         * @return `str` com o conteúdo, quando decodificável como UTF-8.
         * @see to_bytes
         */
        .def("to_string", &zupt::SecureBuffer::toString)
        /**
         * @brief `zeroize()` — zera o conteúdo do buffer.
         * @details Encaminhamento para `zupt::SecureBuffer::zeroize()`, que
         *          aplica `zupt::secureWipe` (escrita via `volatile`). Não afeta
         *          cópias já devolvidas por `to_bytes()`/`to_string()`.
         */
        .def("zeroize", &zupt::SecureBuffer::zeroize)
        /**
         * @brief `len(objeto)` — mesmo que `size()`.
         * @details Aponta o protocolo de comprimento para
         *          `zupt::SecureBuffer::size`, de modo que `len(buf)` e
         *          `buf.size()` são equivalentes. Não há `__getitem__` nem
         *          `__iter__` registrados, então `len()` não implica indexação.
         * @return Inteiro com o tamanho em bytes.
         */
        .def("__len__", &zupt::SecureBuffer::size)
        /**
         * @brief `repr(objeto)` — descrição textual do objeto.
         * @details Devolve a cadeia `<SecureBuffer size=N>`, onde N é
         *          `self.size()`. Nenhum byte do conteúdo aparece no resultado,
         *          o que evita exposição acidental em logs e `print`.
         * @return `str` com o formato `<SecureBuffer size=N>`.
         */
        .def("__repr__", [](const zupt::SecureBuffer& self) {
            return "<SecureBuffer size=" + std::to_string(self.size()) + ">";
        });

    // KeyPair struct
    /**
     * @brief Registra a struct `zupt::KeyPair` como `KeyPair` em Python.
     * @details Expõe os dois membros como atributos somente leitura
     *          (`def_readonly`). Como `public_key` e `secret_key` são
     *          `std::vector<uint8_t>`, o pybind11 (via `pybind11/stl.h`) os
     *          converte em `list` de `int`, e não em `bytes`: cada acesso
     *          produz uma lista nova, copiada dos vetores C++.
     *          \warning atributos `def_readonly` não impedem mutação do objeto
     *          Python recebido (`list.append` funciona), mas a mudança não é
     *          refletida no `KeyPair` C++, pois a lista é uma cópia.
     *          \warning o `std::vector` de chave privada permanece em claro no
     *          objeto C++ e o `list` de Python não tem como ser zerado.
     */
    py::class_<zupt::KeyPair>(m, "KeyPair")
        /**
         * @brief `KeyPair()` — construtor padrão.
         * @details Encaminha para `zupt::KeyPair()`. Os dois vetores ficam
         *          vazios, de modo que `len(kp.public_key) == 0` logo após a
         *          criação.
         */
        .def(py::init<>())
        /** Chave pública híbrida, devolvida como `list` de inteiros. */
        .def_readonly("public_key", &zupt::KeyPair::public_key)
        /** Chave secreta híbrida, devolvida como `list` de inteiros. */
        .def_readonly("secret_key", &zupt::KeyPair::secret_key);

    // KeyGenerator class
    /**
     * @brief Registra a classe C++ `zupt::KeyGenerator` como `KeyGenerator`.
     * @details As assinaturas Python divergem do nome C++ apenas na convenção
     *          (`snake_case` contra `camelCase`): `generate_keypair`,
     *          `load_keypair`, `load_public_key`, `export_public_key` e
     *          `save_keypair`. Nenhum `py::arg` nomeia os parâmetros, então o
     *          chamador só pode passar valores posicionalmente: tentar usar
     *          palavras-chave levanta `TypeError`.
     *          \note `save_keypair` e `export_public_key` escrevem em disco no
     *          caminho informado pelo chamador; não há validação deste lado.
     */
    py::class_<zupt::KeyGenerator>(m, "KeyGenerator")
        /**
         * @brief `KeyGenerator()` — construtor vazio.
         * @details Encaminha para `zupt::KeyGenerator()`, que não recebe
         *          parâmetros.
         */
        .def(py::init<>())
        /**
         * @brief `generate_keypair()` — gera um par de chaves híbrido.
         * @details Encaminhamento direto. O retorno é uma cópia da struct C++
         *          convertida em objeto `KeyPair` de Python.
         *          \warning ao contrário do binding Node.js, nenhum
         *          `secureWipe` é aplicado ao `zupt::KeyPair` C++ local: ele é
         *          convertido e depois destruído sem limpeza explícita.
         * @return Objeto `KeyPair` com as chaves geradas.
         */
        .def("generate_keypair", &zupt::KeyGenerator::generateKeyPair)
        /**
         * @brief `load_keypair(filename)` — lê keypair de arquivo.
         * @details Encaminhamento direto para `zupt::KeyGenerator::loadKeyPair`.
         *          Falhas de leitura/versão/magic chegam como exceção
         *          `ZuptError` em Python.
         * - `filename`: Caminho do arquivo de chave privada híbrida.         * @return Objeto `KeyPair` carregado.
         */
        .def("load_keypair", &zupt::KeyGenerator::loadKeyPair)
        /**
         * @brief `load_public_key(filename)` — lê chave pública de arquivo.
         * @details Encaminhamento direto. Como o retorno é `std::vector<uint8_t>`,
         *          o pybind11 o entrega como `list` de inteiros, e não como
         *          `bytes`.
         *          \warning inconsistência com os métodos de cifra, que devolvem
         *          `bytes`: aqui o chamador precisa de `bytes(load_public_key(...))`
         *          para obter um `bytes`, e `bytes(list_de_ints)` funciona apenas
         *          se todos os valores estiverem em `0..255`.
         * - `filename`: Caminho do arquivo de chave pública híbrida.         * @return `list` de inteiros com a chave pública lida.
         */
        .def("load_public_key", &zupt::KeyGenerator::loadPublicKey)
        /**
         * @brief `export_public_key(privfile, pubfile)` — extrai a chave pública.
         * @details Encaminhamento para
         *          `zupt::KeyGenerator::exportPublicKey(privfile, pubfile)`: lê a
         *          keypair privada de `privfile` e escreve apenas a parte pública
         *          em `pubfile`. Nenhum valor é devolvido.
         *          \warning sobrescreve `pubfile` sem aviso, e ambos os
         *          caminhos vêm direto do chamador, sem validação.
         * - `privfile`: Caminho do arquivo de chave privada híbrida.         * - `pubfile`: Caminho do arquivo público de saída.         */
        .def("export_public_key", &zupt::KeyGenerator::exportPublicKey)
        /**
         * @brief `save_keypair(keypair, filename)` — persiste a keypair.
         * @details Encaminhamento para
         *          `zupt::KeyGenerator::saveKeyPair(const KeyPair&, const std::string&)`.
         *          O primeiro argumento é o objeto `KeyPair` registrado pelo
         *          pybind11, de modo que a função C++ recebe a instância
         *          original, e não uma cópia convertida.
         *          \warning não há checagem de que o objeto foi gerado ou
         *          carregado: um `KeyPair()` vazio chega ao serializador com
         *          vetores vazios.
         * - `keypair`: Objeto `KeyPair` a serializar.         * - `filename`: Caminho do arquivo de saída.         */
        .def("save_keypair", &zupt::KeyGenerator::saveKeyPair);

    // Encryptor class
    /**
     * @brief Registra a classe C++ `zupt::Encryptor` como `Encryptor`.
     * @details Cinco pontos de entrada de cifra com semânticas diferentes de
     *          conversão de entrada e de saída, o que obriga o chamador a
     *          conhecer qual método está usando:
     *          - `encrypt` e `encrypt_memory` devolvem `tuple(bytes, bytes)`;
     *          - `encrypt_secure` devolve `tuple(list, list)` porque o retorno
     *            passa direto pelo conversor STL de `std::vector<uint8_t>`;
     *          - `encrypt_file` devolve `tuple(bytes, bytes)`;
     *          - `HEADER_SIZE` é uma propriedade somente leitura de classe.
     *          Nenhuma operação salva o arquivo cifrado em disco:
     *          `encrypt_file` devolve o resultado em memória.
     *          \note nenhum método é liberado do GIL explicitamente (`py::call_guard`
     *          ausente), então a cifra bloqueia o interpretador durante a chamada.
     */
    py::class_<zupt::Encryptor>(m, "Encryptor")
        /**
         * @brief `Encryptor(public_key)` — constrói o criptógrafo.
         * @details O argumento é `const std::vector<uint8_t>&`: o pybind11 aceita
         *          `list`/`tuple` de inteiros e converte para um vetor temporário,
         *          que é copiado para dentro do `zupt::Encryptor`.
         *          \warning um `bytes` NÃO satisfaz essa assinatura: não existe
         *          no pybind11 conversão de `bytes` para
         *          `std::vector<uint8_t>`, de modo que a chamada falha com
         *          `TypeError` de argumentos incompatíveis. O docstring de
         *          `examples_python/__init__.py` mostra
         *          `zupt.Encryptor(keypair.public_key)`, que só funciona porque
         *          `public_key` chega como `list` de inteiros.
         * - `public_key`: Chave pública híbrida como sequência de inteiros.         */
        .def(py::init<const std::vector<uint8_t>&>())
        /**
         * @brief `encrypt(data)` — cifra texto claro vindo de `bytes`.
         * @details Converte `data` em `bytes` e depois em `std::string`, e chama
         *          `zupt::Encryptor::encryptMemory(const uint8_t*, size_t)`. O
         *          par `{ciphertext, enc_header}` é convertido em
         *          `tuple(bytes, bytes)`.
         *          <b>Cópia</b>: o texto claro passa por `std::string`
         *          intermediário; nenhuma cópia é zerada.
         *          \warning `data.cast<py::bytes>()` não está protegido por `try`:
         *          se `data` não for conversível, o pybind11 levanta `TypeError`.
         *          \warning este método e `encrypt_memory` fazem a mesma coisa com
         *          assinaturas diferentes, e `encrypt_secure` faz a mesma cifra com
         *          tipo de saída distinto.
         * - `data`: Texto claro como `bytes`.         * @return `tuple` `(ciphertext, enc_header)`, ambos `bytes`.
         * @see encrypt_memory, encrypt_secure
         */
        .def("encrypt", [](zupt::Encryptor& self, py::object data) {
            py::bytes data_bytes = data.cast<py::bytes>();
            std::string data_str = data_bytes.cast<std::string>();
            auto result = self.encryptMemory(reinterpret_cast<const uint8_t*>(data_str.data()), data_str.size());
            return py::make_tuple(
                py::bytes(reinterpret_cast<const char*>(result.first.data()), result.first.size()),
                py::bytes(reinterpret_cast<const char*>(result.second.data()), result.second.size())
            );
        })
        /**
         * @brief `encrypt_memory(data, size)` — cifra a partir de endereço e contagem.
         * @details A assinatura C++ é `(const uint8_t* data, size_t size)`. O
         *          pybind11 converte o primeiro parâmetro a partir de um
         *          `int`/`None` interpretado como endereço, e o segundo a partir
         *          de um inteiro.
         *          \warning perigoso: qualquer número inteiro vale como
         *          `data`, e o pybind11 não valida o endereço nem o comprimento.
         *          Um chamador Python pode ler memória fora de qualquer buffer
         *          controlado, inclusive fora do processo. Para texto comum use
         *          `encrypt()`.
         *          <b>Conversões</b>: o retorno é `tuple(bytes, bytes)`, como em
         *          `encrypt()`.
         * - `data`: Endereço de memória inicial do texto claro, como inteiro.         * - `size`: Quantidade de bytes a cifrar.         * @return `tuple` `(ciphertext, enc_header)`, ambos `bytes`.
         * @see encrypt
         */
        .def("encrypt_memory", [](zupt::Encryptor& self, const uint8_t* data, size_t size) {
            auto result = self.encryptMemory(data, size);
            return py::make_tuple(
                py::bytes(reinterpret_cast<const char*>(result.first.data()), result.first.size()),
                py::bytes(reinterpret_cast<const char*>(result.second.data()), result.second.size())
            );
        })
        /**
         * @brief `encrypt_secure(buffer)` — cifra o conteúdo de um `SecureBuffer`.
         * @details Chama `zupt::Encryptor::encryptMemory(const SecureBuffer&)`,
         *          que lê o buffer internamente sem cópia adicional. O par de
         *          vetores C++ é devolvido sem conversão para `py::bytes`, de modo
         *          que o resultado chega como `tuple(list, list)` de inteiros.
         *          \warning inconsistência de tipo de saída frente a `encrypt()` e
         *          `encrypt_memory()`, que devolvem `bytes`. A conversão manual
         *          `bytes(x)` para cada elemento da tupla é necessária para
         *          interoperar com os métodos de decifragem que esperam `bytes`.
         * - `buffer`: Objeto `SecureBuffer` com o texto claro.         * @return `tuple` `(ciphertext, enc_header)`, ambos `list` de inteiros.
         * @see encrypt
         */
        .def("encrypt_secure", [](zupt::Encryptor& self, const zupt::SecureBuffer& buffer) {
            return self.encryptMemory(buffer);
        })
        /**
         * @brief `encrypt_file(filename)` — cifra o conteúdo de um arquivo.
         * @details Lê o arquivo, cifra e devolve `tuple(bytes, bytes)`. Não
         *          sobrescreve nem cria arquivo cifrado em disco.
         *          \warning `filename` vem direto do chamador, sem validação;
         *          falhas de leitura chegam como exceção `ZuptError`.
         * - `filename`: Caminho do arquivo em texto claro.         * @return `tuple` `(ciphertext, enc_header)`, ambos `bytes`.
         */
        .def("encrypt_file", [](zupt::Encryptor& self, const std::string& filename) {
            auto [ciphertext, enc_header] = self.encryptFile(filename);
            return py::make_tuple(
                py::bytes(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size()),
                py::bytes(reinterpret_cast<const char*>(enc_header.data()), enc_header.size())
            );
        })
        /**
         * @brief Propriedade de classe `Encryptor.HEADER_SIZE`.
         * @details Getter estático que devolve o que
         *          `zupt::Encryptor::getEncryptionHeaderSize()` retorna — a
         *          constante `HYBRID_ENC_HEADER_SIZE`, 1137 bytes.
         *          `def_property_readonly_static` a apresenta como atributo de
         *          classe, e não como método: `zupt.Encryptor.HEADER_SIZE` é um
         *          `int`.
         *          \note o valor é lido a cada acesso, mas é constante; não há
         *          estado envolvido.
         * @return Inteiro com o tamanho do cabeçalho de cifra, em bytes.
         */
        .def_property_readonly_static("HEADER_SIZE", [](py::object) {
            return zupt::Encryptor::getEncryptionHeaderSize();
        });

    // Decryptor class
    /**
     * @brief Registra a classe C++ `zupt::Decryptor` como `Decryptor`.
     * @details Quatro métodos de decifragem, cada um com conversão própria:
     *          `decrypt` aceita `bytes` ou sequência de inteiros e devolve
     *          `bytes`; `decrypt_memory` recebe endereço e contagem e devolve
     *          `list` de inteiros; `decrypt_secure` recebe dois vetores e devolve
     *          um objeto `SecureBuffer`; `decrypt_file` lê o arquivo cifrado e
     *          devolve `bytes`.
     *          \note nenhum método é liberado do GIL, e nenhum captura exceções
     *          além do `try`/`catch (...)` de `decrypt` e `decrypt_file`.
     */
    py::class_<zupt::Decryptor>(m, "Decryptor")
        /**
         * @brief `Decryptor(private_key)` — constrói o descriptógrafo.
         * @details O argumento é `const std::vector<uint8_t>&`, aceito como
         *          `list`/`tuple` de inteiros; o pybind11 cria um vetor temporário
         *          que o construtor de libzupt copia.
         *          \warning um `bytes` não é aceito por essa assinatura (não há
         *          conversão `bytes` para `std::vector<uint8_t>`), então a chave
         *          privada precisa vir da `list` de `KeyPair.secret_key` ou de
         *          conversão explícita pelo chamador.
         *          \note o `std::vector` temporário criado pelo conversor não é
         *          zerado depois, de modo que a chave privada fica em claro no
         *          heap até a liberação do objeto Python que a originou.
         * - `private_key`: Chave privada híbrida como sequência de inteiros.         */
        .def(py::init<const std::vector<uint8_t>&>())
        /**
         * @brief `decrypt(ciphertext, enc_header)` — decifra texto cifrado.
         * @details Dois ramos de conversão do primeiro argumento, encadeados por
         *          `try`/`catch (...)`: primeiro tenta `bytes`, depois `list` de
         *          inteiros (montando uma `std::string` de mesmo comprimento e
         *          preenchendo byte a byte com `py::cast<uint8_t>`, que rejeita
         *          valores fora de `0..255`). O cabeçalho entra como
         *          `const std::vector<uint8_t>&`, aceitando `list` de inteiros.
         *          O texto claro é devolvido como `bytes`.
         *          <b>Cópia</b>: o texto claro existe em `std::string` de entrada,
         *          `std::vector` de saída e no objeto `bytes` devolvido; nenhuma
         *          das três é zerada.
         *          \warning o `catch (...)` engolfa qualquer causa, inclusive
         *          erro de Python pendente, e cai no ramo de `list`, o que gera
         *          mensagens enganosas.
         *          \warning inconsistência com `decrypt_secure`: este método usa
         *          `decryptMemory` comum, que não limpa o texto claro.
         * - `ciphertext`: Texto cifrado como `bytes` ou sequência de inteiros.         * - `enc_header`: Cabeçalho de cifra como sequência de inteiros.         * @return `bytes` com o texto claro.
         * @see decrypt_secure
         */
        .def("decrypt", [](zupt::Decryptor& self, py::object ciphertext_obj, const std::vector<uint8_t>& enc_header) {
            py::bytes data_bytes;
            try {
                data_bytes = ciphertext_obj.cast<py::bytes>();
            } catch (...) {
                py::list data_list = ciphertext_obj.cast<py::list>();
                std::string data_str(data_list.size(), 0);
                for (size_t i = 0; i < data_list.size(); ++i) {
                    data_str[i] = static_cast<char>(py::cast<uint8_t>(data_list[i]));
                }
                data_bytes = py::bytes(data_str);
            }
            std::string data_str = data_bytes.cast<std::string>();
            std::vector<uint8_t> result = self.decryptMemory(reinterpret_cast<const uint8_t*>(data_str.data()), data_str.size(), enc_header);
            return py::bytes(reinterpret_cast<const char*>(result.data()), result.size());
        })
        /**
         * @brief `decrypt_memory(ciphertext, ciphertextSize, enc_header)`.
         * @details Recebe o texto cifrado como endereço inteiro e contagem, como
         *          na versão homóloga de `Encryptor`, e devolve o resultado
         *          diretamente: o `std::vector<uint8_t>` de libzupt é convertido
         *          pelo pybind11 em `list` de inteiros.
         *          \warning o endereço não é validado: qualquer inteiro é aceito,
         *          e ler além da memória mapeada derruba o processo.
         *          \warning inconsistência de tipo de saída: `decrypt` devolve
         *          `bytes` e este método devolve `list`.
         * - `ciphertext`: Endereço de memória do texto cifrado, como inteiro.         * - `ciphertextSize`: Quantidade de bytes de texto cifrado.         * - `enc_header`: Cabeçalho de cifra como sequência de inteiros.         * @return `list` de inteiros com o texto claro.
         * @see decrypt
         */
        .def("decrypt_memory", [](zupt::Decryptor& self, const uint8_t* ciphertext, size_t ciphertextSize,
                                   const std::vector<uint8_t>& enc_header) {
            return self.decryptMemory(ciphertext, ciphertextSize, enc_header);
        })
        /**
         * @brief `decrypt_secure(ciphertext, enc_header)` — decifra com limpeza.
         * @details Chama `zupt::Decryptor::decryptMemorySecure(const std::vector<uint8_t>&, const std::vector<uint8_t>&)`,
         *          que zera o texto claro em buffers internos durante o processo.
         *          O retorno é um `zupt::SecureBuffer`, apresentado em Python como
         *          o objeto `SecureBuffer` registrado neste módulo.
         *          <b>Recomendação de uso</b>: é o único caminho de decifragem
         *          deste binding que mantém o texto claro sob controle, pois o
         *          `SecureBuffer` zera o conteúdo quando o objeto Python morre.
         *          \warning o texto cifrado de entrada, convertido pelo pybind11,
         *          continua sem limpeza.
         * - `ciphertext`: Texto cifrado como sequência de inteiros.         * - `enc_header`: Cabeçalho de cifra como sequência de inteiros.         * @return Objeto `SecureBuffer` com o texto claro.
         */
        .def("decrypt_secure", [](zupt::Decryptor& self, const std::vector<uint8_t>& ciphertext,
                                   const std::vector<uint8_t>& enc_header) {
            return self.decryptMemorySecure(ciphertext, enc_header);
        })
        /**
         * @brief `decrypt_file(filename, enc_header)` — decifra um arquivo.
         * @details Converte o cabeçalho (ramos `bytes` ou `list` de inteiros, o
         *          mesmo padrão dos outros métodos) e chama
         *          `zupt::Decryptor::decryptFile(filename, enc_header)`, que lê o
         *          arquivo cifrado e devolve o texto claro em memória. Nada é
         *          escrito em disco.
         *          \warning `filename` vem direto do chamador, sem validação; e o
         *          `catch (...)` do ramo de conversão engolfa qualquer causa.
         * - `filename`: Caminho do arquivo cifrado.         * - `enc_header`: Cabeçalho de cifra como `bytes` ou sequência de         *                       inteiros.
         * @return `bytes` com o texto claro.
         */
        .def("decrypt_file", [](zupt::Decryptor& self, const std::string& filename, py::object enc_header_obj) {
            std::vector<uint8_t> enc_header;
            try {
                py::bytes header_bytes = enc_header_obj.cast<py::bytes>();
                std::string header_str = header_bytes.cast<std::string>();
                enc_header.assign(header_str.begin(), header_str.end());
            } catch (...) {
                py::list header_list = enc_header_obj.cast<py::list>();
                enc_header.reserve(header_list.size());
                for (size_t i = 0; i < header_list.size(); ++i) {
                    enc_header.push_back(py::cast<uint8_t>(header_list[i]));
                }
            }
            std::vector<uint8_t> result = self.decryptFile(filename, enc_header);
            return py::bytes(reinterpret_cast<const char*>(result.data()), result.size());
        });

    // Helper functions
    /**
     * @brief `random_bytes(size)` — devolve aleatórios criptográficos.
     * @details Chama `zupt::randomBytes(size)` e converte o vetor resultante em
     *          `bytes` por `py::bytes`, o que copia os dados.
     *          <b>Conversão</b>: o argumento é `size_t`; valores negativos e
     *          acima do suportado são rejeitados pelo pybind11 antes da chamada.
     * - `size`: Quantidade de bytes aleatórios desejados.     * @return `bytes` com os aleatórios.
     */
    m.def("random_bytes", [](size_t size) {
        std::vector<uint8_t> result = zupt::randomBytes(size);
        return py::bytes(reinterpret_cast<const char*>(result.data()), result.size());
    });
    /**
     * @brief `sha256(data)` — digest SHA-256 de um dado binário.
     * @details Converte `data` para `bytes` e depois para `std::string`; chama
     *          `zupt::sha256(const uint8_t*, size_t)` e devolve os 32 bytes do
     *          digest como `bytes`.
     *          \warning a conversão para `bytes` não é protegida por `try`,
     *          então um argumento não conversível levanta `TypeError`. Nenhum
     *          `str` é aceito implicitamente além do que `py::bytes` aceita.
     * - `data`: Conteúdo a resumir, como `bytes`.     * @return `bytes` com os 32 bytes do digest SHA-256.
     * @see sha3_512
     */
    m.def("sha256", [](py::object data) {
        py::bytes data_bytes = data.cast<py::bytes>();
        std::string data_str = data_bytes.cast<std::string>();
        std::vector<uint8_t> result = zupt::sha256(
            reinterpret_cast<const uint8_t*>(data_str.data()),
            data_str.size()
        );
        return py::bytes(reinterpret_cast<const char*>(result.data()), result.size());
    });
    /**
     * @brief `sha3_512(data)` — digest SHA3-512 de um dado binário.
     * @details Mesmo padrão de `sha256`: converte para `bytes`, depois para
     *          `std::string`, chama
     *          `zupt::sha3_512(const uint8_t*, size_t)` e devolve o digest como
     *          `bytes`.
     *          \warning conversão não protegida: argumento não conversível
     *          levanta `TypeError`.
     * - `data`: Conteúdo a resumir, como `bytes`.     * @return `bytes` com o digest SHA3-512.
     * @see sha256
     */
    m.def("sha3_512", [](py::object data) {
        py::bytes data_bytes = data.cast<py::bytes>();
        std::string data_str = data_bytes.cast<std::string>();
        std::vector<uint8_t> result = zupt::sha3_512(
            reinterpret_cast<const uint8_t*>(data_str.data()),
            data_str.size()
        );
        return py::bytes(reinterpret_cast<const char*>(result.data()), result.size());
    });
    /**
     * @brief `secure_wipe(ptr, size)` — limpa memória no processo.
     * @details Encaminhamento direto para `zupt::secureWipe(void*, size_t)`.
     *          O pybind11 converte o primeiro parâmetro a partir de um inteiro
     *          interpretado como endereço, e o segundo a partir de um inteiro.
     *          \warning extremamente perigoso para uso em Python: não há
     *          validação do endereço nem do tamanho, e `nullptr` com `size > 0`
     *          é comportamento indefinido. Passar `0` com `size > 0` derruba o
     *          processo. Existe sobretudo para interagir com os endereços
     *          devolvidos por `SecureBuffer.data_ptr()`.
     * - `ptr`: Endereço inicial do buffer a apagar, como inteiro.     * - `size`: Quantidade de bytes a apagar.     */
    m.def("secure_wipe", &zupt::secureWipe);

    // Version info
    /**
     * @brief `zupt.__version__` — versão da biblioteca compartilhada.
     * @details Recebe `const char*` de `zupt::getVersion()`; o pybind11 o
     *          converte em `str` de Python. Convencão de atributo do pacote:
     *          `examples_python/__init__.py` faz
     *          `__version__ = zupt.__version__`.
     *          \warning não há checagem de ponteiro nulo: se a função devolver
     *          `nullptr`, a conversão derruba o processo.
     */
    m.attr("__version__") = zupt::getVersion();
    /**
     * @brief `zupt.LIBRARY_NAME` — nome da biblioteca compartilhada.
     * @details Recebe `const char*` de `zupt::getLibraryName()` convertido em
     *          `str`. É informativo: nenhum código deste binding usa o valor.
     */
    m.attr("LIBRARY_NAME") = zupt::getLibraryName();
}