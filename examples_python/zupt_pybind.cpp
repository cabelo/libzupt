/*
 * libzupt - Python bindings with pybind11
 * SPDX-License-Identifier: MIT
 */

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/iostream.h>

#include "zupt.hpp"

/**
 * @cond PORT
 * @file  examples_python/zupt_pybind.cpp
 * @brief Binding Python da camada C++ da libzupt, usando pybind11.
 * @details Este TU compila o módulo nativo `zupt` (target CMake
 * `zupt_python_bindings`, `OUTPUT_NAME zupt` em
 * `examples_python/CMakeLists.txt`) e espelha a API de
 * `include/zupt.hpp` sem adicionar lógica própria de criptografia.
 * São exportados: o enum `ErrorCode`, a exceção `ZuptError`,
 * onze constantes de tamanho, as classes `SecureBuffer`, `KeyPair`,
 * `KeyGenerator`, `Encryptor` e `Decryptor`, e as funções de módulo
 * `random_bytes`, `sha256`, `sha3_512` e `secure_wipe`.
 *
 * <b>Fronteira de tipos</b>: a maioria dos dados binários entra e sai
 * como `bytes` (via `py::bytes`), convertida para `std::string` e
 * reinterpretada como `const uint8_t*`. `pybind11/stl.h` converte
 * automaticamente `std::vector<uint8_t>` para `list` de `int`, de modo
 * que nem todo dado binário chega como `bytes`: o que o método devolve
 * sem conversão explícita para `py::bytes` chega como `list` de inteiros
 * (por exemplo `KeyPair.public_key`, `load_public_key`, `encrypt_secure`
 * e `decrypt_memory`). Ver os blocos de cada método e o arquivo de
 * achados.
 *
 * <b>Erros</b>: este TU não captura exceções de libzupt fora dos dois
 * `catch (...)` dos construtores de `SecureBuffer` e de `decrypt`.
 * `zupt::ZuptError` é registrada por `py::register_exception` e o
 * pybind11 a converte em exceção Python da classe `zupt.ZuptError`,
 * derivada de `RuntimeError`. Qualquer outra exceção C++ não
 * registrada se converte em `RuntimeError` genérico do pybind11, e
 * `py::error_already_set` (erro já pendente em Python) é devolvida ao
 * interpretador.
 *
 * <b>Propriedade de memória</b>: as classes C++ são gerenciadas pelo
 * pybind11, que destrói o objeto C++ quando o objeto Python morre
 * (referência forte do Python para a instância C++). `SecureBuffer`
 * zera o próprio conteúdo no destrutor. Os ponteiros expostos por
 * `data_ptr` e `data_ptr_const` são ponteiros internos e ficam
 * inválidos quando o objeto Python é destruído ou movido.
 * @endcond
 * @cond INGLES
 * @file  examples_python/zupt_pybind.cpp
 * @brief Python binding for the libzupt C++ layer, using pybind11.
 * @details This TU compiles the native `zupt` module (CMake target
 * `zupt_python_bindings`, `OUTPUT_NAME zupt` in
 * `examples_python/CMakeLists.txt`) and mirrors the API of
 * `include/zupt.hpp` without adding encryption logic of its own.
 * The following are exported: the `ErrorCode` enum, the `ZuptError`
 * exception, eleven size constants, the classes `SecureBuffer`, `KeyPair`,
 * `KeyGenerator`, `Encryptor` and `Decryptor`, and the module functions
 * `random_bytes`, `sha256`, `sha3_512` and `secure_wipe`.
 *
 * <b>Type boundary</b>: most binary data enters and leaves as `bytes`
 * (via `py::bytes`), converted to `std::string` and reinterpreted as
 * `const uint8_t*`. `pybind11/stl.h` automatically converts
 * `std::vector<uint8_t>` to a `list` of `int`, so not all binary data
 * arrives as `bytes`: what a method returns without an explicit
 * conversion to `py::bytes` arrives as a `list` of integers (for example
 * `KeyPair.public_key`, `load_public_key`, `encrypt_secure` and
 * `decrypt_memory`). See the block of each method and the findings file.
 *
 * <b>Errors</b>: this TU does not catch libzupt exceptions outside the two
 * `catch (...)` of the `SecureBuffer` constructors and of `decrypt`.
 * `zupt::ZuptError` is registered by `py::register_exception` and
 * pybind11 converts it into a Python exception of class
 * `zupt.ZuptError`, derived from `RuntimeError`. Any other unregistered
 * C++ exception becomes a generic pybind11 `RuntimeError`, and
 * `py::error_already_set` (an error already pending in Python) is
 * returned to the interpreter.
 *
 * <b>Memory ownership</b>: the C++ classes are managed by pybind11, which
 * destroys the C++ object when the Python object dies (strong Python
 * reference to the C++ instance). `SecureBuffer` zeroes its own content
 * in the destructor. The pointers exposed by `data_ptr` and
 * `data_ptr_const` are internal pointers and become invalid when the
 * Python object is destroyed or moved.
 * @endcond */

/**
 * @cond PORT
 * @namespace py
 * @brief Alias de namespace para `pybind11`, usado em todo o arquivo.
 * @details É apenas um apelido; não introduz símbolos próprios.
 * @endcond
 * @cond INGLES
 * @namespace py
 * @brief Namespace alias for `pybind11`, used throughout the file.
 * @details It is only a nickname; it introduces no symbols of its own.
 * @endcond */
namespace py = pybind11;

/**
 * @cond PORT
 * @brief Macro de definição do módulo nativo `zupt`.
 * @details `PYBIND11_MODULE(zupt, m)` expande para a função de registro
 * chamada pelo interpretador no `import zupt`. O primeiro argumento
 * (`zupt`) deve coincidir com o nome do módulo importável (o
 * `OUTPUT_NAME` do target CMake); o segundo é a referência ao objeto
 * de módulo. Todo o restante deste arquivo acontece dentro desta
 * função: registro de tipos, constantes e funções livres.
 * <b>Ordem de registro</b>: primeiro o enum `ErrorCode`, depois a
 * exceção, depois as constantes, depois as classes e por fim as
 * funções e atributos de versão. A ordem não é apenas cosmética: um
 * tipo referenciado por assinatura de função precisa estar registrado
 * antes do uso, o que aqui é garantido porque as classes precedem as
 * funções que usam `SecureBuffer`.
 * <b>Erros de registro</b>: `m.def`/`py::class_` lançam se o nome já
 * existe ou se há incompatibilidade de tipo; não há tratamento de erro
 * e o `import` simplesmente falha.
 * - `m`: Objeto de módulo Python em construção (`py::module_&`). * @note O docstring do módulo é definido como
 * "libzupt - Hybrid Post-Quantum Encryption Library".
 * @endcond
 * @cond INGLES
 * @brief Definition macro of the native `zupt` module.
 * @details `PYBIND11_MODULE(zupt, m)` expands to the registration
 * function called by the interpreter on `import zupt`. The first
 * argument (`zupt`) must match the name of the importable module (the
 * `OUTPUT_NAME` of the CMake target); the second is the reference to
 * the module object. Everything else in this file happens inside this
 * function: registration of types, constants and free functions.
 * <b>Registration order</b>: first the `ErrorCode` enum, then the
 * exception, then the constants, then the classes and finally the
 * functions and version attributes. The order is not merely cosmetic: a
 * type referenced by a function signature must be registered before use,
 * which here is guaranteed because the classes precede the functions that
 * use `SecureBuffer`.
 * <b>Registration errors</b>: `m.def`/`py::class_` throw if the name
 * already exists or if there is a type mismatch; there is no error
 * handling and the `import` simply fails.
 * - `m`: Python module object under construction (`py::module_&`). * @note The module docstring is defined as
 * "libzupt - Hybrid Post-Quantum Encryption Library".
 * @endcond */
PYBIND11_MODULE(zupt, m) {
    m.doc() = "libzupt - Hybrid Post-Quantum Encryption Library";

    // Error codes
    /**
     * @cond PORT
     * @brief Espelho Python do enum `zupt::ErrorCode`.
     * @details Registra as 12 constantes com os mesmos nomes usados em C++ e
     * aplica `export_values()`, o que coloca cada constante também no
     * namespace do módulo (`zupt.ERR_IO`, além de
     * `zupt.ErrorCode.ERR_IO`). Os valores numéricos são os da
     * definição em `include/zupt.hpp`: `OK = 0` e os demais negativos,
     * de `ERR_IO = -1` até `ERR_AUTH_FAIL = -11`.
     * <b>Mapeamento</b>:
     * - `OK` (0): sucesso;
     * - `ERR_IO` (-1): falha de abrir/ler/escrever/arquivo;
     * - `ERR_CORRUPT` (-2): estrutura interna inconsistente;
     * - `ERR_BAD_MAGIC` (-3): assinatura de formato ausente/diferente;
     * - `ERR_BAD_VERSION` (-4): versão de formato não suportada;
     * - `ERR_BAD_CHECKSUM` (-5): soma de verificação divergente;
     * - `ERR_NOMEM` (-6): alocação falhou;
     * - `ERR_OVERFLOW` (-7): tamanho acima do suportado;
     * - `ERR_INVALID` (-8): argumento/buffer inválido;
     * - `ERR_NOT_FOUND` (-9): item inexistente;
     * - `ERR_UNSUPPORTED` (-10): operação não suportada nesta build;
     * - `ERR_AUTH_FAIL` (-11): MAC/GCM do envelope não validou.
     * @note Nenhum caminho deste binding entrega um `ErrorCode`
     * numérico ao chamador: a camada C++ sinaliza falha por exceção e
     * `py::register_exception` não expõe o método `code()` de
     * `zupt::ZuptError`, de modo que em Python a exceção carrega apenas
     * a mensagem. As constantes registradas aqui, portanto, só têm uso
     * comparativo explícito (ver arquivo de achados).
     * \see include/zupt.hpp (enum `zupt::ErrorCode`)
     * @endcond
     * @cond INGLES
     * @brief Python mirror of the `zupt::ErrorCode` enum.
     * @details Registers the 12 constants with the same names used in C++ and
     * applies `export_values()`, which places each constant also in the
     * module namespace (`zupt.ERR_IO`, in addition to
     * `zupt.ErrorCode.ERR_IO`). The numeric values are those of the
     * definition in `include/zupt.hpp`: `OK = 0` and the others negative,
     * from `ERR_IO = -1` to `ERR_AUTH_FAIL = -11`.
     * <b>Mapping</b>:
     * - `OK` (0): success;
     * - `ERR_IO` (-1): open/read/write/file failure;
     * - `ERR_CORRUPT` (-2): inconsistent internal structure;
     * - `ERR_BAD_MAGIC` (-3): missing/different format signature;
     * - `ERR_BAD_VERSION` (-4): unsupported format version;
     * - `ERR_BAD_CHECKSUM` (-5): mismatching checksum;
     * - `ERR_NOMEM` (-6): allocation failed;
     * - `ERR_OVERFLOW` (-7): size above the supported limit;
     * - `ERR_INVALID` (-8): invalid argument/buffer;
     * - `ERR_NOT_FOUND` (-9): item does not exist;
     * - `ERR_UNSUPPORTED` (-10): operation not supported in this build;
     * - `ERR_AUTH_FAIL` (-11): envelope MAC/GCM did not validate.
     * @note No path of this binding delivers a numeric `ErrorCode` to the
     * caller: the C++ layer signals failure by exception and
     * `py::register_exception` does not expose the `code()` method of
     * `zupt::ZuptError`, so in Python the exception carries only the
     * message. The constants registered here therefore have only explicit
     * comparative use (see the findings file).
     * \see include/zupt.hpp (enum `zupt::ErrorCode`)
     * @endcond */
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
     * @cond PORT
     * @brief Registra `zupt.ZuptError` como tipo de exceção Python.
     * @details `py::register_exception` cria, no módulo, uma classe de exceção
     * que o pybind11 usa para lançar `std::exception` derivada de
     * `zupt::ZuptError`. O terceiro argumento, `PyExc_RuntimeError`, é
     * a base da nova classe: `except RuntimeError` continua
     * capturando as falhas de libzupt. O texto da exceção é o que
     * `std::runtime_error::what()` devolve.
     * \warning o atributo `code()` de `zupt::ZuptError` não é
     * transportado para Python: o registro não gera bindings da classe,
     * apenas da exceção. Em Python, o código de erro (enum
     * `ErrorCode` acima) não é consultável.
     * @endcond
     * @cond INGLES
     * @brief Registers `zupt.ZuptError` as a Python exception type.
     * @details `py::register_exception` creates, in the module, an exception
     * class that pybind11 uses to throw `std::exception` derived from
     * `zupt::ZuptError`. The third argument, `PyExc_RuntimeError`, is the
     * base of the new class: `except RuntimeError` still catches libzupt
     * failures. The exception text is what `std::runtime_error::what()`
     * returns.
     * \warning the `code()` attribute of `zupt::ZuptError` is not
     * carried over to Python: the registration generates no bindings for the
     * class, only for the exception. In Python, the error code (the
     * `ErrorCode` enum above) is not queryable.
     * @endcond */
    py::register_exception<zupt::ZuptError>(m, "ZuptError", PyExc_RuntimeError);

    // Constants
    /**
     * @cond PORT
     * @brief Expõe as constantes `constexpr` de `include/zupt.hpp` como
     * atributos de módulo.
     * @details Cada linha atribui um `size_t` do C++ a um atributo Python, que
     * o pybind11 converte em `int` imutável. Os valores são:
     * `MLKEM_PUBLICKEYBYTES = 1184`, `MLKEM_SECRETKEYBYTES = 2400`,
     * `MLKEM_CIPHERTEXTBYTES = 1088`, `MLKEM_SSBYTES = 32`,
     * `X25519_KEYBYTES = 32`, `HYBRID_PUB_KEY_SIZE = 1224`,
     * `HYBRID_PRIV_KEY_SIZE = 3656`, `HYBRID_ENC_HEADER_SIZE = 1137`,
     * `AES_KEY_SIZE = 32`, `AES_NONCE_SIZE = 16` e `HMAC_SIZE = 32`.
     * @note a atribuição cria cópias: mudar o valor em Python não afeta
     * a biblioteca, e a biblioteca não valida que o chamador use os
     * tamanhos corretos — o erro aparece mais tarde, como exceção.
     * @endcond
     * @cond INGLES
     * @brief Exposes the `constexpr` constants of `include/zupt.hpp` as
     * module attributes.
     * @details Each line assigns a C++ `size_t` to a Python attribute, which
     * pybind11 converts into an immutable `int`. The values are:
     * `MLKEM_PUBLICKEYBYTES = 1184`, `MLKEM_SECRETKEYBYTES = 2400`,
     * `MLKEM_CIPHERTEXTBYTES = 1088`, `MLKEM_SSBYTES = 32`,
     * `X25519_KEYBYTES = 32`, `HYBRID_PUB_KEY_SIZE = 1224`,
     * `HYBRID_PRIV_KEY_SIZE = 3656`, `HYBRID_ENC_HEADER_SIZE = 1137`,
     * `AES_KEY_SIZE = 32`, `AES_NONCE_SIZE = 16` and `HMAC_SIZE = 32`.
     * @note the assignment creates copies: changing the value in Python does
     * not affect the library, and the library does not validate that the
     * caller uses the correct sizes — the error appears later, as an
     * exception.
     * @endcond */
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
     * @cond PORT
     * @brief Registra a classe C++ `zupt::SecureBuffer` como `SecureBuffer` em Python.
     * @details Sem `py::buffer_protocol`: o objeto não é conversível de/para
     * `memoryview` nem aceita `numpy`, de modo que toda entrada e saída
     * binária passa pelos métodos `to_bytes`, `to_string`, `__len__` e
     * pelos dois construtores. O pybind11 é quem destrói o objeto C++
     * quando a referência Python morre, e o destrutor de
     * `zupt::SecureBuffer` chama `zeroize()`.
     * \note não há `__eq__`, `__bool__` nem `__getstate__` registrados:
     * dois objetos nunca comparam iguais por valor, e o objeto não é
     * serializável com `pickle` (o pybind11 gera erro para tipos sem
     * suporte).
     * \see include/zupt.hpp (classe `zupt::SecureBuffer`)
     * @endcond
     * @cond INGLES
     * @brief Registers the C++ class `zupt::SecureBuffer` as `SecureBuffer` in Python.
     * @details No `py::buffer_protocol`: the object is not convertible
     * to/from `memoryview` and does not accept `numpy`, so all binary input
     * and output goes through the `to_bytes`, `to_string`, `__len__` methods
     * and through the two constructors. It is pybind11 that destroys the C++
     * object when the Python reference dies, and the destructor of
     * `zupt::SecureBuffer` calls `zeroize()`.
     * \note there is no registered `__eq__`, `__bool__` or `__getstate__`:
     * two objects never compare equal by value, and the object is not
     * serializable with `pickle` (pybind11 raises an error for unsupported
     * types).
     * \see include/zupt.hpp (class `zupt::SecureBuffer`)
     * @endcond */
    py::class_<zupt::SecureBuffer>(m, "SecureBuffer")
        /**
         * @cond PORT
         * @brief Construtor `SecureBuffer(size)`.
         * @details Encaminha para `zupt::SecureBuffer(size_t)`, que aloca o
         * buffer sem inicializar o conteúdo: os `size` bytes ficam com
         * valores indefinidos até serem escritos. A conversão do
         * argumento é feita pelo pybind11, que rejeita valores
         * negativos e acima de `sys.maxsize` com `OverflowError` ou
         * `TypeError`. Falha de alocação se manifesta como
         * `std::bad_alloc` convertido pelo pybind11 em exceção
         * `RuntimeError` (nenhuma conversão própria para `MemoryError`
         * é registrada neste arquivo).
         * - `size`: Quantidade de bytes a alocar.
         * @endcond
         * @cond INGLES
         * @brief `SecureBuffer(size)` constructor.
         * @details Forwards to `zupt::SecureBuffer(size_t)`, which allocates the
         * buffer without initializing the content: the `size` bytes hold
         * undefined values until they are written. Conversion of the argument is
         * done by pybind11, which rejects negative values and values above
         * `sys.maxsize` with `OverflowError` or `TypeError`. Allocation failure
         * manifests as `std::bad_alloc`, converted by pybind11 into a
         * `RuntimeError` exception (no conversion of its own to `MemoryError` is
         * registered in this file).
         * - `size`: Number of bytes to allocate.
         * @endcond */
        .def(py::init<size_t>())
        /**
         * @cond PORT
         * @brief Construtor flexível `SecureBuffer(data)`.
         * @details Lambda de fábrica com dois ramos encadeados por `try` /
         * `catch (...)`:
         * - primeiro ramo: `data.cast<py::bytes>()` seguido de
         * `.cast<std::string>()`, com os bytes passados a
         * `zupt::SecureBuffer(const uint8_t*, size_t)` por
         * `reinterpret_cast`;
         * - segundo ramo (somente se o primeiro lançou qualquer
         * coisa): `data.cast<py::list>()` e elemento a elemento
         * `py::cast<uint8_t>`, o que rejeita valores fora de
         * `0..255`, seguido de `zupt::SecureBuffer(std::vector)`.
         * <b>Cópia</b>: os dois caminhos copiam os bytes para o buffer
         * interno; o objeto Python de origem pode ser alterado depois
         * sem afetar o `SecureBuffer`.
         * \warning o `catch (...)` engolfa todas as causas: um erro
         * Python já pendente (por exemplo `MemoryError`) ou um
         * `bytes` válido que falhe na etapa seguinte cai no ramo de
         * lista e produz mensagem enganosa.
         * \warning o `std::string` intermediário do primeiro ramo não
         * é zerado, de modo que permanece uma cópia do material em
         * claro no heap até a liberação da string C++.
         * - `data`: Conteúdo inicial: o código aceita `bytes` (primeiro ramo)         *             ou sequência de inteiros convertível a `list` (segundo
         * ramo).
         * @endcond
         * @cond INGLES
         * @brief Flexible `SecureBuffer(data)` constructor.
         * @details Factory lambda with two branches chained by `try` /
         * `catch (...)`:
         * - first branch: `data.cast<py::bytes>()` followed by
         * `.cast<std::string>()`, with the bytes passed to
         * `zupt::SecureBuffer(const uint8_t*, size_t)` via
         * `reinterpret_cast`;
         * - second branch (only if the first threw anything):
         * `data.cast<py::list>()` and element by element
         * `py::cast<uint8_t>`, which rejects values outside `0..255`,
         * followed by `zupt::SecureBuffer(std::vector)`.
         * <b>Copy</b>: both paths copy the bytes into the internal buffer; the
         * source Python object can be modified afterwards without affecting the
         * `SecureBuffer`.
         * \warning the `catch (...)` swallows all causes: a Python error already
         * pending (for example `MemoryError`), or a valid `bytes` that fails in
         * the next step, falls into the list branch and produces a misleading
         * message.
         * \warning the intermediate `std::string` of the first branch is not
         * zeroed, so a copy of the plaintext material remains on the heap until
         * the C++ string is released.
         * - `data`: Initial content: the code accepts `bytes` (first branch)         *             or a sequence of integers convertible to `list` (second
         * branch).
         * @endcond */
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
         * @cond PORT
         * @brief `size()` — devolve o tamanho do buffer em bytes.
         * @details Encaminhamento direto para `zupt::SecureBuffer::size()`, que
         * devolve `size_` (zero depois de um movimento). Equivalente a
         * `len(objeto)`, pois `__len__` aponta para o mesmo método.
         * @return Inteiro com o tamanho em bytes.
         * @endcond
         * @cond INGLES
         * @brief `size()` — returns the size of the buffer in bytes.
         * @details Direct forwarding to `zupt::SecureBuffer::size()`, which
         * returns `size_` (zero after a move). Equivalent to `len(object)`,
         * since `__len__` points to the same method.
         * @return Integer with the size in bytes.
         * @endcond */
        .def("size", &zupt::SecureBuffer::size)
        /**
         * @cond PORT
         * @brief `data_ptr()` — devolve o ponteiro interno como inteiro.
         * @details O cast `(uint8_t*(zupt::SecureBuffer::*)())` seleciona a
         * sobrecarga não-const de `data()`. O pybind11 converte o
         * `uint8_t*` retornado em um `int` de endereço.
         * \warning expor o endereço interno da chave/Texto em claro é
         * um vazamento de endereço e permite interação com outras
         * APIs que aceitam inteiros como ponteiros (por exemplo
         * `secure_wipe` deste mesmo módulo). O endereço vale apenas
         * enquanto o objeto Python estiver vivo e não for movido.
         * @return Endereço de memória do buffer interno como inteiro.
         * @endcond
         * @cond INGLES
         * @brief `data_ptr()` — returns the internal pointer as an integer.
         * @details The cast `(uint8_t*(zupt::SecureBuffer::*)())` selects the
         * non-const overload of `data()`. pybind11 converts the returned
         * `uint8_t*` into an address `int`.
         * \warning exposing the internal address of the key/plaintext is an
         * address leak and allows interaction with other APIs that accept
         * integers as pointers (for example `secure_wipe` of this same module).
         * The address is valid only while the Python object is alive and is not
         * moved.
         * @return Memory address of the internal buffer, as an integer.
         * @endcond */
        .def("data_ptr", (uint8_t*(zupt::SecureBuffer::*)()) &zupt::SecureBuffer::data)
        /**
         * @cond PORT
         * @brief `data_ptr_const()` — mesmo ponteiro, via sobrecarga const.
         * @details O cast
         * `(const uint8_t*(zupt::SecureBuffer::*)() const)` seleciona a
         * sobrecarga `const` de `data()`. Em Python não há diferença
         * observável de mutabilidade: o retorno é apenas um inteiro, e
         * o resultado é o mesmo endereço devolvido por `data_ptr()`.
         * @return Endereço de memória do buffer interno como inteiro.
         * @see data_ptr
         * @endcond
         * @cond INGLES
         * @brief `data_ptr_const()` — same pointer, via the const overload.
         * @details The cast
         * `(const uint8_t*(zupt::SecureBuffer::*)() const)` selects the
         * `const` overload of `data()`. In Python there is no observable
         * difference in mutability: the return value is just an integer, and the
         * result is the same address returned by `data_ptr()`.
         * @return Memory address of the internal buffer, as an integer.
         * @see data_ptr
         * @endcond */
        .def("data_ptr_const", (const uint8_t*(zupt::SecureBuffer::*)() const) &zupt::SecureBuffer::data)
        /**
         * @cond PORT
         * @brief `to_bytes()` — cópia do conteúdo como `bytes`.
         * @details Lambda que constrói `py::bytes` a partir de
         * `self.data()` e `self.size()`, o que copia os bytes para um
         * novo objeto imutável de Python. O conteúdo devolvido é
         * independente do buffer interno.
         * \warning o objeto `bytes` devolvido é exatamente o texto em
         * claro e não pode ser zerado pelo chamador; `zeroize()` ou a
         * destruição do `SecureBuffer` não o alcança.
         * @return Objeto `bytes` com os `size()` bytes do buffer.
         * @endcond
         * @cond INGLES
         * @brief `to_bytes()` — copy of the content as `bytes`.
         * @details Lambda that constructs `py::bytes` from `self.data()` and
         * `self.size()`, which copies the bytes into a new immutable Python
         * object. The returned content is independent of the internal buffer.
         * \warning the returned `bytes` object is exactly the plaintext and
         * cannot be zeroed by the caller; `zeroize()` or the destruction of the
         * `SecureBuffer` does not reach it.
         * @return `bytes` object with the `size()` bytes of the buffer.
         * @endcond */
        .def("to_bytes", [](const zupt::SecureBuffer& self) {
            return py::bytes(reinterpret_cast<const char*>(self.data()), self.size());
        })
        /**
         * @cond PORT
         * @brief `to_string()` — mesmo conteúdo que `to_bytes()`.
         * @details Encaminhamento para `zupt::SecureBuffer::toString()`, que
         * copia os bytes para um `std::string`; o pybind11 converte esse
         * `std::string` em `str` de Python decodificando como UTF-8.
         * \warning conteúdo binário aleatório quase sempre não é UTF-8
         * válido, então o uso normal desta função lança `UnicodeDecodeError`.
         * Para bytes use `to_bytes()`.
         * @return `str` com o conteúdo, quando decodificável como UTF-8.
         * @see to_bytes
         * @endcond
         * @cond INGLES
         * @brief `to_string()` — same content as `to_bytes()`.
         * @details Forwarding to `zupt::SecureBuffer::toString()`, which copies
         * the bytes into a `std::string`; pybind11 converts that `std::string`
         * into a Python `str` by decoding it as UTF-8.
         * \warning random binary content is almost never valid UTF-8, so normal
         * use of this function raises `UnicodeDecodeError`. For bytes use
         * `to_bytes()`.
         * @return `str` with the content, when decodable as UTF-8.
         * @see to_bytes
         * @endcond */
        .def("to_string", &zupt::SecureBuffer::toString)
        /**
         * @cond PORT
         * @brief `zeroize()` — zera o conteúdo do buffer.
         * @details Encaminhamento para `zupt::SecureBuffer::zeroize()`, que
         * aplica `zupt::secureWipe` (escrita via `volatile`). Não afeta
         * cópias já devolvidas por `to_bytes()`/`to_string()`.
         * @endcond
         * @cond INGLES
         * @brief `zeroize()` — zeroes the content of the buffer.
         * @details Forwarding to `zupt::SecureBuffer::zeroize()`, which applies
         * `zupt::secureWipe` (write via `volatile`). Does not affect copies
         * already returned by `to_bytes()`/`to_string()`.
         * @endcond */
        .def("zeroize", &zupt::SecureBuffer::zeroize)
        /**
         * @cond PORT
         * @brief `len(objeto)` — mesmo que `size()`.
         * @details Aponta o protocolo de comprimento para
         * `zupt::SecureBuffer::size`, de modo que `len(buf)` e
         * `buf.size()` são equivalentes. Não há `__getitem__` nem
         * `__iter__` registrados, então `len()` não implica indexação.
         * @return Inteiro com o tamanho em bytes.
         * @endcond
         * @cond INGLES
         * @brief `len(object)` — same as `size()`.
         * @details Points the length protocol to `zupt::SecureBuffer::size`, so
         * that `len(buf)` and `buf.size()` are equivalent. There is no
         * registered `__getitem__` or `__iter__`, so `len()` does not imply
         * indexing.
         * @return Integer with the size in bytes.
         * @endcond */
        .def("__len__", &zupt::SecureBuffer::size)
        /**
         * @cond PORT
         * @brief `repr(objeto)` — descrição textual do objeto.
         * @details Devolve a cadeia `<SecureBuffer size=N>`, onde N é
         * `self.size()`. Nenhum byte do conteúdo aparece no resultado,
         * o que evita exposição acidental em logs e `print`.
         * @return `str` com o formato `<SecureBuffer size=N>`.
         * @endcond
         * @cond INGLES
         * @brief `repr(object)` — textual description of the object.
         * @details Returns the string `<SecureBuffer size=N>`, where N is
         * `self.size()`. No byte of the content appears in the result, which
         * avoids accidental exposure in logs and `print`.
         * @return `str` in the format `<SecureBuffer size=N>`.
         * @endcond */
        .def("__repr__", [](const zupt::SecureBuffer& self) {
            return "<SecureBuffer size=" + std::to_string(self.size()) + ">";
        });

    // KeyPair struct
    /**
     * @cond PORT
     * @brief Registra a struct `zupt::KeyPair` como `KeyPair` em Python.
     * @details Expõe os dois membros como atributos somente leitura
     * (`def_readonly`). Como `public_key` e `secret_key` são
     * `std::vector<uint8_t>`, o pybind11 (via `pybind11/stl.h`) os
     * converte em `list` de `int`, e não em `bytes`: cada acesso
     * produz uma lista nova, copiada dos vetores C++.
     * \warning atributos `def_readonly` não impedem mutação do objeto
     * Python recebido (`list.append` funciona), mas a mudança não é
     * refletida no `KeyPair` C++, pois a lista é uma cópia.
     * \warning o `std::vector` de chave privada permanece em claro no
     * objeto C++ e o `list` de Python não tem como ser zerado.
     * @endcond
     * @cond INGLES
     * @brief Registers the C++ struct `zupt::KeyPair` as `KeyPair` in Python.
     * @details Exposes the two members as read-only attributes
     * (`def_readonly`). Since `public_key` and `secret_key` are
     * `std::vector<uint8_t>`, pybind11 (via `pybind11/stl.h`) converts them
     * into a `list` of `int`, and not into `bytes`: each access produces a
     * new list, copied from the C++ vectors.
     * \warning `def_readonly` attributes do not prevent mutation of the
     * Python object received (`list.append` works), but the change is not
     * reflected in the C++ `KeyPair`, because the list is a copy.
     * \warning the private key `std::vector` remains plaintext in the C++
     * object, and the Python `list` has no way to be zeroed.
     * @endcond */
    py::class_<zupt::KeyPair>(m, "KeyPair")
        /**
         * @cond PORT
         * @brief `KeyPair()` — construtor padrão.
         * @details Encaminha para `zupt::KeyPair()`. Os dois vetores ficam
         * vazios, de modo que `len(kp.public_key) == 0` logo após a
         * criação.
         * @endcond
         * @cond INGLES
         * @brief `KeyPair()` — default constructor.
         * @details Forwards to `zupt::KeyPair()`. The two vectors are left empty,
         * so `len(kp.public_key) == 0` right after creation.
         * @endcond */
        .def(py::init<>())
        /**
         * @cond PORT
         * Chave pública híbrida, devolvida como `list` de inteiros.
         * @endcond
         * @cond INGLES
         * Hybrid public key, returned as a `list` of integers.
         * @endcond */
        .def_readonly("public_key", &zupt::KeyPair::public_key)
        /**
         * @cond PORT
         * Chave secreta híbrida, devolvida como `list` de inteiros.
         * @endcond
         * @cond INGLES
         * Hybrid secret key, returned as a `list` of integers.
         * @endcond */
        .def_readonly("secret_key", &zupt::KeyPair::secret_key);

    // KeyGenerator class
    /**
     * @cond PORT
     * @brief Registra a classe C++ `zupt::KeyGenerator` como `KeyGenerator`.
     * @details As assinaturas Python divergem do nome C++ apenas na convenção
     * (`snake_case` contra `camelCase`): `generate_keypair`,
     * `load_keypair`, `load_public_key`, `export_public_key` e
     * `save_keypair`. Nenhum `py::arg` nomeia os parâmetros, então o
     * chamador só pode passar valores posicionalmente: tentar usar
     * palavras-chave levanta `TypeError`.
     * \note `save_keypair` e `export_public_key` escrevem em disco no
     * caminho informado pelo chamador; não há validação deste lado.
     * @endcond
     * @cond INGLES
     * @brief Registers the C++ class `zupt::KeyGenerator` as `KeyGenerator`.
     * @details The Python signatures differ from the C++ names only in
     * convention (`snake_case` versus `camelCase`): `generate_keypair`,
     * `load_keypair`, `load_public_key`, `export_public_key` and
     * `save_keypair`. No `py::arg` names the parameters, so the caller can
     * only pass values positionally: trying to use keywords raises
     * `TypeError`.
     * \note `save_keypair` and `export_public_key` write to disk at the path
     * given by the caller; there is no validation on this side.
     * @endcond */
    py::class_<zupt::KeyGenerator>(m, "KeyGenerator")
        /**
         * @cond PORT
         * @brief `KeyGenerator()` — construtor vazio.
         * @details Encaminha para `zupt::KeyGenerator()`, que não recebe
         * parâmetros.
         * @endcond
         * @cond INGLES
         * @brief `KeyGenerator()` — empty constructor.
         * @details Forwards to `zupt::KeyGenerator()`, which takes no parameters.
         * @endcond */
        .def(py::init<>())
        /**
         * @cond PORT
         * @brief `generate_keypair()` — gera um par de chaves híbrido.
         * @details Encaminhamento direto. O retorno é uma cópia da struct C++
         * convertida em objeto `KeyPair` de Python.
         * \warning ao contrário do binding Node.js, nenhum
         * `secureWipe` é aplicado ao `zupt::KeyPair` C++ local: ele é
         * convertido e depois destruído sem limpeza explícita.
         * @return Objeto `KeyPair` com as chaves geradas.
         * @endcond
         * @cond INGLES
         * @brief `generate_keypair()` — generates a hybrid key pair.
         * @details Direct forwarding. The return value is a copy of the C++
         * struct converted into a Python `KeyPair` object.
         * \warning unlike the Node.js binding, no `secureWipe` is applied to the
         * local `zupt::KeyPair` C++ object: it is converted and then destroyed
         * without explicit wiping.
         * @return `KeyPair` object with the generated keys.
         * @endcond */
        .def("generate_keypair", &zupt::KeyGenerator::generateKeyPair)
        /**
         * @cond PORT
         * @brief `load_keypair(filename)` — lê keypair de arquivo.
         * @details Encaminhamento direto para `zupt::KeyGenerator::loadKeyPair`.
         * Falhas de leitura/versão/magic chegam como exceção
         * `ZuptError` em Python.
         * - `filename`: Caminho do arquivo de chave privada híbrida.         * @return Objeto `KeyPair` carregado.
         * @endcond
         * @cond INGLES
         * @brief `load_keypair(filename)` — reads a keypair from a file.
         * @details Direct forwarding to `zupt::KeyGenerator::loadKeyPair`.
         * Read/version/magic failures arrive as a `ZuptError` exception in
         * Python.
         * - `filename`: Path of the hybrid private key file.         * @return Loaded `KeyPair` object.
         * @endcond */
        .def("load_keypair", &zupt::KeyGenerator::loadKeyPair)
        /**
         * @cond PORT
         * @brief `load_public_key(filename)` — lê chave pública de arquivo.
         * @details Encaminhamento direto. Como o retorno é `std::vector<uint8_t>`,
         * o pybind11 o entrega como `list` de inteiros, e não como
         * `bytes`.
         * \warning inconsistência com os métodos de cifra, que devolvem
         * `bytes`: aqui o chamador precisa de `bytes(load_public_key(...))`
         * para obter um `bytes`, e `bytes(list_de_ints)` funciona apenas
         * se todos os valores estiverem em `0..255`.
         * - `filename`: Caminho do arquivo de chave pública híbrida.         * @return `list` de inteiros com a chave pública lida.
         * @endcond
         * @cond INGLES
         * @brief `load_public_key(filename)` — reads a public key from a file.
         * @details Direct forwarding. Since the return value is
         * `std::vector<uint8_t>`, pybind11 delivers it as a `list` of integers,
         * and not as `bytes`.
         * \warning inconsistency with the cipher methods, which return `bytes`:
         * here the caller needs `bytes(load_public_key(...))` to obtain a
         * `bytes`, and `bytes(list_of_ints)` works only if all the values are
         * within `0..255`.
         * - `filename`: Path of the hybrid public key file.         * @return `list` of integers with the public key read.
         * @endcond */
        .def("load_public_key", &zupt::KeyGenerator::loadPublicKey)
        /**
         * @cond PORT
         * @brief `export_public_key(privfile, pubfile)` — extrai a chave pública.
         * @details Encaminhamento para
         * `zupt::KeyGenerator::exportPublicKey(privfile, pubfile)`: lê a
         * keypair privada de `privfile` e escreve apenas a parte pública
         * em `pubfile`. Nenhum valor é devolvido.
         * \warning sobrescreve `pubfile` sem aviso, e ambos os
         * caminhos vêm direto do chamador, sem validação.
         * - `privfile`: Caminho do arquivo de chave privada híbrida.         * - `pubfile`: Caminho do arquivo público de saída.
         * @endcond
         * @cond INGLES
         * @brief `export_public_key(privfile, pubfile)` — extracts the public key.
         * @details Forwarding to
         * `zupt::KeyGenerator::exportPublicKey(privfile, pubfile)`: it reads the
         * private keypair from `privfile` and writes only the public part to
         * `pubfile`. No value is returned.
         * \warning overwrites `pubfile` without warning, and both paths come
         * directly from the caller, without validation.
         * - `privfile`: Path of the hybrid private key file.         * - `pubfile`: Path of the public output file.
         * @endcond */
        .def("export_public_key", &zupt::KeyGenerator::exportPublicKey)
        /**
         * @cond PORT
         * @brief `save_keypair(keypair, filename)` — persiste a keypair.
         * @details Encaminhamento para
         * `zupt::KeyGenerator::saveKeyPair(const KeyPair&, const std::string&)`.
         * O primeiro argumento é o objeto `KeyPair` registrado pelo
         * pybind11, de modo que a função C++ recebe a instância
         * original, e não uma cópia convertida.
         * \warning não há checagem de que o objeto foi gerado ou
         * carregado: um `KeyPair()` vazio chega ao serializador com
         * vetores vazios.
         * - `keypair`: Objeto `KeyPair` a serializar.         * - `filename`: Caminho do arquivo de saída.
         * @endcond
         * @cond INGLES
         * @brief `save_keypair(keypair, filename)` — persists the keypair.
         * @details Forwarding to
         * `zupt::KeyGenerator::saveKeyPair(const KeyPair&, const std::string&)`.
         * The first argument is the `KeyPair` object registered by pybind11, so
         * the C++ function receives the original instance, and not a converted
         * copy.
         * \warning there is no check that the object was generated or loaded: an
         * empty `KeyPair()` reaches the serializer with empty vectors.
         * - `keypair`: `KeyPair` object to serialize.         * - `filename`: Path of the output file.
         * @endcond */
        .def("save_keypair", &zupt::KeyGenerator::saveKeyPair);

    // Encryptor class
    /**
     * @cond PORT
     * @brief Registra a classe C++ `zupt::Encryptor` como `Encryptor`.
     * @details Cinco pontos de entrada de cifra com semânticas diferentes de
     * conversão de entrada e de saída, o que obriga o chamador a
     * conhecer qual método está usando:
     * - `encrypt` e `encrypt_memory` devolvem `tuple(bytes, bytes)`;
     * - `encrypt_secure` devolve `tuple(list, list)` porque o retorno
     * passa direto pelo conversor STL de `std::vector<uint8_t>`;
     * - `encrypt_file` devolve `tuple(bytes, bytes)`;
     * - `HEADER_SIZE` é uma propriedade somente leitura de classe.
     * Nenhuma operação salva o arquivo cifrado em disco:
     * `encrypt_file` devolve o resultado em memória.
     * \note nenhum método é liberado do GIL explicitamente (`py::call_guard`
     * ausente), então a cifra bloqueia o interpretador durante a chamada.
     * @endcond
     * @cond INGLES
     * @brief Registers the C++ class `zupt::Encryptor` as `Encryptor`.
     * @details Five cipher entry points with different input-conversion and
     * output semantics, which forces the caller to know which method is
     * being used:
     * - `encrypt` and `encrypt_memory` return `tuple(bytes, bytes)`;
     * - `encrypt_secure` returns `tuple(list, list)` because the return
     * value passes straight through the STL converter of
     * `std::vector<uint8_t>`;
     * - `encrypt_file` returns `tuple(bytes, bytes)`;
     * - `HEADER_SIZE` is a read-only class property.
     * No operation saves the encrypted file to disk: `encrypt_file` returns
     * the result in memory.
     * \note no method explicitly releases the GIL (no `py::call_guard`), so
     * encryption blocks the interpreter during the call.
     * @endcond */
    py::class_<zupt::Encryptor>(m, "Encryptor")
        /**
         * @cond PORT
         * @brief `Encryptor(public_key)` — constrói o criptógrafo.
         * @details O argumento é `const std::vector<uint8_t>&`: o pybind11 aceita
         * `list`/`tuple` de inteiros e converte para um vetor temporário,
         * que é copiado para dentro do `zupt::Encryptor`.
         * \warning um `bytes` NÃO satisfaz essa assinatura: não existe
         * no pybind11 conversão de `bytes` para
         * `std::vector<uint8_t>`, de modo que a chamada falha com
         * `TypeError` de argumentos incompatíveis. O docstring de
         * `examples_python/__init__.py` mostra
         * `zupt.Encryptor(keypair.public_key)`, que só funciona porque
         * `public_key` chega como `list` de inteiros.
         * - `public_key`: Chave pública híbrida como sequência de inteiros.
         * @endcond
         * @cond INGLES
         * @brief `Encryptor(public_key)` — builds the encryptor.
         * @details The argument is `const std::vector<uint8_t>&`: pybind11
         * accepts a `list`/`tuple` of integers and converts it into a temporary
         * vector, which is copied into the `zupt::Encryptor`.
         * \warning a `bytes` does NOT satisfy this signature: pybind11 has no
         * conversion from `bytes` to `std::vector<uint8_t>`, so the call fails
         * with a `TypeError` of incompatible arguments. The docstring of
         * `examples_python/__init__.py` shows
         * `zupt.Encryptor(keypair.public_key)`, which only works because
         * `public_key` arrives as a `list` of integers.
         * - `public_key`: Hybrid public key, as a sequence of integers.
         * @endcond */
        .def(py::init<const std::vector<uint8_t>&>())
        /**
         * @cond PORT
         * @brief `encrypt(data)` — cifra texto claro vindo de `bytes`.
         * @details Converte `data` em `bytes` e depois em `std::string`, e chama
         * `zupt::Encryptor::encryptMemory(const uint8_t*, size_t)`. O
         * par `{ciphertext, enc_header}` é convertido em
         * `tuple(bytes, bytes)`.
         * <b>Cópia</b>: o texto claro passa por `std::string`
         * intermediário; nenhuma cópia é zerada.
         * \warning `data.cast<py::bytes>()` não está protegido por `try`:
         * se `data` não for conversível, o pybind11 levanta `TypeError`.
         * \warning este método e `encrypt_memory` fazem a mesma coisa com
         * assinaturas diferentes, e `encrypt_secure` faz a mesma cifra com
         * tipo de saída distinto.
         * - `data`: Texto claro como `bytes`.         * @return `tuple` `(ciphertext, enc_header)`, ambos `bytes`.
         * @see encrypt_memory, encrypt_secure
         * @endcond
         * @cond INGLES
         * @brief `encrypt(data)` — encrypts plaintext coming from `bytes`.
         * @details Converts `data` into `bytes` and then into `std::string`, and
         * calls `zupt::Encryptor::encryptMemory(const uint8_t*, size_t)`. The
         * `{ciphertext, enc_header}` pair is converted into
         * `tuple(bytes, bytes)`.
         * <b>Copy</b>: the plaintext passes through an intermediate
         * `std::string`; no copy is zeroed.
         * \warning `data.cast<py::bytes>()` is not protected by `try`: if `data`
         * is not convertible, pybind11 raises `TypeError`.
         * \warning this method and `encrypt_memory` do the same thing with
         * different signatures, and `encrypt_secure` performs the same
         * encryption with a different output type.
         * - `data`: Plaintext as `bytes`.         * @return `tuple` `(ciphertext, enc_header)`, both `bytes`.
         * @see encrypt_memory, encrypt_secure
         * @endcond */
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
         * @cond PORT
         * @brief `encrypt_memory(data, size)` — cifra a partir de endereço e contagem.
         * @details A assinatura C++ é `(const uint8_t* data, size_t size)`. O
         * pybind11 converte o primeiro parâmetro a partir de um
         * `int`/`None` interpretado como endereço, e o segundo a partir
         * de um inteiro.
         * \warning perigoso: qualquer número inteiro vale como
         * `data`, e o pybind11 não valida o endereço nem o comprimento.
         * Um chamador Python pode ler memória fora de qualquer buffer
         * controlado, inclusive fora do processo. Para texto comum use
         * `encrypt()`.
         * <b>Conversões</b>: o retorno é `tuple(bytes, bytes)`, como em
         * `encrypt()`.
         * - `data`: Endereço de memória inicial do texto claro, como inteiro.         * - `size`: Quantidade de bytes a cifrar.         * @return `tuple` `(ciphertext, enc_header)`, ambos `bytes`.
         * @see encrypt
         * @endcond
         * @cond INGLES
         * @brief `encrypt_memory(data, size)` — encrypts from an address and a count.
         * @details The C++ signature is `(const uint8_t* data, size_t size)`.
         * pybind11 converts the first parameter from an `int`/`None`
         * interpreted as an address, and the second from an integer.
         * \warning dangerous: any integer is accepted as `data`, and pybind11
         * validates neither the address nor the length. A Python caller can read
         * memory outside any controlled buffer, including outside the process.
         * For ordinary text use `encrypt()`.
         * <b>Conversions</b>: the return value is `tuple(bytes, bytes)`, as in
         * `encrypt()`.
         * - `data`: Starting memory address of the plaintext, as an integer.         * - `size`: Number of bytes to encrypt.         * @return `tuple` `(ciphertext, enc_header)`, both `bytes`.
         * @see encrypt
         * @endcond */
        .def("encrypt_memory", [](zupt::Encryptor& self, const uint8_t* data, size_t size) {
            auto result = self.encryptMemory(data, size);
            return py::make_tuple(
                py::bytes(reinterpret_cast<const char*>(result.first.data()), result.first.size()),
                py::bytes(reinterpret_cast<const char*>(result.second.data()), result.second.size())
            );
        })
        /**
         * @cond PORT
         * @brief `encrypt_secure(buffer)` — cifra o conteúdo de um `SecureBuffer`.
         * @details Chama `zupt::Encryptor::encryptMemory(const SecureBuffer&)`,
         * que lê o buffer internamente sem cópia adicional. O par de
         * vetores C++ é devolvido sem conversão para `py::bytes`, de modo
         * que o resultado chega como `tuple(list, list)` de inteiros.
         * \warning inconsistência de tipo de saída frente a `encrypt()` e
         * `encrypt_memory()`, que devolvem `bytes`. A conversão manual
         * `bytes(x)` para cada elemento da tupla é necessária para
         * interoperar com os métodos de decifragem que esperam `bytes`.
         * - `buffer`: Objeto `SecureBuffer` com o texto claro.         * @return `tuple` `(ciphertext, enc_header)`, ambos `list` de inteiros.
         * @see encrypt
         * @endcond
         * @cond INGLES
         * @brief `encrypt_secure(buffer)` — encrypts the content of a `SecureBuffer`.
         * @details Calls `zupt::Encryptor::encryptMemory(const SecureBuffer&)`,
         * which reads the buffer internally without an additional copy. The pair
         * of C++ vectors is returned without conversion to `py::bytes`, so the
         * result arrives as a `tuple(list, list)` of integers.
         * \warning output type inconsistency with respect to `encrypt()` and
         * `encrypt_memory()`, which return `bytes`. The manual conversion
         * `bytes(x)` for each element of the tuple is needed to interoperate
         * with the decryption methods that expect `bytes`.
         * - `buffer`: `SecureBuffer` object with the plaintext.         * @return `tuple` `(ciphertext, enc_header)`, both a `list` of integers.
         * @see encrypt
         * @endcond */
        .def("encrypt_secure", [](zupt::Encryptor& self, const zupt::SecureBuffer& buffer) {
            return self.encryptMemory(buffer);
        })
        /**
         * @cond PORT
         * @brief `encrypt_file(filename)` — cifra o conteúdo de um arquivo.
         * @details Lê o arquivo, cifra e devolve `tuple(bytes, bytes)`. Não
         * sobrescreve nem cria arquivo cifrado em disco.
         * \warning `filename` vem direto do chamador, sem validação;
         * falhas de leitura chegam como exceção `ZuptError`.
         * - `filename`: Caminho do arquivo em texto claro.         * @return `tuple` `(ciphertext, enc_header)`, ambos `bytes`.
         * @endcond
         * @cond INGLES
         * @brief `encrypt_file(filename)` — encrypts the content of a file.
         * @details Reads the file, encrypts it and returns
         * `tuple(bytes, bytes)`. It does not overwrite nor create an encrypted
         * file on disk.
         * \warning `filename` comes directly from the caller, without
         * validation; read failures arrive as a `ZuptError` exception.
         * - `filename`: Path of the plaintext file.         * @return `tuple` `(ciphertext, enc_header)`, both `bytes`.
         * @endcond */
        .def("encrypt_file", [](zupt::Encryptor& self, const std::string& filename) {
            auto [ciphertext, enc_header] = self.encryptFile(filename);
            return py::make_tuple(
                py::bytes(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size()),
                py::bytes(reinterpret_cast<const char*>(enc_header.data()), enc_header.size())
            );
        })
        /**
         * @cond PORT
         * @brief Propriedade de classe `Encryptor.HEADER_SIZE`.
         * @details Getter estático que devolve o que
         * `zupt::Encryptor::getEncryptionHeaderSize()` retorna — a
         * constante `HYBRID_ENC_HEADER_SIZE`, 1137 bytes.
         * `def_property_readonly_static` a apresenta como atributo de
         * classe, e não como método: `zupt.Encryptor.HEADER_SIZE` é um
         * `int`.
         * \note o valor é lido a cada acesso, mas é constante; não há
         * estado envolvido.
         * @return Inteiro com o tamanho do cabeçalho de cifra, em bytes.
         * @endcond
         * @cond INGLES
         * @brief `Encryptor.HEADER_SIZE` class property.
         * @details Static getter that returns what
         * `zupt::Encryptor::getEncryptionHeaderSize()` returns — the constant
         * `HYBRID_ENC_HEADER_SIZE`, 1137 bytes.
         * `def_property_readonly_static` presents it as a class attribute, and
         * not as a method: `zupt.Encryptor.HEADER_SIZE` is an `int`.
         * \note the value is read on each access, but it is constant; no state
         * is involved.
         * @return Integer with the size of the encryption header, in bytes.
         * @endcond */
        .def_property_readonly_static("HEADER_SIZE", [](py::object) {
            return zupt::Encryptor::getEncryptionHeaderSize();
        });

    // Decryptor class
    /**
     * @cond PORT
     * @brief Registra a classe C++ `zupt::Decryptor` como `Decryptor`.
     * @details Quatro métodos de decifragem, cada um com conversão própria:
     * `decrypt` aceita `bytes` ou sequência de inteiros e devolve
     * `bytes`; `decrypt_memory` recebe endereço e contagem e devolve
     * `list` de inteiros; `decrypt_secure` recebe dois vetores e devolve
     * um objeto `SecureBuffer`; `decrypt_file` lê o arquivo cifrado e
     * devolve `bytes`.
     * \note nenhum método é liberado do GIL, e nenhum captura exceções
     * além do `try`/`catch (...)` de `decrypt` e `decrypt_file`.
     * @endcond
     * @cond INGLES
     * @brief Registers the C++ class `zupt::Decryptor` as `Decryptor`.
     * @details Four decryption methods, each with its own conversion:
     * `decrypt` accepts `bytes` or a sequence of integers and returns
     * `bytes`; `decrypt_memory` receives an address and a count and returns
     * a `list` of integers; `decrypt_secure` receives two vectors and
     * returns a `SecureBuffer` object; `decrypt_file` reads the encrypted
     * file and returns `bytes`.
     * \note no method releases the GIL, and none catches exceptions beyond
     * the `try`/`catch (...)` of `decrypt` and `decrypt_file`.
     * @endcond */
    py::class_<zupt::Decryptor>(m, "Decryptor")
        /**
         * @cond PORT
         * @brief `Decryptor(private_key)` — constrói o descriptógrafo.
         * @details O argumento é `const std::vector<uint8_t>&`, aceito como
         * `list`/`tuple` de inteiros; o pybind11 cria um vetor temporário
         * que o construtor de libzupt copia.
         * \warning um `bytes` não é aceito por essa assinatura (não há
         * conversão `bytes` para `std::vector<uint8_t>`), então a chave
         * privada precisa vir da `list` de `KeyPair.secret_key` ou de
         * conversão explícita pelo chamador.
         * \note o `std::vector` temporário criado pelo conversor não é
         * zerado depois, de modo que a chave privada fica em claro no
         * heap até a liberação do objeto Python que a originou.
         * - `private_key`: Chave privada híbrida como sequência de inteiros.
         * @endcond
         * @cond INGLES
         * @brief `Decryptor(private_key)` — builds the decryptor.
         * @details The argument is `const std::vector<uint8_t>&`, accepted as a
         * `list`/`tuple` of integers; pybind11 creates a temporary vector that
         * the libzupt constructor copies.
         * \warning a `bytes` is not accepted by this signature (there is no
         * `bytes` to `std::vector<uint8_t>` conversion), so the private key must
         * come from the `list` of `KeyPair.secret_key` or from an explicit
         * conversion by the caller.
         * \note the temporary `std::vector` created by the converter is not
         * zeroed afterwards, so the private key stays plaintext on the heap
         * until the Python object that originated it is released.
         * - `private_key`: Hybrid private key, as a sequence of integers.
         * @endcond */
        .def(py::init<const std::vector<uint8_t>&>())
        /**
         * @cond PORT
         * @brief `decrypt(ciphertext, enc_header)` — decifra texto cifrado.
         * @details Dois ramos de conversão do primeiro argumento, encadeados por
         * `try`/`catch (...)`: primeiro tenta `bytes`, depois `list` de
         * inteiros (montando uma `std::string` de mesmo comprimento e
         * preenchendo byte a byte com `py::cast<uint8_t>`, que rejeita
         * valores fora de `0..255`). O cabeçalho entra como
         * `const std::vector<uint8_t>&`, aceitando `list` de inteiros.
         * O texto claro é devolvido como `bytes`.
         * <b>Cópia</b>: o texto claro existe em `std::string` de entrada,
         * `std::vector` de saída e no objeto `bytes` devolvido; nenhuma
         * das três é zerada.
         * \warning o `catch (...)` engolfa qualquer causa, inclusive
         * erro de Python pendente, e cai no ramo de `list`, o que gera
         * mensagens enganosas.
         * \warning inconsistência com `decrypt_secure`: este método usa
         * `decryptMemory` comum, que não limpa o texto claro.
         * - `ciphertext`: Texto cifrado como `bytes` ou sequência de inteiros.         * - `enc_header`: Cabeçalho de cifra como sequência de inteiros.         * @return `bytes` com o texto claro.
         * @see decrypt_secure
         * @endcond
         * @cond INGLES
         * @brief `decrypt(ciphertext, enc_header)` — decrypts ciphertext.
         * @details Two conversion branches for the first argument, chained by
         * `try`/`catch (...)`: first it tries `bytes`, then a `list` of
         * integers (building a `std::string` of the same length and filling it
         * byte by byte with `py::cast<uint8_t>`, which rejects values outside
         * `0..255`). The header enters as `const std::vector<uint8_t>&`,
         * accepting a `list` of integers. The plaintext is returned as `bytes`.
         * <b>Copy</b>: the plaintext exists in the input `std::string`, the
         * output `std::vector` and the returned `bytes` object; none of the
         * three is zeroed.
         * \warning the `catch (...)` swallows any cause, including a pending
         * Python error, and falls into the `list` branch, which produces
         * misleading messages.
         * \warning inconsistency with `decrypt_secure`: this method uses the
         * plain `decryptMemory`, which does not wipe the plaintext.
         * - `ciphertext`: Ciphertext as `bytes` or as a sequence of integers.         * - `enc_header`: Encryption header, as a sequence of integers.         * @return `bytes` with the plaintext.
         * @see decrypt_secure
         * @endcond */
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
         * @cond PORT
         * @brief `decrypt_memory(ciphertext, ciphertextSize, enc_header)`.
         * @details Recebe o texto cifrado como endereço inteiro e contagem, como
         * na versão homóloga de `Encryptor`, e devolve o resultado
         * diretamente: o `std::vector<uint8_t>` de libzupt é convertido
         * pelo pybind11 em `list` de inteiros.
         * \warning o endereço não é validado: qualquer inteiro é aceito,
         * e ler além da memória mapeada derruba o processo.
         * \warning inconsistência de tipo de saída: `decrypt` devolve
         * `bytes` e este método devolve `list`.
         * - `ciphertext`: Endereço de memória do texto cifrado, como inteiro.         * - `ciphertextSize`: Quantidade de bytes de texto cifrado.         * - `enc_header`: Cabeçalho de cifra como sequência de inteiros.         * @return `list` de inteiros com o texto claro.
         * @see decrypt
         * @endcond
         * @cond INGLES
         * @brief `decrypt_memory(ciphertext, ciphertextSize, enc_header)`.
         * @details Receives the ciphertext as an integer address and a count, as
         * in the counterpart version of `Encryptor`, and returns the result
         * directly: the libzupt `std::vector<uint8_t>` is converted by pybind11
         * into a `list` of integers.
         * \warning the address is not validated: any integer is accepted, and
         * reading beyond mapped memory brings the process down.
         * \warning output type inconsistency: `decrypt` returns `bytes` and this
         * method returns `list`.
         * - `ciphertext`: Memory address of the ciphertext, as an integer.         * - `ciphertextSize`: Number of bytes of ciphertext.         * - `enc_header`: Encryption header, as a sequence of integers.         * @return `list` of integers with the plaintext.
         * @see decrypt
         * @endcond */
        .def("decrypt_memory", [](zupt::Decryptor& self, const uint8_t* ciphertext, size_t ciphertextSize,
                                   const std::vector<uint8_t>& enc_header) {
            return self.decryptMemory(ciphertext, ciphertextSize, enc_header);
        })
        /**
         * @cond PORT
         * @brief `decrypt_secure(ciphertext, enc_header)` — decifra com limpeza.
         * @details Chama `zupt::Decryptor::decryptMemorySecure(const std::vector<uint8_t>&, const std::vector<uint8_t>&)`,
         * que zera o texto claro em buffers internos durante o processo.
         * O retorno é um `zupt::SecureBuffer`, apresentado em Python como
         * o objeto `SecureBuffer` registrado neste módulo.
         * <b>Recomendação de uso</b>: é o único caminho de decifragem
         * deste binding que mantém o texto claro sob controle, pois o
         * `SecureBuffer` zera o conteúdo quando o objeto Python morre.
         * \warning o texto cifrado de entrada, convertido pelo pybind11,
         * continua sem limpeza.
         * - `ciphertext`: Texto cifrado como sequência de inteiros.         * - `enc_header`: Cabeçalho de cifra como sequência de inteiros.         * @return Objeto `SecureBuffer` com o texto claro.
         * @endcond
         * @cond INGLES
         * @brief `decrypt_secure(ciphertext, enc_header)` — decrypts with wiping.
         * @details Calls
         * `zupt::Decryptor::decryptMemorySecure(const std::vector<uint8_t>&, const std::vector<uint8_t>&)`,
         * which zeroes the plaintext in internal buffers during the process. The
         * return value is a `zupt::SecureBuffer`, presented in Python as the
         * `SecureBuffer` object registered in this module.
         * <b>Usage recommendation</b>: it is the only decryption path of this
         * binding that keeps the plaintext under control, because the
         * `SecureBuffer` zeroes its content when the Python object dies.
         * \warning the input ciphertext, converted by pybind11, remains unwiped.
         * - `ciphertext`: Ciphertext as a sequence of integers.         * - `enc_header`: Encryption header, as a sequence of integers.         * @return `SecureBuffer` object with the plaintext.
         * @endcond */
        .def("decrypt_secure", [](zupt::Decryptor& self, const std::vector<uint8_t>& ciphertext,
                                   const std::vector<uint8_t>& enc_header) {
            return self.decryptMemorySecure(ciphertext, enc_header);
        })
        /**
         * @cond PORT
         * @brief `decrypt_file(filename, enc_header)` — decifra um arquivo.
         * @details Converte o cabeçalho (ramos `bytes` ou `list` de inteiros, o
         * mesmo padrão dos outros métodos) e chama
         * `zupt::Decryptor::decryptFile(filename, enc_header)`, que lê o
         * arquivo cifrado e devolve o texto claro em memória. Nada é
         * escrito em disco.
         * \warning `filename` vem direto do chamador, sem validação; e o
         * `catch (...)` do ramo de conversão engolfa qualquer causa.
         * - `filename`: Caminho do arquivo cifrado.         * - `enc_header`: Cabeçalho de cifra como `bytes` ou sequência de         *                       inteiros.
         * @return `bytes` com o texto claro.
         * @endcond
         * @cond INGLES
         * @brief `decrypt_file(filename, enc_header)` — decrypts a file.
         * @details Converts the header (`bytes` or `list` of integers branches,
         * the same pattern as the other methods) and calls
         * `zupt::Decryptor::decryptFile(filename, enc_header)`, which reads the
         * encrypted file and returns the plaintext in memory. Nothing is written
         * to disk.
         * \warning `filename` comes directly from the caller, without
         * validation; and the `catch (...)` of the conversion branch swallows
         * any cause.
         * - `filename`: Path of the encrypted file.         * - `enc_header`: Encryption header as `bytes` or as a sequence of         *                       integers.
         * @return `bytes` with the plaintext.
         * @endcond */
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
     * @cond PORT
     * @brief `random_bytes(size)` — devolve aleatórios criptográficos.
     * @details Chama `zupt::randomBytes(size)` e converte o vetor resultante em
     * `bytes` por `py::bytes`, o que copia os dados.
     * <b>Conversão</b>: o argumento é `size_t`; valores negativos e
     * acima do suportado são rejeitados pelo pybind11 antes da chamada.
     * - `size`: Quantidade de bytes aleatórios desejados.     * @return `bytes` com os aleatórios.
     * @endcond
     * @cond INGLES
     * @brief `random_bytes(size)` — returns cryptographically secure random bytes.
     * @details Calls `zupt::randomBytes(size)` and converts the resulting
     * vector into `bytes` by `py::bytes`, which copies the data.
     * <b>Conversion</b>: the argument is `size_t`; negative values and values
     * above the supported limit are rejected by pybind11 before the call.
     * - `size`: Number of random bytes wanted.     * @return `bytes` with the random bytes.
     * @endcond */
    m.def("random_bytes", [](size_t size) {
        std::vector<uint8_t> result = zupt::randomBytes(size);
        return py::bytes(reinterpret_cast<const char*>(result.data()), result.size());
    });
    /**
     * @cond PORT
     * @brief `sha256(data)` — digest SHA-256 de um dado binário.
     * @details Converte `data` para `bytes` e depois para `std::string`; chama
     * `zupt::sha256(const uint8_t*, size_t)` e devolve os 32 bytes do
     * digest como `bytes`.
     * \warning a conversão para `bytes` não é protegida por `try`,
     * então um argumento não conversível levanta `TypeError`. Nenhum
     * `str` é aceito implicitamente além do que `py::bytes` aceita.
     * - `data`: Conteúdo a resumir, como `bytes`.     * @return `bytes` com os 32 bytes do digest SHA-256.
     * @see sha3_512
     * @endcond
     * @cond INGLES
     * @brief `sha256(data)` — SHA-256 digest of a binary datum.
     * @details Converts `data` to `bytes` and then to `std::string`; calls
     * `zupt::sha256(const uint8_t*, size_t)` and returns the 32 bytes of the
     * digest as `bytes`.
     * \warning the conversion to `bytes` is not protected by `try`, so a
     * non-convertible argument raises `TypeError`. No `str` is accepted
     * implicitly beyond what `py::bytes` accepts.
     * - `data`: Content to hash, as `bytes`.     * @return `bytes` with the 32 bytes of the SHA-256 digest.
     * @see sha3_512
     * @endcond */
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
     * @cond PORT
     * @brief `sha3_512(data)` — digest SHA3-512 de um dado binário.
     * @details Mesmo padrão de `sha256`: converte para `bytes`, depois para
     * `std::string`, chama
     * `zupt::sha3_512(const uint8_t*, size_t)` e devolve o digest como
     * `bytes`.
     * \warning conversão não protegida: argumento não conversível
     * levanta `TypeError`.
     * - `data`: Conteúdo a resumir, como `bytes`.     * @return `bytes` com o digest SHA3-512.
     * @see sha256
     * @endcond
     * @cond INGLES
     * @brief `sha3_512(data)` — SHA3-512 digest of a binary datum.
     * @details Same pattern as `sha256`: converts to `bytes`, then to
     * `std::string`, calls
     * `zupt::sha3_512(const uint8_t*, size_t)` and returns the digest as
     * `bytes`.
     * \warning unprotected conversion: a non-convertible argument raises
     * `TypeError`.
     * - `data`: Content to hash, as `bytes`.     * @return `bytes` with the SHA3-512 digest.
     * @see sha256
     * @endcond */
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
     * @cond PORT
     * @brief `secure_wipe(ptr, size)` — limpa memória no processo.
     * @details Encaminhamento direto para `zupt::secureWipe(void*, size_t)`.
     * O pybind11 converte o primeiro parâmetro a partir de um inteiro
     * interpretado como endereço, e o segundo a partir de um inteiro.
     * \warning extremamente perigoso para uso em Python: não há
     * validação do endereço nem do tamanho, e `nullptr` com `size > 0`
     * é comportamento indefinido. Passar `0` com `size > 0` derruba o
     * processo. Existe sobretudo para interagir com os endereços
     * devolvidos por `SecureBuffer.data_ptr()`.
     * - `ptr`: Endereço inicial do buffer a apagar, como inteiro.     * - `size`: Quantidade de bytes a apagar.
     * @endcond
     * @cond INGLES
     * @brief `secure_wipe(ptr, size)` — wipes memory in the process.
     * @details Direct forwarding to `zupt::secureWipe(void*, size_t)`. The
     * pybind11 converts the first parameter from an integer interpreted as
     * an address, and the second from an integer.
     * \warning extremely dangerous for use in Python: there is no validation
     * of the address nor of the size, and `nullptr` with `size > 0` is
     * undefined behavior. Passing `0` with `size > 0` brings the process
     * down. It exists mainly to interact with the addresses returned by
     * `SecureBuffer.data_ptr()`.
     * - `ptr`: Starting address of the buffer to erase, as an integer.     * - `size`: Number of bytes to erase.
     * @endcond */
    m.def("secure_wipe", &zupt::secureWipe);

    // Version info
    /**
     * @cond PORT
     * @brief `zupt.__version__` — versão da biblioteca compartilhada.
     * @details Recebe `const char*` de `zupt::getVersion()`; o pybind11 o
     * converte em `str` de Python. Convencão de atributo do pacote:
     * `examples_python/__init__.py` faz
     * `__version__ = zupt.__version__`.
     * \warning não há checagem de ponteiro nulo: se a função devolver
     * `nullptr`, a conversão derruba o processo.
     * @endcond
     * @cond INGLES
     * @brief `zupt.__version__` — version of the shared library.
     * @details Receives `const char*` from `zupt::getVersion()`; pybind11
     * converts it into a Python `str`. Package attribute convention:
     * `examples_python/__init__.py` does
     * `__version__ = zupt.__version__`.
     * \warning there is no null pointer check: if the function returns
     * `nullptr`, the conversion brings the process down.
     * @endcond */
    m.attr("__version__") = zupt::getVersion();
    /**
     * @cond PORT
     * @brief `zupt.LIBRARY_NAME` — nome da biblioteca compartilhada.
     * @details Recebe `const char*` de `zupt::getLibraryName()` convertido em
     * `str`. É informativo: nenhum código deste binding usa o valor.
     * @endcond
     * @cond INGLES
     * @brief `zupt.LIBRARY_NAME` — name of the shared library.
     * @details Receives `const char*` from `zupt::getLibraryName()` converted
     * into `str`. It is informative: no code of this binding uses the value.
     * @endcond */
    m.attr("LIBRARY_NAME") = zupt::getLibraryName();
}