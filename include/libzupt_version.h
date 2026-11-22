/* SPDX-License-Identifier: MIT */
/**
 * @cond PORT
 * @file  libzupt_version.h
 * @brief Constante de versão da biblioteca, lida pelo CMake.
 * @details Este é o cabeçalho instalado (ver `install(FILES ...)` no
 * CMakeLists.txt) e a fonte canônica usada pelo CMakeLists.txt para
 * derivar `PROJECT_VERSION`, `SOVERSION` e o nome do pacote.
 * O CMake extrai o valor com uma expressão regular aplicada à linha
 * a linha que define `LIBZUPT_VERSION_STRING`, de modo que a macro precisa
 * permanecer no início da linha e conter exatamente "major.minor.patch".
 *
 * @note A árvore do repositório contém três versões divergentes registradas em
 * lugares diferentes: `LIBZUPT_VERSION_STRING` (aqui, "1.0.15"),
 * `ZUPT_VERSION_STRING` em include/zupt.h ("2.1.5") e "2.0.0" no
 * README.md e no CHANGES.md. Esta documentação descreve os valores como
 * estão; a divergência está registrada como pendência e não foi
 * harmonizada.
 * @see ZUPT_VERSION_STRING
 * @endcond
 * @cond INGLES
 * @file  libzupt_version.h
 * @brief Library version constant, read by CMake.
 * @details This is the installed header (see `install(FILES ...)` in
 * CMakeLists.txt) and the canonical source used by CMakeLists.txt to
 * derive `PROJECT_VERSION`, `SOVERSION` and the package name.
 * CMake extracts the value with a regular expression applied to the
 * line that defines `LIBZUPT_VERSION_STRING`, so the macro must
 * remain at the beginning of the line and contain exactly "major.minor.patch".
 *
 * @note The repository tree contains three divergent versions recorded in
 * different places: `LIBZUPT_VERSION_STRING` (here, "1.0.15"),
 * `ZUPT_VERSION_STRING` in include/zupt.h ("2.1.5") and "2.0.0" in
 * README.md and in CHANGES.md. This documentation describes the values as
 * they are; the divergence is recorded as a pending item and has not
 * been harmonized.
 * @see ZUPT_VERSION_STRING
 * @endcond */
#ifndef LIBZUPT_VERSION_H
#define LIBZUPT_VERSION_H

/**
 * @cond PORT
 * @def LIBZUPT_VERSION_STRING
 * @brief Versão da biblioteca no formato "major.minor.patch".
 * @details Usada pelo CMakeLists.txt como `PROJECT_VERSION` e, portanto,
 * como `SOVERSION` (major) da biblioteca compartilhada `libzupt`.
 * @endcond
 * @cond INGLES
 * @def LIBZUPT_VERSION_STRING
 * @brief Library version in "major.minor.patch" format.
 * @details Used by CMakeLists.txt as `PROJECT_VERSION` and, therefore,
 * as the `SOVERSION` (major) of the `libzupt` shared library.
 * @endcond */
#define LIBZUPT_VERSION_STRING "1.0.15"

#endif
