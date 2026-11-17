#pragma once
#include <cstdlib>
#include <stdexcept>
#include <string>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <unistd.h>
#endif

inline std::string testPath(const std::string& name) {
    static const auto root = [] {
#ifdef _WIN32
        char temp[MAX_PATH + 1];
        const DWORD length = GetTempPathA(sizeof(temp), temp);
        if (length == 0 || length >= sizeof(temp))
            throw std::runtime_error("Cannot locate the temporary directory");
        const std::string prefix = std::string(temp) + "libzupt-tests-" +
            std::to_string(GetCurrentProcessId()) + "-" +
            std::to_string(GetTickCount64()) + "-";
        for (unsigned attempt = 0; attempt < 128; ++attempt) {
            const std::string candidate = prefix + std::to_string(attempt);
            if (CreateDirectoryA(candidate.c_str(), nullptr)) return candidate;
            if (GetLastError() != ERROR_ALREADY_EXISTS)
                throw std::runtime_error("Cannot create the temporary test directory");
        }
        throw std::runtime_error("Cannot create a unique temporary test directory");
#else
        const char* configured = std::getenv("TMPDIR");
        std::string base = configured && *configured ? configured : "/tmp";
        if (base.back() != '/') base += '/';
        const std::string pattern = base + "libzupt-tests-XXXXXX";
        std::vector<char> path(pattern.begin(), pattern.end());
        path.push_back('\0');
        // Atomic creation with mode 0700; no shared predictable test directory.
        char* created = ::mkdtemp(path.data());
        if (!created)
            throw std::runtime_error("Cannot create the temporary test directory");
        return std::string(created);
#endif
    }();
    return root + "/" + name;
}
