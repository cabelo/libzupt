// SPDX-License-Identifier: MIT
#include "zupt.hpp"
#include <fstream>
#include <iostream>
#include <sys/stat.h>
#include <unistd.h>
extern "C" {
#include "zupt.h"
}

int main() {
    zupt::KeyGenerator keygen;
    const auto keys = keygen.generateKeyPair();
    const char* victim = "key-storage-victim";
    const char* link = "key-storage-link";
    std::ofstream(victim) << "keep this file";
    if (symlink(victim, link) != 0) return 1;
    bool rejected = false;
    try {
        keygen.saveKeyPair(keys, link);
    } catch (const zupt::ZuptError& error) {
        rejected = error.code() == zupt::ErrorCode::ERR_IO;
    }
    std::string content;
    std::getline(std::ifstream(victim), content);
    unlink(link);
    unlink(victim);
    if (!rejected || content != "keep this file") {
        std::cerr << "Private key saving must reject symlinks without changing their targets\n";
        return 1;
    }
    std::ofstream(victim) << "old contents";
    if (chmod(victim, 0644) != 0) return 1;
    keygen.saveKeyPair(keys, victim);
    struct stat st {};
    if (stat(victim, &st) != 0) return 1;
    const auto loaded = keygen.loadKeyPair(victim);
    unlink(victim);
    if ((st.st_mode & 0777) != 0600 || loaded.secret_key != keys.secret_key) return 1;

    std::ofstream(victim) << "keep this hardlinked file";
    if (::link(victim, link) != 0) return 1;
    rejected = false;
    try { keygen.saveKeyPair(keys, link); }
    catch (const zupt::ZuptError&) { rejected = true; }
    std::getline(std::ifstream(victim), content);
    unlink(link);
    unlink(victim);
    if (!rejected || content != "keep this hardlinked file") return 1;
    if (mkfifo(link, 0600) != 0) return 1;
    rejected = false;
    try { keygen.saveKeyPair(keys, link); }
    catch (const zupt::ZuptError&) { rejected = true; }
    unlink(link);
    if (!rejected) return 1;

    std::ofstream(victim) << "old contents";
    if (chmod(victim, 0644) != 0) return 1;
    if (zupt_hybrid_keygen(victim) != 0 || stat(victim, &st) != 0) return 1;
    unlink(victim);
    if ((st.st_mode & 0777) != 0600) {
        std::cerr << "Low-level private key generation must tighten existing permissions\n";
        return 1;
    }
    return 0;
}
