// SPDX-License-Identifier: MIT
#include "zupt.hpp"
#include <iostream>
#include <utility>

int main() {
    zupt::SecureBuffer original(std::vector<uint8_t>{1, 2, 3});
    zupt::SecureBuffer moved(std::move(original));
    if (original.size() != 0 || original.data() != nullptr) {
        std::cerr << "Moved-from buffer must be empty\n";
        return 1;
    }
    if (!original.toVector().empty() || !original.toString().empty()) return 1;
    zupt::SecureBuffer destination(std::vector<uint8_t>{4, 5});
    destination = std::move(moved);
    if (moved.size() != 0 || moved.data() != nullptr) return 1;
    if (destination.toVector() != std::vector<uint8_t>{1, 2, 3}) return 1;
    destination.zeroize();
    return destination.toVector() == std::vector<uint8_t>{0, 0, 0} ? 0 : 1;
}
