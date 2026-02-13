#include "../tests/common.hpp"
#include <array>
#include <cstdint>
#include <iostream>
#include <vector>

#include "bits/substitute.hpp"

using namespace crypto::bits;

int main() {
  std::vector<uint8_t> bits = {0b00001111};
  std::array<uint8_t, 256> s_block;

  for (int i = 0; i < 16; i++)
    s_block[i] = i;

  auto out = substitute(bits, s_block, 4, 2);
  printf("%b\n", out[0]);
}
