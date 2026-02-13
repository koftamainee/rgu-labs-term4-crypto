#include "../tests/common.hpp"
#include <array>
#include <cstdint>
#include <iostream>
#include <sys/types.h>
#include <vector>

#include "bits/permute.hpp"
#include "bits/utils.hpp"

using namespace crypto::bits;

int main() {
  std::vector<uint8_t> data = bits_from_string("110011010000");
  std::vector<uint8_t> mask = bits_from_string("111100000000");
  size_t mask_bits = 12;

  std::cout << "Original: " << bits_to_string(data) << std::endl;
  std::cout << "Mask: " << bits_to_string(mask) << std::endl;

  auto and_result = apply_mask(data, mask, mask_bits, MaskType::And);
  auto or_result = apply_mask(data, mask, mask_bits, MaskType::Or);
  auto xor_result = apply_mask(data, mask, mask_bits, MaskType::Xor);

  std::cout << "AND Masked: " << bits_to_string(and_result) << std::endl;
  std::cout << "OR Masked : " << bits_to_string(or_result) << std::endl;
  std::cout << "XOR Masked: " << bits_to_string(xor_result) << std::endl;

  auto b = get_bits(or_result, 2, 8);
  std::cout << "2 to 8th bits from xor result: " << bits_to_string(b)
            << std::endl;

  return 0;
}
