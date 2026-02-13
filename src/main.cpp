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
  // std::vector<uint8_t> data = bits_from_string("110011010000");
  // std::vector<uint8_t> mask = bits_from_string("111100000000");
  // size_t mask_bits = 12;
  //
  // std::cout << "Original: " << bits_to_string(data) << std::endl;
  // std::cout << "Mask: " << bits_to_string(mask) << std::endl;
  //
  // auto and_result = apply_mask(data, mask, mask_bits, MaskType::And);
  // auto or_result = apply_mask(data, mask, mask_bits, MaskType::Or);
  // auto xor_result = apply_mask(data, mask, mask_bits, MaskType::Xor);
  //
  // std::cout << "AND Masked: " << bits_to_string(and_result) << std::endl;
  // std::cout << "OR Masked : " << bits_to_string(or_result) << std::endl;
  // std::cout << "XOR Masked: " << bits_to_string(xor_result) << std::endl;

  auto bits = bits_from_string("1010011011010011");
  auto expected = bits_from_string("1111001111001100");
  std::vector<size_t> indexes = {2,  2,  1, 1, 6,  6,  5,  5,
                                 10, 10, 9, 9, 14, 14, 13, 13};

  auto ans = permute(bits, indexes, BitOrder::LittleEndian, BitIndexBase::One);
  std::cout << bits_to_string(bits) << " source" << std::endl;
  std::cout << bits_to_string(ans) << " res" << std::endl;
  std::cout << bits_to_string(expected) << " expected" << std::endl;

  return 0;
}
