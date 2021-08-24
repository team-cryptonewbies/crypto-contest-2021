#include <climits>
#include <fstream>
#include <iostream>

#include "./prince_ref.h"

const uint64_t k0 = 0x687a717a7a6c7073;
const uint64_t k1 = 0x7567737568637072;

static inline uint64_t rotr64(uint64_t n, unsigned int c) {
  const unsigned int mask = (CHAR_BIT * sizeof(n) - 1);

  // assert ( (c<=mask) &&"rotate by type width or more");
  c &= mask;
  return (n >> c) | (n << ((-c) & mask));
}

inline uint64_t encrypt(const uint64_t plaintext, const uint64_t k0,
                        const uint64_t k1) {
  uint64_t k0_prime = rotr64(k0, 1) ^ (k0 >> 63);
  uint64_t state = plaintext;

  // whitening
  state ^= k0;

  // round 1
  state ^= k1;
  state ^= prince_round_constant(0);

  // round 2
  state = prince_s_layer(state);
  state = prince_m_layer(state);
  state ^= prince_round_constant(1);
  state ^= k1;

  // middle layer
  state = prince_s_layer(state);
  state = prince_m_prime_layer(state);
  state = prince_s_inv_layer(state);

  // round 3
  state ^= prince_round_constant(2);
  state ^= k1;
  state = prince_m_inv_layer(state);
  state = prince_s_inv_layer(state);

  // round 4
  state ^= prince_round_constant(3);
  state ^= k1;

  // whitening
  state ^= k0_prime;
  return state;
}

int main() {
  std::ifstream plaintext_file("./pt.dat");
  std::ifstream ciphertext_file("./ct.dat");
  while (true) {
    uint64_t plaintext_block, ciphertext_block;
    if (!plaintext_file.read(reinterpret_cast<char *>(&plaintext_block),
                             sizeof(uint64_t))) {
      break;
    }
    ciphertext_file.read(reinterpret_cast<char *>(&ciphertext_block),
                         sizeof(uint64_t));
    std::cout << "Testing: " << std::hex << plaintext_block << " -> "
              << std::hex << ciphertext_block << std::dec << std::endl;
    if (encrypt(plaintext_block, k0, k1) != ciphertext_block)
      std::cout << "Mismatch: " << std::hex << encrypt(plaintext_block, k0, k1)
                << ciphertext_block << std::dec << std::endl;
  }
  return 0;
}
