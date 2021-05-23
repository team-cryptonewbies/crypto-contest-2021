#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>

#include "./prince_ref.h"

inline uint64_t partial_prince(const uint64_t plaintext,
                               const uint64_t k0_prime, const uint64_t k1) {
  uint64_t k0 = (k0_prime << 1) | (k0_prime >> 63);
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

  // round 3 (partial)
  state ^= prince_round_constant(2);
  state ^= k1;

  return state;
}

uint64_t decode_last_round(uint64_t ciphertext, uint64_t k0_prime_xor_k1) {
  uint64_t state = ciphertext;
  state ^= k0_prime_xor_k1;
  state ^= prince_round_constant(3);
  state = prince_s_layer(state);
  state = prince_m_layer(state);
  return state;
}

int main(int argc, char* argv[]) {
  std::ifstream fin("./bruteforce_input.txt");
  uint64_t plaintext_sample, ciphertext_sample, k0_prime_xor_k1,
      k0_prime_template, k1_template;
  fin >> std::hex >> plaintext_sample >> ciphertext_sample >> k0_prime_xor_k1 >>
      k0_prime_template >> k1_template;
  uint8_t xored_nibbles[8];
  for (int i = 0; i < 8; ++i)
    xored_nibbles[i] = (k0_prime_xor_k1 >> ((7 - i) * 8)) & 0b00001111;

  const uint8_t first_nib = atoi(argv[1]);
  uint8_t nibs[8] = {
      first_nib,
      0,
  };
  const uint64_t partial_decoded =
      decode_last_round(ciphertext_sample, k0_prime_xor_k1);
  std::cout << std::hex;
  for (nibs[1] = 0; nibs[1] < 16; ++nibs[1])
    for (nibs[2] = 0; nibs[2] < 16; ++nibs[2])
      for (nibs[3] = 0; nibs[3] < 16; ++nibs[3])
        for (nibs[4] = 0; nibs[4] < 16; ++nibs[4])
          for (nibs[5] = 0; nibs[5] < 16; ++nibs[5])
            for (nibs[6] = 0; nibs[6] < 16; ++nibs[6])
              for (nibs[7] = 0; nibs[7] < 16; ++nibs[7]) {
                std::cout << "trying: [" << (int)nibs[0] << " " << (int)nibs[1]
                          << " " << (int)nibs[2] << " " << (int)nibs[3] << " "
                          << (int)nibs[4] << " " << (int)nibs[5] << " "
                          << (int)nibs[6] << " " << (int)nibs[7] << "]\n";
                uint64_t k0_prime = k0_prime_template;
                uint64_t k1 = k1_template;
                for (int i = 0; i < 8; ++i) {
                  uint8_t nib_prime = xored_nibbles[i] ^ nibs[i];
                  uint64_t mask = (uint64_t)nibs[i] << ((7 - i) * 8);
                  k0_prime |= mask;
                  uint64_t mask_prime = (uint64_t)nib_prime << ((7 - i) * 8);
                  k1 |= mask_prime;
                }
                if (partial_prince(plaintext_sample, k0_prime, k1) ==
                    partial_decoded) {
                  std::cout << "key found: k0' = 0x" << k0_prime << ", k1 = 0x"
                            << k1 << "\n";
                  return 0;
                }
              }
}
