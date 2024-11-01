#include "zip.hpp"
#include "crc32.hpp"

#include <vector>

/**
 * Verify the password used to encrypt a given ciphertext knowing the check bits
 * and crc32 of the plaintext.
 *
 * c.f. https://support.pkware.com/pkzip/application-note-archives
 *
 * @param ciphertext the ciphertext (including 12 byte encryption header)
 * @param len length of ciphertext
 * @param password the password to verify
 * @param check_bits the check bits to be compared against bytes 10 and 11 of
 * the plaintext
 * @param plaintext_crc32 the crc32 of the plaintext
 * @return true if the check bits and crc32 generated using password match those
 * provided as parameters
 */
bool zip_cracker::verify_password(const std::byte *ciphertext, std::size_t len,
                                  std::string_view password,
                                  std::uint16_t check_bits,
                                  std::uint32_t plaintext_crc32) {

  // adapt crc32 for use on a residual and a single byte
  auto crc = [](std::uint32_t residual, const std::byte p) {
    crc32(&p, 1, residual);
    return residual;
  };

  std::array<std::uint32_t, 3> key{305419896, 591751049, 878082192};

  // key tumbler
  auto update_keys = [&](std::byte p) {
    key[0] = crc(key[0], p);
    key[1] = key[1] + (key[0] & 0x000000ffu);
    key[1] = key[1] * 134775813 + 1;
    key[2] = crc(key[2], std::byte(key[1] >> 24));
  };

  // next byte in decryption key stream
  auto decrypt_byte = [&]() {
    const std::uint16_t i = key[2] | 2;
    return std::byte((i * (i ^ 1)) >> 8);
  };

  // initialize keys using the password
  for (char p : password)
    update_keys(std::byte(p));

  // decrypt first 10 chars of encryption header
  for (auto c : std::span(ciphertext, ciphertext + 10))
    update_keys(c ^ decrypt_byte());

  // decrypt 11th char of encryption header and check against check bits
  if (std::byte p = ciphertext[10] ^ decrypt_byte();
      p == std::byte(check_bits)) {
    update_keys(p);
  } else {
    return false; // bit check failed
  }

  // decrypt 12th char of encryption header and check against check bits
  if (std::byte p = ciphertext[11] ^ decrypt_byte();
      p == std::byte(check_bits >> 8)) {
    update_keys(p);
  } else {
    return false; // bit check failed
  }

  // now decrypt the rest of the ciphertext, using it to calculate a crc32 of
  // the plaintext
  std::uint32_t residual = 0xffffffffu;
  for (std::byte c : std::span(ciphertext + 12, ciphertext + len)) {
    std::byte p = c ^ decrypt_byte();
    update_keys(p);
    residual = crc(residual, p);
  }

  // and compare it with the crc32 that was provided
  return (~residual == plaintext_crc32);
}
