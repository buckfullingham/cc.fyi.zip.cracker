#ifndef ZIP_CRACKER_DECRYPTER_HPP
#define ZIP_CRACKER_DECRYPTER_HPP

#include "crc32.hpp"

#include <algorithm>
#include <array>
#include <concepts>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace zip_cracker {

class decrypter {
  /**
   * adapt crc32 for use on a residual and a single byte
   */
  static std::uint32_t crc(std::uint32_t residual, const std::byte p) {
    crc32(&p, 1, residual);
    return residual;
  }

  std::byte update_key(std::byte p) {
    key_[0] = crc(key_[0], p);
    key_[1] = key_[1] + (key_[0] & 0x000000ffu);
    key_[1] = key_[1] * 134775813 + 1;
    key_[2] = crc(key_[2], std::byte(key_[1] >> 24));
    return p;
  }

  std::byte next_key_stream_byte() {
    const std::uint16_t i = key_[2] | 2;
    return std::byte((i * (i ^ 1)) >> 8);
  }

public:
  decrypter() : key_() {}
  decrypter(const decrypter &) = delete;
  decrypter &operator=(const decrypter &) = delete;
  decrypter(decrypter &&) = delete;
  decrypter &operator=(decrypter &&) = delete;
  ~decrypter() = default;

  bool reset(std::string_view password, const std::byte *header,
             std::uint16_t check_bits) {
    key_ = {305419896, 591751049, 878082192};

    for (auto p : password)
      update_key(std::byte(p));

    // decrypt first 10 chars of encryption header
    for (auto c : std::span(header, header + 10))
      update_key(c ^ next_key_stream_byte());

    // decrypt 11th char of encryption header and check against check bits
    if (std::byte p = header[10] ^ next_key_stream_byte();
        p == std::byte(check_bits)) {
      update_key(p);
    } else {
      return false; // bit check failed
    }

    // decrypt 12th char of encryption header and check against check bits
    if (std::byte p = header[11] ^ next_key_stream_byte();
        p == std::byte(check_bits >> 8)) {
      update_key(p);
    } else {
      return false; // bit check failed
    }

    return true;
  }

  template <std::invocable<const std::byte *, std::size_t> Receiver>
  void transform(const std::byte *ciphertext, std::size_t len,
                 Receiver receiver) {
    while (len) {
      std::array<std::byte, 1 << 12> plaintext{};
      std::size_t plaintext_len = std::min(plaintext.size(), len);
      std::transform(
          ciphertext, ciphertext + plaintext_len, plaintext.begin(),
          [this](auto c) { return update_key(c ^ next_key_stream_byte()); });
      receiver(plaintext.begin(), plaintext_len);
      len -= plaintext_len;
    }
  }

private:
  std::array<std::uint32_t, 3> key_;
};

} // namespace zip_cracker

#endif // ZIP_CRACKER_DECRYPTER_HPP
