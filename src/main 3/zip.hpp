#ifndef CC_FYI_ZIP_CRACKER_IS_ZIP_HPP
#define CC_FYI_ZIP_CRACKER_IS_ZIP_HPP

#include "storage.hpp"
#include "visitor.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cassert>
#include <concepts>
#include <cstdint>
#include <cstring>
#include <functional>
#include <span>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <variant>

namespace zip_cracker {

enum class compression_method : std::uint8_t {
  stored = 0,
  deflated = 8,
};

/**
 * Take an unsigned integral type, which was serialized as little endian and
 * return a copy of it converted to the requested byte ordering (defaulting to
 * the native ordering).
 */
template <std::endian ordering = std::endian::native,
          std::unsigned_integral T = void>
inline constexpr auto nativize(T input) -> T {
  if constexpr (ordering != std::endian::little) {
    T result{};
    for (std::size_t i = 0; i < 8 * sizeof(T); i += 8) {
      result <<= 8;
      result |= std::uint8_t(input >> i);
    }
    return result;
  }
  return input;
}

/**
 * Take a potentially unaligned unsigned integral and return it aligned.
 */
template <std::unsigned_integral T, storage_c Storage>
inline constexpr auto align(Storage *storage) {
  T result;
  std::memcpy(&result, storage, sizeof(T));
  return result;
}

/**
 * A data descriptor excluding its (optional) signature.
 */
template <std::unsigned_integral Size> struct basic_data_descriptor {
  std::uint32_t crc32;
  Size compressed_size;
  Size uncompressed_size;
} __attribute__((packed));

constexpr std::uint32_t data_descriptor_magic = 0x08074b50;
using data_descriptor32 = basic_data_descriptor<std::uint32_t>;
using data_descriptor64 = basic_data_descriptor<std::uint64_t>;

/**
 * A zip64 extra field.
 */
class zip64_extra_field {
public:
  [[nodiscard]] std::uint64_t uncompressed_size() const {
    return nativize(uncompressed_size_);
  }

  [[nodiscard]] std::uint64_t compressed_size() const {
    return nativize(compressed_size_);
  }

private:
  std::uint64_t uncompressed_size_;
  std::uint64_t compressed_size_;
} __attribute__((packed));

/**
 * An extra field that can contain multiple sub fields (only zip64 is currently
 * supported.
 */
class extra_field {
public:
  [[nodiscard]] std::uint16_t header_id() const { return nativize(header_id_); }

  [[nodiscard]] const std::byte *data() const {
    return object_to_storage(this) + sizeof(*this);
  }

  [[nodiscard]] std::uint16_t size() const { return nativize(size_); }

  template <typename Visitor> void visit(Visitor visitor) const {
    switch (header_id()) {
    case 0x0001:
      return visitor(*storage_to_object<zip64_extra_field>(data()));
    default:
      return;
    }
  }

private:
  std::uint16_t header_id_;
  std::uint16_t size_;
} __attribute__((packed));

/**
 * Iterator over fields within an extra_field.
 */
template <typename Storage> class extra_field_iterator {
public:
  using value_type = object_t<extra_field, Storage>;
  using pointer_type = value_type *;
  using difference_type = std::ptrdiff_t;

  explicit extra_field_iterator(Storage *addr = nullptr) noexcept
      : addr_(addr) {}

  extra_field_iterator(const extra_field_iterator &) noexcept = default;
  extra_field_iterator &
  operator=(const extra_field_iterator &) noexcept = default;
  extra_field_iterator(extra_field_iterator &&) noexcept = default;
  extra_field_iterator &operator=(extra_field_iterator &&) noexcept = default;
  ~extra_field_iterator() = default;

public:
  value_type &operator*() const {
    return *storage_to_object<value_type>(addr_);
  }

  pointer_type operator->() const {
    return storage_to_object<value_type>(addr_);
  }

  extra_field_iterator &operator++() {
    auto &value = *storage_to_object<value_type>(addr_);
    addr_ = value.data() + value.size();
    return *this;
  }

  extra_field_iterator operator++(int) {
    auto result = *this;
    ++(*this);
    return result;
  }

  bool operator==(const extra_field_iterator &that) const noexcept {
    return addr_ == that.addr_;
  }

private:
  Storage *addr_;
};

static_assert(std::forward_iterator<extra_field_iterator<std::byte>>);
static_assert(std::forward_iterator<extra_field_iterator<const std::byte>>);

/**
 * Local file header as described in the PK APPNOTE.
 */
class local_file {
public:
  [[nodiscard]] std::uint32_t signature() const { return nativize(signature_); }

  [[nodiscard]] std::uint32_t general_purpose_bit_flags() const {
    return nativize(general_purpose_bit_flags_);
  }

  [[nodiscard]] std::uint32_t file_last_mod_time() const {
    return nativize(file_last_mod_time_);
  }

  [[nodiscard]] std::uint32_t raw_uncompressed_crc32() const {
    return nativize(uncompressed_crc32_);
  }

  [[nodiscard]] std::uint32_t uncompressed_crc32() const {
    std::uint32_t result = raw_uncompressed_crc32();

    if (has_data_descriptor()) {
      visit_data_descriptor([&](auto &d) { result = d.crc32; });
    }

    return result;
  }

  /**
   * The raw field from the local header; note actual size might be in the
   * zip64 extra field.
   */
  [[nodiscard]] std::uint32_t raw_uncompressed_size() const {
    return nativize(uncompressed_size_);
  }

  [[nodiscard]] std::uint64_t uncompressed_size() const {
    std::uint64_t result = raw_uncompressed_size();

    if (is_zip64())
      result = get_zip64_extra_field().uncompressed_size();

    if (has_data_descriptor()) {
      visit_data_descriptor([&](auto &d) { result = d.uncompressed_size; });
    }

    return result;
  }

  /**
   * The raw field from the local header; note actual size might be in the
   * zip64 extra field.
   */
  [[nodiscard]] std::uint32_t raw_compressed_size() const {
    return nativize(compressed_size_);
  }

  [[nodiscard]] std::uint64_t compressed_size() const {
    std::uint64_t result = raw_compressed_size();

    if (is_zip64())
      result = get_zip64_extra_field().compressed_size();

    return result;
  }

  [[nodiscard]] std::uint32_t file_name_length() const {
    return nativize(file_name_length_);
  }

  [[nodiscard]] std::uint32_t extra_field_length() const {
    return nativize(extra_field_length_);
  }

  [[nodiscard]] std::uint32_t compression_method() const {
    return nativize(compression_method_);
  }

  [[nodiscard]] auto file_name() const {
    return std::span{object_to_storage(this) + sizeof(*this),
                     file_name_length()};
  }

  [[nodiscard]] auto extra_field() const {
    return std::span{object_to_storage(this) + sizeof(*this) +
                         file_name_length(),
                     extra_field_length()};
  }

  [[nodiscard]] auto compressed_data() const {
    return std::span{object_to_storage(this) + sizeof(*this) +
                         file_name_length() + extra_field_length(),
                     compressed_size()};
  }

  [[nodiscard]] auto data_descriptor_data() const {
    assert(has_data_descriptor());

    auto ptr = object_to_storage(this) + sizeof(*this) + file_name_length() +
               extra_field_length() + compressed_size();

    std::size_t len = 0;

    visit_data_descriptor(
        [&](auto &d) { len = (object_to_storage(&d) + sizeof(d)) - ptr; });

    return std::span{ptr, len};
  }

  template <typename Visitor>
  void visit_data_descriptor(Visitor visitor) const {
    assert(has_data_descriptor());

    auto ptr = object_to_storage(this) + sizeof(*this) + file_name_length() +
               extra_field_length() + compressed_size();

    // skip signature if it's the magic number (don't see how we can handle the
    // case where the crc32 is the magic number)
    if (nativize(align<std::uint32_t>(ptr)) == data_descriptor_magic)
      ptr += 4;

    if (is_zip64())
      visitor(*storage_to_object<data_descriptor64>(ptr));
    else
      visitor(*storage_to_object<data_descriptor32>(ptr));
  }

  [[nodiscard]] bool is_encrypted() const {
    return general_purpose_bit_flags() & 0x01;
  }

  [[nodiscard]] bool has_data_descriptor() const {
    return general_purpose_bit_flags() & 0x08;
  }

  [[nodiscard]] bool is_zip64() const {
    return raw_compressed_size() == 0xffffffff &&
           raw_uncompressed_size() == 0xffffffff;
  }

private:
  [[nodiscard]] const zip64_extra_field &get_zip64_extra_field() const {
    const zip64_extra_field *result = nullptr;

    for (extra_field_iterator i(extra_field().data()),
         e(extra_field().data() + extra_field().size());
         i != e; ++i) {
      i->visit(visitor{[&](const zip64_extra_field &ef) { result = &ef; }});
    }

    if (result == nullptr)
      throw std::runtime_error("attempt to get non-existent zip64 data");

    return *result;
  }

  std::uint32_t signature_;
  std::uint16_t version_need_to_extract_;
  std::uint16_t general_purpose_bit_flags_;
  std::uint16_t compression_method_;
  std::uint16_t file_last_mod_time_;
  std::uint16_t file_last_mod_date_;
  std::uint32_t uncompressed_crc32_;
  std::uint32_t compressed_size_;
  std::uint32_t uncompressed_size_;
  std::uint16_t file_name_length_;
  std::uint16_t extra_field_length_;
} __attribute__((packed));

constexpr std::uint32_t local_file_header_magic = 0x04034b50;
static_assert(sizeof(local_file) == 30);

template <typename Storage = const std::byte> class local_file_iterator {
public:
  using value_type = object_t<local_file, Storage>;
  using pointer_type = value_type *;
  using difference_type = std::ptrdiff_t;

  local_file_iterator() noexcept : addr_(), end_() {}
  explicit local_file_iterator(std::span<Storage> span) noexcept
      : addr_(span.data()), end_(addr_ + span.size()) {}

  local_file_iterator(const local_file_iterator &) noexcept = default;
  local_file_iterator &
  operator=(const local_file_iterator &) noexcept = default;
  local_file_iterator(local_file_iterator &&) noexcept = default;
  local_file_iterator &operator=(local_file_iterator &&) noexcept = default;
  ~local_file_iterator() = default;

public:
  value_type &operator*() const {
    return *storage_to_object<value_type>(addr_);
  }

  pointer_type operator->() const {
    return storage_to_object<value_type>(addr_);
  }

  local_file_iterator &operator++() {
    auto &value = *storage_to_object<value_type>(addr_);

    addr_ =
        value.has_data_descriptor()
            ? value.data_descriptor_data().data() +
                  value.data_descriptor_data().size()
            : value.compressed_data().data() + value.compressed_data().size();

    if (addr_ >= end_)
      addr_ = nullptr;

    return *this;
  }

  local_file_iterator operator++(int) {
    auto result = *this;
    ++(*this);
    return result;
  }

  bool operator==(const local_file_iterator &that) const noexcept {
    if (this == &that)
      return true;

    auto get_addr = [](auto &self) {
      return (self.addr_ && self.addr_ < self.end_ &&
              storage_to_object<local_file>(self.addr_)->signature() ==
                  local_file_header_magic)
                 ? self.addr_
                 : nullptr;
    };

    return get_addr(*this) == get_addr(that);
  }

private:
  Storage *addr_;
  Storage *end_;
};

static_assert(std::forward_iterator<local_file_iterator<std::byte>>);
static_assert(std::forward_iterator<local_file_iterator<const std::byte>>);

/**
 * basic check that this looks like a zip file (i.e. it starts with a
 * local_file
 */
inline bool is_zip(const std::byte *const buf, std::size_t len) {
  if (len < sizeof(local_file))
    return false;

  auto header = storage_to_object<local_file>(buf);

  if (header->signature() != local_file_header_magic)
    return false;

  return true;
}

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
bool verify_password(const std::byte *ciphertext, std::size_t len,
                     std::string_view password, std::uint16_t check_bits,
                     std::uint32_t plaintext_crc32);

} // namespace zip_cracker

#endif // CC_FYI_ZIP_CRACKER_IS_ZIP_HPP
