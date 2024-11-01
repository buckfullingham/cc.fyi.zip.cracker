#ifndef ZIP_CRACKER_DICTIONARY_HPP
#define ZIP_CRACKER_DICTIONARY_HPP

#include <algorithm>
#include <cassert>
#include <concepts>
#include <cstring>
#include <optional>
#include <span>
#include <stdexcept>
#include <string_view>
#include <utility>

namespace zip_cracker {

class dict_iterator {
public:
  using value_type = std::string_view;
  using difference_type = std::ptrdiff_t;

  explicit dict_iterator() noexcept : addr_(), end_() {}

  explicit dict_iterator(std::span<const char> span) noexcept
      : addr_(span.data()), end_(addr_ + span.size()) {}

  dict_iterator(const dict_iterator &) noexcept = default;
  dict_iterator &operator=(const dict_iterator &) noexcept = default;
  dict_iterator(dict_iterator &&) noexcept = default;
  dict_iterator &operator=(dict_iterator &&) noexcept = default;
  ~dict_iterator() = default;

public:
  value_type operator*() const {
    return {addr_, std::find(addr_, end_, '\n')};
  }

  dict_iterator &operator++() {
    const auto pos = std::find(addr_, end_, '\n');
    addr_ = pos + 1;
    return *this;
  }

  dict_iterator operator++(int) {
    dict_iterator result(*this);
    ++(*this);
    return result;
  }

private:
  friend bool operator==(const dict_iterator &lhs,
                         const dict_iterator &rhs) noexcept;

  const char *addr_;
  const char *end_;
  mutable std::optional<std::string_view> value_;
};

inline bool operator==(const dict_iterator &lhs,
                       const dict_iterator &rhs) noexcept {
  auto get_addr = [](auto& it) {
    return it.addr_ == it.end_ ? nullptr : it.addr_;
  };

  return get_addr(lhs) == get_addr(rhs);
}

static_assert(std::forward_iterator<dict_iterator>);

} // namespace zip_cracker

#endif // ZIP_CRACKER_DICTIONARY_HPP
