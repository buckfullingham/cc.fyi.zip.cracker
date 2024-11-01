#ifndef ZIP_CRACKER_BRUTE_HPP
#define ZIP_CRACKER_BRUTE_HPP

#include <algorithm>
#include <cassert>
#include <concepts>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

namespace zip_cracker {

/**
 * Iterator over all possible passwords made up of a given alphabet.
 */
class brute_iterator {
public:
  using iterator_category = std::random_access_iterator_tag;
  using value_type = std::string;
  using reference = value_type;
  using difference_type = __int128_t;

  brute_iterator() : index_(), alphabet_(), indices_(), indices_len_() {}

  explicit brute_iterator(__uint128_t index,
                          std::shared_ptr<std::string> alphabet)
      : index_(), alphabet_(std::move(alphabet)), indices_(), indices_len_() {
    set_index(index);
    assert(index == index_);
  }

  brute_iterator(const brute_iterator &) noexcept = default;
  brute_iterator &operator=(const brute_iterator &) noexcept = default;
  brute_iterator(brute_iterator &&) noexcept = default;
  brute_iterator &operator=(brute_iterator &&) noexcept = default;
  ~brute_iterator() = default;

  std::string operator*() const {
    std::string result;
    std::transform(indices_.begin(), indices_.begin() + indices_len_,
                   std::back_inserter(result),
                   [this](auto i) { return (*alphabet_)[i]; });
    return result;
  }

  brute_iterator &operator++() noexcept {
    // avoid repeated division of index_ in this heavily used method

    const auto pos =
        std::find_if(indices_.begin(), indices_.begin() + indices_len_,
                     [this](auto c) { return c != alphabet_->size() - 1; });

    for (auto i = indices_.begin(); i != pos; ++i)
      *i = 0;

    if (pos == indices_.begin() + indices_len_) {
      ++indices_len_;
      *pos = 1;
    } else {
      ++(*pos);
    }

    ++index_;

    return *this;
  }

  brute_iterator &operator+=(difference_type offset) noexcept {
    set_index(index_ + offset);
    return *this;
  }

  brute_iterator &operator-=(difference_type offset) noexcept {
    set_index(index_ - offset);
    return *this;
  }

  brute_iterator &operator--() noexcept {
    set_index(index_ - 1);
    return *this;
  }

  brute_iterator operator++(int) noexcept {
    brute_iterator result(*this);
    ++(*this);
    return result;
  }

  brute_iterator operator--(int) noexcept {
    brute_iterator result(*this);
    --(*this);
    return result;
  }

  reference operator[](difference_type offset) const {
    return *(*this + offset);
  }

private:
  void set_index(__uint128_t index) {
    index_ = index;
    std::uint8_t *o = indices_.begin();
    do {
      *o++ = index % alphabet_->size();
      index /= alphabet_->size();
    } while (index);
    indices_len_ = o - indices_.begin();
  }

  friend difference_type operator-(const brute_iterator &lhs,
                                   const brute_iterator &rhs) noexcept;
  friend brute_iterator operator-(const brute_iterator &lhs,
                                  difference_type rhs) noexcept;
  friend brute_iterator operator+(const brute_iterator &lhs,
                                  difference_type rhs) noexcept;
  friend brute_iterator operator+(difference_type lhs,
                                  const brute_iterator &rhs) noexcept;
  friend bool operator==(const brute_iterator &lhs,
                         const brute_iterator &rhs) noexcept;
  friend std::strong_ordering operator<=>(const brute_iterator &lhs,
                                          const brute_iterator &rhs) noexcept;

  __uint128_t index_;
  std::shared_ptr<std::string> alphabet_;
  std::array<std::uint8_t, 128> indices_;
  std::uint8_t indices_len_;
};

inline bool operator==(const brute_iterator &lhs,
                       const brute_iterator &rhs) noexcept {
  assert(lhs.alphabet_ == rhs.alphabet_);
  return lhs.index_ == rhs.index_;
}

inline std::strong_ordering operator<=>(const brute_iterator &lhs,
                                        const brute_iterator &rhs) noexcept {
  assert(lhs.alphabet_ == rhs.alphabet_);
  return lhs.index_ <=> rhs.index_;
}

brute_iterator::difference_type operator-(const brute_iterator &lhs,
                                          const brute_iterator &rhs) noexcept {
  assert(lhs.alphabet_ == rhs.alphabet_);
  return brute_iterator::difference_type(lhs.index_ - rhs.index_);
}

brute_iterator operator-(const brute_iterator &lhs,
                         brute_iterator::difference_type rhs) noexcept {
  auto result = lhs;
  result -= rhs;
  return result;
}

brute_iterator operator+(const brute_iterator &lhs,
                         brute_iterator::difference_type rhs) noexcept {
  auto result = lhs;
  result += rhs;
  return result;
}

brute_iterator operator+(brute_iterator::difference_type lhs,
                         const brute_iterator &rhs) noexcept {
  auto result = rhs;
  result += lhs;
  return result;
}

static_assert(std::random_access_iterator<brute_iterator>);
static_assert(
    std::is_same_v<std::iterator_traits<brute_iterator>::iterator_category,
                   std::random_access_iterator_tag>);

} // namespace zip_cracker

#endif // ZIP_CRACKER_BRUTE_HPP
