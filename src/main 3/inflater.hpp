#ifndef ZIP_CRACKER_ZLIB_HPP
#define ZIP_CRACKER_ZLIB_HPP

#include "transformer.hpp"

#include <zlib.h>

#include <array>
#include <concepts>
#include <cstdint>
#include <memory>

namespace zip_cracker {

class inflater;

void swap(inflater &, inflater &) noexcept;

class inflater {
  friend void swap(inflater &, inflater &) noexcept;

  static void destroy_stream(z_streamp stream) {
    if (stream)
      ::inflateEnd(stream);
    delete stream;
  }

  template <typename... Args, std::invocable<z_streamp, Args...> Function>
  auto zlib(Function function,
            Args... args) -> decltype(function(nullptr, args...)) {
    auto result = function(stream_.get(), args...);
    if (result < 0)
      throw std::runtime_error(stream_->msg ? stream_->msg : "unknown error");
    return result;
  }

public:
  inflater() : stream_(new z_stream{}, destroy_stream) {
    zlib([](auto s) { return inflateInit2(s, -15); });
  }

  inflater(inflater &&that) : inflater() { swap(*this, that); }

  inflater &operator=(inflater &&that) noexcept {
    if (this != &that)
      swap(*this, that);
    return *this;
  }

  inflater(const inflater &) = delete;
  inflater &operator=(const inflater &) = delete;

  void reset() { zlib(::inflateReset2, -15); }

  template <std::invocable<const std::byte *, std::size_t> Receiver>
  void transform(const std::byte *buf_in, std::size_t len, Receiver receiver,
                 bool finish) {
    std::array<std::byte, 1 << 10> buf_out{};

    stream_->next_in =
        reinterpret_cast<std::uint8_t *>(const_cast<std::byte *>(buf_in));
    stream_->avail_in = len;
    stream_->next_out = reinterpret_cast<std::uint8_t *>(buf_out.begin());
    stream_->avail_out = buf_out.size();

    while (stream_->avail_in) {
      zlib(::inflate, finish ? Z_FINISH : Z_NO_FLUSH);
      receiver(buf_out.begin(), buf_out.size() - stream_->avail_out);
      stream_->next_out = reinterpret_cast<std::uint8_t *>(buf_out.begin());
      stream_->avail_out = buf_out.size();
    }
  }

private:
  std::unique_ptr<::z_stream, decltype(&destroy_stream)> stream_;
};

static_assert(transformer_c<inflater>);

void swap(inflater &lhs, inflater &rhs) noexcept {
  using std::swap;
  swap(lhs.stream_, rhs.stream_);
}

} // namespace zip_cracker

#endif // ZIP_CRACKER_ZLIB_HPP
