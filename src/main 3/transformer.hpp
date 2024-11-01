#ifndef ZIP_CRACKER_TRANSFORMER_HPP
#define ZIP_CRACKER_TRANSFORMER_HPP

#include <concepts>
#include <cstdint>
#include <functional>

namespace zip_cracker {

template <typename Transformer>
concept transformer_c =
    requires(Transformer &t, const std::byte *buf, std::size_t len,
             std::function<void(const std::byte *, std::size_t)> receiver,
             bool finish) {
      t.reset();
      t.transform(buf, len, receiver, finish);
    };

} // namespace zip_cracker

#endif // ZIP_CRACKER_TRANSFORMER_HPP
