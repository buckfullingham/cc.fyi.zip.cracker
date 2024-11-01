#ifndef ZIP_CRACKER_VISITOR_HPP
#define ZIP_CRACKER_VISITOR_HPP

namespace zip_cracker {

template <typename... Ts> struct visitor : Ts... {
  using Ts::operator()...;
};

template <typename... Ts> visitor(Ts...) -> visitor<Ts...>;

} // namespace zip_cracker

#endif // ZIP_CRACKER_VISITOR_HPP
