#ifndef ZIP_CRACKER_STORAGE_HPP
#define ZIP_CRACKER_STORAGE_HPP

#include <new>
#include <type_traits>
#include <utility>

namespace zip_cracker {

// Utilities for converting between std::byte arrays and objects whilst
// maintaining const qualification
//
// e.g.
//
// object_to_storage(const int*) returns const std::byte*
// object_to_storage(int*) returns std::byte*
//
// storage_to_object<int>(const std:byte*) returns const int*
// storage_to_object<int>(std:byte*) returns int*
//
template <typename T>
concept storage_c = std::is_same_v<std::remove_cvref_t<T>, std::byte>;

template <typename Object>
using storage_t =
    std::conditional_t<std::is_const_v<std::remove_reference_t<Object>>,
                       const std::byte, std::byte>;

static_assert(std::is_const_v<std::remove_reference_t<const int>>);
static_assert(std::is_same_v<storage_t<const int>, const std::byte>);
static_assert(std::is_same_v<storage_t<int>, std::byte>);

template <typename T> storage_t<T> *object_to_storage(T *t) {
  return std::launder(reinterpret_cast<storage_t<T> *>(t));
}

template <typename T, storage_c Storage>
using object_t =
    std::conditional_t<std::is_const_v<std::remove_reference_t<Storage>>,
                       const T, T>;

template <typename T, storage_c Storage>
object_t<T, Storage> *storage_to_object(Storage *storage) {
  return std::launder(reinterpret_cast<object_t<T, Storage> *>(storage));
}

} // namespace zip_cracker

#endif // ZIP_CRACKER_STORAGE_HPP
