#include "brute.hpp"
#include "decrypter.hpp"
#include "dictionary.hpp"
#include "inflater.hpp"
#include "zip.hpp"

#include <common/io.hpp>

#include <charconv>
#include <execution>
#include <iostream>
#include <mutex>
#include <optional>
#include <regex>
#include <span>
#include <string>

#include <fcntl.h>
#include <unistd.h>

namespace zc = zip_cracker;
namespace io = common::io;

namespace {

/**
 * raise x to the power y
 */
__uint128_t pow(__uint128_t x, std::uint8_t y) {
  __uint128_t result = 1;
  for (std::uint8_t i = 0; i < y; ++i)
    result *= x;
  return result;
}

/**
 * make an alphabet of ascii characters by filtering them with a regular
 * expression
 */
std::string make_alphabet(const std::regex &re) {
  std::string result;

  for (int i = 0; i < 128; ++i) {
    const char c = char(i);
    if (std::regex_match(&c, &c + 1, re))
      result.push_back(c);
  }

  return result;
}

/**
 * try decrypting a local_file with the given password
 * @return true if the file is successfully decrypted with the password
 */
bool is_password_valid(const zc::local_file &local_file,
                       std::string_view password) {
  if (!local_file.is_encrypted())
    return false;

  // make these static thread_local to avoid per-attempt memory allocations
  static thread_local zc::decrypter decrypter;
  static thread_local zc::inflater inflater;

  auto buf = local_file.compressed_data().data();
  auto len = local_file.compressed_data().size();

  if (!decrypter.reset(password, buf, local_file.file_last_mod_time()))
    return false; // check bits didn't match, don't bother decrypting

  inflater.reset();
  std::uint32_t residual = 0xffffffffu;

  switch (zc::compression_method(local_file.compression_method())) {
  case zc::compression_method::stored:
    decrypter.transform(buf + 12, len - 12, [&](auto buf, auto len) {
      zc::crc32(buf, len, residual);
    });
    break;
  case zc::compression_method::deflated:
    decrypter.transform(buf + 12, len - 12, [&](auto buf, auto len) {
      inflater.transform(
          buf, len, [&](auto buf, auto len) { zc::crc32(buf, len, residual); },
          false);
    });
    break;
  }

  return ~residual == local_file.uncompressed_crc32();
}

/**
 * Given an in-memory representation of a zip-file and a range of iterators over
 * passwords to try; attempt each password until one is found to decrypt one of
 * the encrypted local_file entries in the zip file.
 *
 * If the passwords iterators model random_access_iterator, this function will
 * parallelize the attempts across the available system threads.
 */
template <std::forward_iterator Iterator, zc::storage_c Storage>
std::optional<std::string> crack(const std::span<Storage> zip_file,
                                 const Iterator pswds_begin,
                                 const Iterator pswds_end) {
  std::mutex result_mutex;
  std::optional<std::string> result;

  using zip_iter_t = zc::local_file_iterator<Storage>;

  std::any_of(std::execution::par, zip_iter_t(zip_file), zip_iter_t(),
              [&](auto &local_file) {
                return std::any_of(
                    std::execution::par, pswds_begin, pswds_end,
                    [&](auto password) {
                      if (is_password_valid(local_file, password)) {
                        std::unique_lock lock(result_mutex);
                        result = password;
                        return true;
                      }
                      return false;
                    });
              });

  return result;
}

} // namespace

int main(int argc, char *const argv[]) {
  std::optional<std::string> result;

  auto error = [&](auto message) {
    std::cerr << "\n"
              << message << "\nusage: " << argv[0]
              << "-z path_to_zip_file {-d path_to_dictionary | -b "
                 "brute_len:brute_char_regex}\n";
    return EXIT_FAILURE;
  };

  std::string zip_path;
  std::optional<std::string> dict_path;
  std::optional<std::string> brute_cfg;

  for (;;) {
    auto c = getopt(argc, argv, "z:d:b:");

    if (c == -1)
      break;

    switch (c) {
    case 'z':
      zip_path = optarg;
      break;
    case 'd':
      dict_path = optarg;
      break;
    case 'b':
      brute_cfg = optarg;
      break;
    default:
      return error("unrecognised option");
    }
  }

  if (zip_path.empty() || (bool(dict_path) == bool(brute_cfg)))
    error("invalid arguments");

  io::file_descriptor zip_fd(::open, zip_path.c_str(), O_RDONLY);
  io::memory_map zip_memory_map(nullptr, io::fstat(zip_fd.value()).st_size,
                                PROT_READ, MAP_SHARED, zip_fd.value(), 0);
  auto zip_span = zip_memory_map.as_span<const std::byte>();

  if (dict_path) {
    io::file_descriptor dict_fd(::open, dict_path->c_str(), O_RDONLY);

    io::memory_map dict_memory_map(nullptr, io::fstat(dict_fd.value()).st_size,
                                   PROT_READ, MAP_SHARED, dict_fd.value(), 0);

    const auto dict_span = dict_memory_map.as_span<const char>();

    const auto pswd_begin = zip_cracker::dict_iterator(dict_span);
    const auto pswd_end = zip_cracker::dict_iterator();

    result = crack(zip_span, pswd_begin, pswd_end);
  } else {
    std::regex arg_re(R"xx((\d+):(.*))xx");

    if (std::smatch m; !std::regex_match(*brute_cfg, m, arg_re)) {
      return error("invalid -b argument");
    } else {
      std::uint8_t max_len = 0;
      std::from_chars(&*m[1].first, &*m[1].second, max_len);
      const auto alphabet =
          std::make_shared<std::string>(make_alphabet(std::regex(m[2].str())));
      const auto max_index = pow(alphabet->size(), max_len);
      const zc::brute_iterator pswd_begin(0, alphabet);
      const zc::brute_iterator pswd_end(max_index, alphabet);

      result = crack(zip_span, pswd_begin, pswd_end);
    }
  }

  if (result) {
    std::cout << "found password [" << *result << "]\n";
    return EXIT_SUCCESS;
  }

  std::cout << "no password found\n";
  return EXIT_FAILURE;
}
