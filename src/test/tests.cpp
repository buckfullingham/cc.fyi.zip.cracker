#include <catch2/catch_all.hpp>

#include "brute.hpp"
#include "decrypter.hpp"
#include "dictionary.hpp"
#include "inflater.hpp"
#include "test_zip_files.hpp"
#include "zip.hpp"

#include <algorithm>

namespace zc = zip_cracker;
namespace zct = zip_cracker::test;

TEST_CASE("is_zip", "[zip cracker]") {
  CHECK(zc::is_zip(zct::encrypted_uncompressed_zip,
                   sizeof(zct::encrypted_uncompressed_zip)));
}

TEST_CASE("nativize", "[zip cracker]") {
  CHECK(zc::nativize(zc::nativize(258u)) == 258u);
  CHECK(zc::nativize<std::endian::little>(
            zc::nativize<std::endian::little>(258u)) == 258u);
  CHECK(zc::nativize<std::endian::big>(zc::nativize<std::endian::big>(258u)) ==
        258u);
  CHECK(zc::nativize<std::endian::little>(258u) !=
        zc::nativize<std::endian::big>(258u));
  std::array<char, 2> input{2, 1};
  CHECK(zc::nativize<std::endian::little>(
            *reinterpret_cast<std::uint16_t *>(input.begin())) == 258u);
  CHECK(zc::nativize<std::endian::big>(
            *reinterpret_cast<std::uint16_t *>(input.begin())) == 513u);
}

namespace {
struct align_fixture {
  std::uint8_t char_ = 42;
  std::uint32_t int_ = 6;
  std::uint64_t long_ = 9;
} __attribute__((packed));

static_assert(alignof(align_fixture) == 1);
static_assert(sizeof(align_fixture) == 13);
} // namespace

TEST_CASE_METHOD(align_fixture, "align", "[zip cracker]") {
  CHECK(zc::align<std::uint8_t>(reinterpret_cast<std::byte *>(&char_)) == 42);
  CHECK(zc::align<std::uint32_t>(reinterpret_cast<std::byte *>(&int_)) == 6);
  CHECK(zc::align<std::uint64_t>(reinterpret_cast<std::byte *>(&long_)) == 9);
}

TEST_CASE("confirm structure", "[zip cracker]") {
  auto h =
      reinterpret_cast<const zc::local_file *>(zct::encrypted_uncompressed_zip);

  REQUIRE(h->is_encrypted());
  REQUIRE(h->signature() == zc::local_file_header_magic);
  REQUIRE(h->has_data_descriptor());

  const auto file_name_length = h->file_name_length();
  const auto extra_field_length = h->extra_field_length();
  const auto compressed_size = h->compressed_size();
  const auto encrypted_uncompressed_size = h->uncompressed_size();

  const auto ciphertext_offset =
      sizeof(zc::local_file) + file_name_length + extra_field_length;

  REQUIRE(sizeof(zct::encrypted_uncompressed_zip) >=
          sizeof(*h) + h->file_name_length() + h->extra_field_length() +
              h->compressed_size() + sizeof(zc::data_descriptor32));

  [[maybe_unused]] auto cksum = zc::crc32(
      zct::encrypted_uncompressed_zip + ciphertext_offset, compressed_size);

  [[maybe_unused]] auto cksum2 =
      zc::crc32(zct::encrypted_uncompressed_zip + ciphertext_offset + 12,
                encrypted_uncompressed_size);
}

TEST_CASE("crc32", "[zip cracker]") {
  unsigned char test[] = "Test";
  CHECK(zc::crc32(zc::object_to_storage(test), 4) == 0x784dd132);
}

TEST_CASE("verify_password", "[zip cracker]") {

  for (auto file : {
           zct::encrypted_uncompressed_zip,
           zct::encrypted_compressed_piped_text_file,
           zct::encrypted_empty_piped_text_file,
           zct::one_encrypted_compressed_text_file,
       }) {

    using iter_t = zc::local_file_iterator<const std::byte>;

    std::string_view password = "test";

    zc::decrypter decrypter;
    zc::inflater inflater;

    for (iter_t i(std::span(file, sizeof(file))), e; i != e; ++i) {
      auto buf = i->compressed_data().data();
      auto len = i->compressed_data().size();

      CHECK(decrypter.reset(password, buf, i->file_last_mod_time()));

      inflater.reset();
      std::uint32_t residual = 0xffffffffu;

      switch (zc::compression_method(i->compression_method())) {
      case zc::compression_method::stored:
        // decrypt and compute crc32
        decrypter.transform(buf + 12, len - 12, [&](auto buf, auto len) {
          zc::crc32(buf, len, residual);
        });
        break;
      case zc::compression_method::deflated:
        // decrypt, inflate and compute crc32
        decrypter.transform(buf + 12, len - 12, [&](auto buf, auto len) {
          inflater.transform(
              buf, len,
              [&](auto buf, auto len) { zc::crc32(buf, len, residual); },
              false);
        });
        break;
      }
      CHECK(~residual == i->uncompressed_crc32());
    }
  }
}

TEST_CASE("visit_local_file_headers", "[zip cracker]") {
  std::vector<std::string_view> result;
  const std::vector<std::string_view> expected{
      "test_file.txt", "empty_file.txt", "subdir/other_file.txt",
      "and_another.txt"};

  using zip_iter = zc::local_file_iterator<const std::byte>;

  for (zip_iter i(std::span(zct::encrypted_uncompressed_zip,
                            sizeof(zct::encrypted_uncompressed_zip))),
       e;
       i != e; ++i) {
    CHECK(i->is_encrypted());
    result.emplace_back(zc::storage_to_object<char>(i->file_name().data()),
                        i->file_name().size());
    auto buf = i->compressed_data().data();
    auto len = i->compressed_data().size();
    CHECK(zc::verify_password(buf, len, "test", i->file_last_mod_time(),
                              i->uncompressed_crc32()));
  }

  CHECK(result == expected);
}

TEST_CASE("decompress a file", "[zip cracker]") {
  using iter_t = zc::local_file_iterator<const std::byte>;
  for (iter_t i(zct::one_unencrypted_compressed_text_file), e; i != e; ++i) {
    REQUIRE(!i->is_encrypted());
    zc::inflater inf;
    std::uint32_t residual = 0xffffffffu;
    inf.transform(
        i->compressed_data().data(), i->compressed_data().size(),
        [&](auto buf, auto len) {
          zc::crc32(zc::object_to_storage(buf), len, residual);
        },
        true);
    CHECK(~residual == i->uncompressed_crc32());
  }
}

TEST_CASE("decompress and decrypt a file", "[zip cracker]") {
  bool visited = false;
  using iter_t = zc::local_file_iterator<const std::byte>;
  for (iter_t i(std::span(zct::one_encrypted_compressed_text_file,
                          sizeof(zct::one_encrypted_compressed_text_file))),
       e;
       i != e; ++i) {
    REQUIRE(i->is_encrypted());
    visited = true;
    std::uint32_t residual = 0xffffffffu;
    zc::decrypter d;
    zc::inflater inf;
    inf.reset();
    auto buf = i->compressed_data().data();
    auto len = i->compressed_data().size();
    CHECK(d.reset("test", buf, i->file_last_mod_time()));
    d.transform(buf + 12, len - 12, [&](auto buf, auto len) {
      inf.transform(
          buf, len, [&](auto buf, auto len) { zc::crc32(buf, len, residual); },
          false);
    });
    CHECK(~residual == i->uncompressed_crc32());
  }

  CHECK(visited);
}

TEST_CASE("dict_iterator") {
  char passwords[] = "hello\nworld\npassword\nlist\n";

  const zc::dict_iterator i(std::span(passwords, std::strlen(passwords)));
  const zc::dict_iterator e;

  CHECK(i != e);
  CHECK(e != i);
  CHECK(i == i);
  CHECK(e == e);

  std::vector<std::string_view> v;
  std::copy(i, e, std::back_inserter(v));

  std::vector<std::string_view> expected = {"hello", "world", "password",
                                            "list"};

  CHECK(v == expected);

  CHECK(std::find(i, e, "password") != e);
  CHECK(std::find(i, e, "blob") == e);
}

TEST_CASE("piped zip file") {
  auto h = zc::storage_to_object<zc::local_file>(
      zct::encrypted_compressed_piped_text_file);

  zc::extra_field_iterator i(h->extra_field().data());
  zc::extra_field_iterator e(h->extra_field().data() + h->extra_field().size());

  CHECK(h->uncompressed_crc32() != 0);
  CHECK(h->raw_compressed_size() == 0xffffffff);
  CHECK(h->raw_uncompressed_size() == 0xffffffff);
  CHECK(h->extra_field_length() == 20);
  CHECK(h->has_data_descriptor());

  std::size_t call_count = 0;

  std::for_each(i, e, [&](auto &ef) {
    ++call_count;
    ef.visit([&](auto &x) {
      CHECK(x.compressed_size() == 26);
      CHECK(x.uncompressed_size() == 45);
    });
  });

  CHECK(call_count == 1);
}

TEST_CASE("binary brute_iterator") {
  const auto alphabet = std::make_shared<std::string>("01");
  const zc::brute_iterator begin(0, alphabet);
  const zc::brute_iterator end(1 << 5, alphabet);

  CHECK(begin[0] == "0");
  CHECK(begin[1] == "1");
  CHECK(begin[(1 << 5) - 1] == "11111");
  CHECK(end - begin == 1 << 5);

  std::set<std::string> results;

  auto it = begin;

  for (int i = 0; i < 1 << 5; ++i) {
    auto password = *it++;
    CHECK(password.size() < 6);
    CHECK(begin[i] == password);
    results.insert(begin[i]);
  }

  CHECK(results.size() == 1 << 5);
}

TEST_CASE("ternary brute_iterator") {
  const auto alphabet = std::make_shared<std::string>("012");
  const zc::brute_iterator begin(0, alphabet);
  const zc::brute_iterator end(27, alphabet); // 3^3 == 27

  CHECK(begin[0] == "0");
  CHECK(begin[1] == "1");
  CHECK(begin[26] == "222");
  CHECK(end - begin == 27);

  std::set<std::string> results;

  auto it = begin;

  for (int i = 0; i < 27; ++i) {
    auto password = *it++;
    CHECK(password.size() < 4);
    CHECK(begin[i] == password);
    results.insert(begin[i]);
  }

  CHECK(results.size() == 27);
}
