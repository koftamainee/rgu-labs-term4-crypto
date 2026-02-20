#include "crypto/algorithms/des.hpp"
#include "crypto/algorithms/triple_des.hpp"
#include "crypto/io/symmetric_cipher.hpp"

#include <cassert>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <random>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using Bytes = std::vector<uint8_t>;

Bytes random_bytes(std::size_t n, uint32_t seed = 42) {
  std::mt19937 rng(seed);
  std::uniform_int_distribution<uint16_t> dist(0, 255);
  Bytes buf(n);
  for (auto &b : buf)
    b = static_cast<uint8_t>(dist(rng));
  return buf;
}

void print_hex(const std::string &label, const Bytes &data,
               std::size_t limit = 32) {
  std::cout << label << " (" << data.size() << " bytes): ";
  for (std::size_t i = 0; i < std::min(data.size(), limit); ++i)
    std::cout << std::hex << std::setw(2) << std::setfill('0')
              << static_cast<int>(data[i]) << ' ';
  if (data.size() > limit)
    std::cout << "...";
  std::cout << std::dec << '\n';
}

void write_file(const std::string &path, const Bytes &data) {
  fs::create_directories(fs::path(path).parent_path());
  std::ofstream f(path, std::ios::binary);
  f.write(reinterpret_cast<const char *>(data.data()),
          static_cast<std::streamsize>(data.size()));
}

Bytes read_file(const std::string &path) {
  std::ifstream f(path, std::ios::binary);
  return {std::istreambuf_iterator<char>(f), {}};
}

bool verify(const Bytes &original, const Bytes &recovered,
            const std::string &tag) {
  if (original == recovered) {
    std::cout << "  [OK]  " << tag << " – round-trip verified\n";
    return true;
  }
  std::cout << "  [FAIL] " << tag << " – mismatch!\n";
  return false;
}

double time_ms(std::function<void()> fn) {
  auto t0 = std::chrono::high_resolution_clock::now();
  fn();
  auto t1 = std::chrono::high_resolution_clock::now();
  return std::chrono::duration<double, std::milli>(t1 - t0).count();
}

void demo_des(const Bytes &plain, const std::string &label) {
  std::cout << "\n=== DES  |  " << label << " ===\n";

  Bytes key = random_bytes(8, 0xDEAD);
  print_hex("Key      ", key, 8);
  print_hex("Plaintext", plain);

  auto des_cipher = std::make_unique<crypto::des::DES>();
  crypto::io::SymmetricCipherIO io(std::move(des_cipher));
  io.set_encryption_key(key);
  io.set_decryption_key(key);

  Bytes cipher, recovered;
  double enc_ms = time_ms([&] { cipher = io.encrypt_bytes(plain); });
  double dec_ms = time_ms([&] { recovered = io.decrypt_bytes(cipher); });

  print_hex("Ciphertext", cipher);
  print_hex("Recovered ", recovered);
  verify(plain, recovered, "DES " + label);
  std::cout << "  Encrypt " << enc_ms << " ms  |  Decrypt " << dec_ms
            << " ms\n";
}

void demo_3des(const Bytes &plain, crypto::des::TripleDESMode mode,
               const std::string &mode_label, const std::string &data_label) {
  std::cout << "\n=== 3DES " << mode_label << "  |  " << data_label << " ===\n";

  bool use_two_keys = (mode == crypto::des::TripleDESMode::EEE2 ||
                       mode == crypto::des::TripleDESMode::EDE2);
  Bytes key = random_bytes(use_two_keys ? 16 : 24,
                           0xBEEF + static_cast<uint32_t>(mode));
  print_hex("Key      ", key, use_two_keys ? 16 : 24);
  print_hex("Plaintext", plain);

  auto tdes = std::make_unique<crypto::des::TripleDES>(mode);
  crypto::io::SymmetricCipherIO io(std::move(tdes));
  io.set_encryption_key(key);
  io.set_decryption_key(key);

  Bytes cipher, recovered;
  double enc_ms = time_ms([&] { cipher = io.encrypt_bytes(plain); });
  double dec_ms = time_ms([&] { recovered = io.decrypt_bytes(cipher); });

  print_hex("Ciphertext", cipher);
  print_hex("Recovered ", recovered);
  verify(plain, recovered, "3DES-" + mode_label + " " + data_label);
  std::cout << "  Encrypt " << enc_ms << " ms  |  Decrypt " << dec_ms
            << " ms\n";
}

void demo_file(const std::string &type_label, const Bytes &content,
               const std::string &ext, crypto::des::TripleDESMode mode,
               const std::string &mode_label) {
  std::cout << "\n--- File demo: " << type_label << "  [3DES-" << mode_label
            << "] ---\n";

  const std::string base = "demo_files/" + type_label;
  const std::string plain_path = base + "_plain." + ext;
  const std::string enc_path = base + "_enc_" + mode_label + ".bin";
  const std::string dec_path = base + "_dec_" + mode_label + "." + ext;

  write_file(plain_path, content);

  bool use_two_keys = (mode == crypto::des::TripleDESMode::EEE2 ||
                       mode == crypto::des::TripleDESMode::EDE2);
  Bytes key = random_bytes(use_two_keys ? 16 : 24,
                           0xCAFE + static_cast<uint32_t>(mode));

  auto make_io = [&](crypto::des::TripleDESMode m) {
    return crypto::io::SymmetricCipherIO(
        std::make_unique<crypto::des::TripleDES>(m));
  };

  auto io = make_io(mode);
  io.set_encryption_key(key);
  io.set_decryption_key(key);

  double enc_ms = time_ms([&] { io.encrypt_file(plain_path, enc_path); });

  auto io2 = make_io(mode);
  io2.set_encryption_key(key);
  io2.set_decryption_key(key);
  double dec_ms = time_ms([&] { io2.decrypt_file(enc_path, dec_path); });

  Bytes recovered = read_file(dec_path);
  verify(content, recovered, type_label + " file [3DES-" + mode_label + "]");

  std::cout << "  " << content.size() << " bytes  |  "
            << "Encrypt " << enc_ms << " ms  |  Decrypt " << dec_ms << " ms\n";
  std::cout << "  plain → " << plain_path << "\n"
            << "  enc   → " << enc_path << "\n"
            << "  dec   → " << dec_path << "\n";
}

Bytes make_text_file() {
  std::string s;
  for (int i = 0; i < 500; ++i)
    s += "Line " + std::to_string(i) +
         ": The quick brown fox jumps over the lazy dog.\n";
  return Bytes(s.begin(), s.end());
}

Bytes make_bmp_like(int w = 64, int h = 64) {
  // Minimal 24-bit BMP header + gradient pixel data
  int row_bytes = w * 3;
  int pad = (4 - row_bytes % 4) % 4;
  int stride = row_bytes + pad;
  int pix_size = stride * h;
  int file_size = 54 + pix_size;

  Bytes bmp(file_size, 0);
  bmp[0] = 'B';
  bmp[1] = 'M';
  auto le32 = [&](int off, uint32_t v) {
    bmp[off] = v & 0xFF;
    bmp[off + 1] = (v >> 8) & 0xFF;
    bmp[off + 2] = (v >> 16) & 0xFF;
    bmp[off + 3] = (v >> 24) & 0xFF;
  };
  le32(2, file_size); // file size
  le32(10, 54);       // pixel data offset
  le32(14, 40);       // BITMAPINFOHEADER size
  le32(18, w);
  le32(22, h);
  bmp[26] = 1;
  bmp[28] = 24; // planes=1, bpp=24
  le32(34, pix_size);

  for (int y = 0; y < h; ++y)
    for (int x = 0; x < w; ++x) {
      int off = 54 + y * stride + x * 3;
      bmp[off + 0] = static_cast<uint8_t>(x * 4);       // B
      bmp[off + 1] = static_cast<uint8_t>(y * 4);       // G
      bmp[off + 2] = static_cast<uint8_t>((x + y) * 2); // R
    }
  return bmp;
}

Bytes make_wav_like(int samples = 8000) {
  int data_bytes = samples * 2;
  int file_size = 44 + data_bytes;
  Bytes wav(file_size, 0);
  auto le32 = [&](int off, uint32_t v) {
    wav[off] = v & 0xFF;
    wav[off + 1] = (v >> 8) & 0xFF;
    wav[off + 2] = (v >> 16) & 0xFF;
    wav[off + 3] = (v >> 24) & 0xFF;
  };
  auto le16 = [&](int off, uint16_t v) {
    wav[off] = v & 0xFF;
    wav[off + 1] = (v >> 8) & 0xFF;
  };
  wav[0] = 'R';
  wav[1] = 'I';
  wav[2] = 'F';
  wav[3] = 'F';
  le32(4, file_size - 8);
  wav[8] = 'W';
  wav[9] = 'A';
  wav[10] = 'V';
  wav[11] = 'E';
  wav[12] = 'f';
  wav[13] = 'm';
  wav[14] = 't';
  wav[15] = ' ';
  le32(16, 16);
  le16(20, 1);
  le16(22, 1);
  le32(24, 8000);
  le32(28, 16000);
  le16(32, 2);
  le16(34, 16);
  wav[36] = 'd';
  wav[37] = 'a';
  wav[38] = 't';
  wav[39] = 'a';
  le32(40, data_bytes);
  for (int i = 0; i < samples; ++i) {
    int16_t s = static_cast<int16_t>(
        32000 * std::sin(2 * 3.14159 * 440.0 * i / 8000.0));
    wav[44 + i * 2] = s & 0xFF;
    wav[44 + i * 2 + 1] = (s >> 8) & 0xFF;
  }
  return wav;
}

Bytes make_cpp_source() {
  std::string src = R"(
#include <cstdlib>
#include <print>
#include <random>

#include "task_runner.hpp"

int main() {
  int n = 10;
  size_t simulations = 1e8;

  TaskRunner runner;

  auto experiment = [n](auto& rng) {
    std::uniform_int_distribution<int> dist(0, n - 1);
    int x = dist(rng);
    int y = dist(rng);
    int z = dist(rng);

    int painted = 0;
    if (x == 0 || x == n - 1) {
      painted++;
    }
    if (y == 0 || y == n - 1) {
      painted++;
    }
    if (z == 0 || z == n - 1) {
      painted++;
    }

    return painted;
  };

  std::print("Cube painting experiment ({}x{}x{} small cubes)\n", n, n, n);
  auto results = runner.run(experiment, simulations);
  std::println();

  auto counts = tally(results);

  for (int faces = 1; faces <= 3; faces++) {
    size_t count = counts[faces];
    double prob = double(count) / simulations;
    std::print("Probability of {} painted faces = {:.6f}\n", faces, prob);
  }
}
)";
  return Bytes(src.begin(), src.end());
}

int main() {
  std::cout << "╔══════════════════════════════════════════════════════╗\n";
  std::cout << "║    DES / 3DES  Encryption & Decryption  Demo        ║\n";
  std::cout << "╚══════════════════════════════════════════════════════╝\n";

  const std::vector<std::pair<std::size_t, std::string>> seq_sizes = {
      {8, "8 B  (1 block)"}, {64, "64 B"},       {1024, "1 KiB"},
      {65536, "64 KiB"},     {1048576, "1 MiB"},
  };

  std::cout << "\n\n══ SECTION 1: DES ══════════════════════════════════════\n";
  for (auto &[sz, lbl] : seq_sizes)
    demo_des(random_bytes(sz), lbl);

  using Mode = crypto::des::TripleDESMode;
  const std::vector<std::pair<Mode, std::string>> modes = {
      {Mode::EEE3, "EEE3"},
      {Mode::EDE3, "EDE3"},
      {Mode::EEE2, "EEE2"},
      {Mode::EDE2, "EDE2"},
  };

  std::cout << "\n\n══ SECTION 2: 3DES  –  all modes ══════════════════════\n";
  for (auto &[mode, mlabel] : modes)
    for (auto &[sz, dlabel] : seq_sizes)
      demo_3des(random_bytes(sz, sz & 0xFFFF), mode, mlabel, dlabel);

  std::cout << "\n\n══ SECTION 3: File encryption (3DES modes) ═════════════\n";

  struct FileSpec {
    std::string label;
    std::string ext;
    std::function<Bytes()> gen;
    FileSpec(std::string l, std::string e, std::function<Bytes()> g)
        : label(std::move(l)), ext(std::move(e)), gen(std::move(g)) {}
  };

  std::vector<FileSpec> files;
  files.emplace_back("text", "txt", [] { return make_text_file(); });
  files.emplace_back("audio_wav", "wav", [] { return make_wav_like(); });
  files.emplace_back("image_bmp", "bmp", [] { return make_bmp_like(); });
  files.emplace_back("source_cpp", "cpp", [] { return make_cpp_source(); });

  for (auto &[mode, mlabel] : modes)
    for (auto &f : files)
      demo_file(f.label, f.gen(), f.ext, mode, mlabel);

  std::cout << "\n\n══ SECTION 4: File encryption (DES) ════════════════════\n";
  auto des_file_demo = [&](const std::string &type_label, const Bytes &content,
                           const std::string &ext) {
    std::cout << "\n--- File demo: " << type_label << "  [DES] ---\n";
    const std::string base = "demo_files/" + type_label;
    const std::string plain = base + "_plain." + ext;
    const std::string enc = base + "_enc_DES.bin";
    const std::string dec = base + "_dec_DES." + ext;

    write_file(plain, content);
    Bytes key = random_bytes(8, 0xABCD);

    auto make = [&] {
      auto io =
          crypto::io::SymmetricCipherIO(std::make_unique<crypto::des::DES>());
      io.set_encryption_key(key);
      io.set_decryption_key(key);
      return io;
    };

    auto io = make();
    double em = time_ms([&] { io.encrypt_file(plain, enc); });
    auto io2 = make();
    double dm = time_ms([&] { io2.decrypt_file(enc, dec); });

    verify(content, read_file(dec), type_label + " [DES]");
    std::cout << "  " << content.size() << " bytes  |  "
              << "Encrypt " << em << " ms  |  Decrypt " << dm << " ms\n";
  };

  for (auto &f : files)
    des_file_demo(f.label, f.gen(), f.ext);

  std::cout << "\n\n[ALL DEMOS COMPLETE]\n";
  return 0;
}
