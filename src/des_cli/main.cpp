#include "crypto/algorithms/des.hpp"
#include "crypto/algorithms/triple_des.hpp"
#include "crypto/io/symmetric_cipher.hpp"

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using Bytes = std::vector<uint8_t>;

class Spinner {
public:
  explicit Spinner(std::string label)
      : m_label(std::move(label)), m_running(false), m_pct(0) {}

  void start() {
    m_running = true;
    m_thread = std::thread([this] {
      static constexpr const char *frames[] = {"⣾", "⣽", "⣻", "⢿",
                                               "⡿", "⣟", "⣯", "⣷"};
      std::size_t i = 0;
      while (m_running.load(std::memory_order_relaxed)) {
        std::cerr << "\r  " << frames[i % 8] << "  " << m_label << "  "
                  << make_bar(m_pct.load()) << "  " << std::flush;
        ++i;
        std::this_thread::sleep_for(std::chrono::milliseconds(80));
      }
    });
  }

  void set_progress(int pct) { m_pct.store(pct, std::memory_order_relaxed); }

  void stop(bool ok = true) {
    m_running.store(false, std::memory_order_relaxed);
    if (m_thread.joinable())
      m_thread.join();
    int pct = ok ? 100 : m_pct.load();
    std::cerr << "\r  " << (ok ? "✔" : "✘") << "  " << m_label << "  "
              << make_bar(pct) << "  \n"
              << std::flush;
  }

  ~Spinner() {
    if (m_running.load())
      stop(false);
  }

private:
  static std::string make_bar(int pct) {
    std::ostringstream s;
    int filled = pct / 5;
    s << "[";
    for (int j = 0; j < 20; ++j)
      s << (j < filled ? "█" : "░");
    s << "] " << std::setw(3) << pct << "%";
    return s.str();
  }

  std::string m_label;
  std::atomic<bool> m_running;
  std::atomic<int> m_pct;
  std::thread m_thread;
};

static void print_usage(const char *argv0) {
  std::cerr << "Usage:\n"
               "  "
            << argv0
            << " -m <method> -k <hex_key> -i <input> -o <output> [-d]\n"
               "\n"
               "  -m  des | 3des-eee3 | 3des-ede3 | 3des-eee2 | 3des-ede2\n"
               "  -k  hex key (DES=16 chars, 3DES-3key=48 chars, 3DES-2key=32 "
               "chars)\n"
               "  -i  input file\n"
               "  -o  output file\n"
               "  -d  decrypt (default: encrypt)\n";
}

static std::string to_lower(std::string s) {
  for (char &c : s)
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return s;
}

static Bytes hex_to_bytes(const std::string &hex) {
  if (hex.size() % 2 != 0) {
    std::cerr << "Error: hex key length must be even.\n";
    std::exit(1);
  }
  Bytes out;
  out.reserve(hex.size() / 2);
  for (std::size_t i = 0; i < hex.size(); i += 2) {
    char buf[3] = {hex[i], hex[i + 1], '\0'};
    char *end = nullptr;
    unsigned long byte = std::strtoul(buf, &end, 16);
    if (end != buf + 2) {
      std::cerr << "Error: invalid hex character in key.\n";
      std::exit(1);
    }
    out.push_back(static_cast<uint8_t>(byte));
  }
  return out;
}

struct CipherHandle {
  crypto::io::SymmetricCipherIO io;
  std::size_t block_size;
};

static CipherHandle make_cipher(const std::string &method, const Bytes &key,
                                bool decrypting) {
  using Mode = crypto::des::TripleDESMode;
  const std::string m = to_lower(method);
  std::unique_ptr<crypto::core::SymmetricCipher> cipher;

  if (m == "des") {
    if (key.size() != 8) {
      std::cerr << "Error: DES needs 8-byte key.\n";
      std::exit(1);
    }
    cipher = std::make_unique<crypto::des::DES>();
  } else if (m == "3des-eee3") {
    if (key.size() != 24) {
      std::cerr << "Error: 3DES-EEE3 needs 24-byte key.\n";
      std::exit(1);
    }
    cipher = std::make_unique<crypto::des::TripleDES>(Mode::EEE3);
  } else if (m == "3des-ede3") {
    if (key.size() != 24) {
      std::cerr << "Error: 3DES-EDE3 needs 24-byte key.\n";
      std::exit(1);
    }
    cipher = std::make_unique<crypto::des::TripleDES>(Mode::EDE3);
  } else if (m == "3des-eee2") {
    if (key.size() != 16) {
      std::cerr << "Error: 3DES-EEE2 needs 16-byte key.\n";
      std::exit(1);
    }
    cipher = std::make_unique<crypto::des::TripleDES>(Mode::EEE2);
  } else if (m == "3des-ede2") {
    if (key.size() != 16) {
      std::cerr << "Error: 3DES-EDE2 needs 16-byte key.\n";
      std::exit(1);
    }
    cipher = std::make_unique<crypto::des::TripleDES>(Mode::EDE2);
  } else {
    std::cerr << "Error: unknown method '" << method << "'.\n\n";
    print_usage("des_cli");
    std::exit(1);
  }

  std::size_t bs = cipher->block_size();
  crypto::io::SymmetricCipherIO io(std::move(cipher));
  if (decrypting)
    io.set_decryption_key(key);
  else
    io.set_encryption_key(key);

  return CipherHandle{std::move(io), bs};
}

static void process(CipherHandle &handle, const std::string &input_path,
                    const std::string &output_path, bool decrypting,
                    Spinner &spinner) {
  std::ifstream in(input_path, std::ios::binary);
  if (!in) {
    std::cerr << "Error: cannot open input: " << input_path << "\n";
    std::exit(1);
  }

  std::ofstream out(output_path, std::ios::binary);
  if (!out) {
    std::cerr << "Error: cannot open output: " << output_path << "\n";
    std::exit(1);
  }

  in.seekg(0, std::ios::end);
  const std::streamsize total = in.tellg();
  in.seekg(0, std::ios::beg);

  const std::size_t bs = handle.block_size > 0 ? handle.block_size : 8;
  const std::size_t chunk_size = bs * 256;
  std::streamsize processed = 0;
  Bytes buf(chunk_size);

  while (in) {
    in.read(reinterpret_cast<char *>(buf.data()),
            static_cast<std::streamsize>(chunk_size));
    std::streamsize got = in.gcount();
    if (got <= 0)
      break;

    std::size_t aligned = (static_cast<std::size_t>(got) / bs) * bs;
    std::size_t remainder = static_cast<std::size_t>(got) - aligned;

    if (aligned > 0) {
      Bytes chunk(buf.begin(), buf.begin() + aligned);
      Bytes result = decrypting ? handle.io.decrypt_bytes(chunk)
                                : handle.io.encrypt_bytes(chunk);
      out.write(reinterpret_cast<const char *>(result.data()),
                static_cast<std::streamsize>(result.size()));
    }

    if (remainder > 0) {
      out.write(reinterpret_cast<const char *>(buf.data() + aligned),
                static_cast<std::streamsize>(remainder));
    }

    processed += got;
    spinner.set_progress(total > 0 ? static_cast<int>(processed * 100 / total)
                                   : 0);
  }
}

int main(int argc, char *argv[]) {
  std::string method, hex_key, input_path, output_path;
  bool decrypt = false;

  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if ((arg == "-m" || arg == "--method") && i + 1 < argc)
      method = argv[++i];
    else if ((arg == "-k" || arg == "--key") && i + 1 < argc)
      hex_key = argv[++i];
    else if ((arg == "-i" || arg == "--input") && i + 1 < argc)
      input_path = argv[++i];
    else if ((arg == "-o" || arg == "--output") && i + 1 < argc)
      output_path = argv[++i];
    else if (arg == "-d" || arg == "--decrypt")
      decrypt = true;
    else if (arg == "-h" || arg == "--help") {
      print_usage(argv[0]);
      return 0;
    } else {
      std::cerr << "Error: unknown argument '" << arg << "'.\n\n";
      print_usage(argv[0]);
      return 1;
    }
  }

  if (method.empty() || hex_key.empty() || input_path.empty() ||
      output_path.empty()) {
    std::cerr << "Error: -m, -k, -i, and -o are all required.\n\n";
    print_usage(argv[0]);
    return 1;
  }

  const auto key = hex_to_bytes(hex_key);
  auto handle = make_cipher(method, key, decrypt);
  const std::string label = std::string(decrypt ? "Decrypting" : "Encrypting") +
                            " [" + to_lower(method) + "]";

  std::cerr << "\n";
  Spinner spinner(label);
  spinner.start();

  bool success = true;
  try {
    process(handle, input_path, output_path, decrypt, spinner);
  } catch (const std::exception &e) {
    spinner.stop(false);
    std::cerr << "Error: " << e.what() << "\n";
    success = false;
  }

  if (success) {
    spinner.set_progress(100);
    spinner.stop(true);
    std::cerr << "\n";
  }

  return success ? 0 : 1;
}
