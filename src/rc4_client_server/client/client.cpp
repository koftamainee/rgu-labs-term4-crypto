#include <exception>
#include <fstream>
#include <iostream>
#include <vector>

#include "input.hpp"
#include "session.hpp"

void do_encode(ClientSession &session, const std::string &input_file_path,
               const std::string &output_file_path) {
  std::ifstream fin(input_file_path, std::ios::binary);
  if (!fin.is_open()) {
    throw std::runtime_error("Failed to open input file: " + input_file_path);
  }

  std::ofstream fout(output_file_path, std::ios::binary);
  if (!fout.is_open()) {
    throw std::runtime_error("Failed to open output file: " + output_file_path);
  }

  std::vector<uint8_t> buffer(MAX_DATA_SIZE);
  while (fin) {
    fin.read(reinterpret_cast<char *>(buffer.data()), MAX_DATA_SIZE);
    std::streamsize bytes_read = fin.gcount();
    if (bytes_read <= 0)
      break;

    std::vector<uint8_t> chunk(buffer.begin(), buffer.begin() + bytes_read);

    auto encoded_chunk = session.encode(chunk);

    fout.write(reinterpret_cast<const char *>(encoded_chunk.data()),
               encoded_chunk.size());
  }

  fin.close();
  fout.close();
}

void do_mutate_text(ClientSession &session, const std::string &key) {

  std::vector<uint8_t> key_bytes(
      key.begin(), key.begin() + std::min(key.size(), size_t(MAX_DATA_SIZE)));
  session.mutate(key_bytes);
}

void do_mutate_file(ClientSession &session, const std::string &key_file_path) {
  std::ifstream infile(key_file_path, std::ios::binary);
  if (!infile) {
    throw std::runtime_error("Failed to open key file: " + key_file_path);
  }

  std::vector<uint8_t> key(MAX_DATA_SIZE);
  infile.read(reinterpret_cast<char *>(key.data()), MAX_DATA_SIZE);
  std::streamsize bytes_read = infile.gcount();
  key.resize(bytes_read);

  session.mutate(key);
  infile.close();
}

int main(int argc, char *argv[]) {
  try {
    if (argc != 2) {
      std::cerr << "Usage: " << argv[0] << " <instructions_file_path>\n";
      return 1;
    }

    const auto instructions = process_input_file(argv[1]);

    if (!instructions.empty() &&
        instructions[0].job_type != JobType::MutateText &&
        instructions[0].job_type != JobType::MutateFile) {
      std::cerr << "You need to mutate with key before encoding!\n";
      return 1;
    }

    ClientSession session;

    for (const auto &task : instructions) {
      switch (task.job_type) {
      case JobType::MutateText:
        std::cout << "Mutatig with key: " << task.arg1 << "... ";
        do_mutate_text(session, task.arg1);
        std::cout << "Done\n";
        break;

      case JobType::MutateFile:
        std::cout << "Mutatig with key from file: " << task.arg1 << "... ";
        do_mutate_file(session, task.arg1);
        std::cout << "Done\n";
        break;

      case JobType::EncodeFile:
        std::cout << "Encoding: " << task.arg1 << " to " << task.arg2 << "... ";
        do_encode(session, task.arg1, task.arg2);
        std::cout << "Done\n";
        break;
      }
    }

    std::cout << "\nAll tasks done. Ending session." << std::endl;
    return 0;

  } catch (const std::exception &e) {
    std::cerr << "Client error: " << e.what() << std::endl;
    return 1;
  }
}
