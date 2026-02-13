#include "input.hpp"
#include <fstream>
#include <sstream>

static inline std::string trim(const std::string &s) {
  auto start = s.find_first_not_of(" \t\r\n");
  if (start == std::string::npos)
    return "";
  auto end = s.find_last_not_of(" \t\r\n");
  return s.substr(start, end - start + 1);
}

std::vector<Job> process_input_file(const std::string &input_file_path) {
  std::ifstream fin(input_file_path);
  if (!fin.is_open()) {
    throw std::runtime_error("Failed to open input file: " + input_file_path);
  }

  std::vector<Job> jobs;
  std::string line;

  while (std::getline(fin, line)) {
    line = trim(line);
    if (line.empty() || line[0] == '#')
      continue;

    std::istringstream iss(line);
    std::string command;
    iss >> command;

    if (command == "MUTATE") {
      std::string type_or_path;
      iss >> type_or_path;

      if (type_or_path == "TEXT") {
        std::string key;
        std::getline(iss, key);
        key = trim(key);
        if (key.empty())
          throw std::runtime_error("MUTATE TEXT missing key");
        jobs.push_back(Job{JobType::MutateText, key, ""});

      } else if (type_or_path == "FILE") {
        std::string key_file;
        iss >> key_file;
        if (key_file.empty())
          throw std::runtime_error("MUTATE FILE missing file path");
        jobs.push_back(Job{JobType::MutateFile, key_file, ""});

      } else {
        throw std::runtime_error("Unknown MUTATE type: " + type_or_path);
      }
    } else if (command == "ENCODE") {
      std::string input_path, output_path;
      iss >> input_path >> output_path;
      if (input_path.empty() || output_path.empty()) {
        throw std::runtime_error("ENCODE missing input/output paths");
      }
      jobs.push_back(Job{JobType::EncodeFile, input_path, output_path});

    } else {
      throw std::runtime_error("Unknown command: " + command);
    }
  }

  return jobs;
}
