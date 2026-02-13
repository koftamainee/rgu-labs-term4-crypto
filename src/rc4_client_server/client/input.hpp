#ifndef RC4_CLIENT_SERVER_CLIENT_INPUT_HPP
#define RC4_CLIENT_SERVER_CLIENT_INPUT_HPP

#include <string>
#include <vector>
enum class JobType {
  MutateText,
  MutateFile,

  EncodeFile,
};

struct Job {
  JobType job_type;
  std::string arg1;
  std::string arg2; // Only for encode
};

std::vector<Job> process_input_file(const std::string &input_file_path);

#endif // !RC4_CLIENT_SERVER_CLIENT_INPUT_HPP
