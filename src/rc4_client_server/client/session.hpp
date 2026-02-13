#ifndef RC4_CLIENT_SERVER_CLIENT_SESSION_HPP
#define RC4_CLIENT_SERVER_CLIENT_SESSION_HPP

#include "../common.hpp"
#include <cstdint>
#include <vector>
class ClientSession final {
public:
  ClientSession();
  ~ClientSession();

  void mutate(const std::vector<uint8_t> &key);
  std::vector<uint8_t> encode(const std::vector<uint8_t> &data);

private:
  SharedMemory *m_shm;
  int m_session_id;

  bool open_shared_memory();
  int find_free_session();
};

#endif // !RC4_CLIENT_SERVER_CLIENT_SESSION_HPP
