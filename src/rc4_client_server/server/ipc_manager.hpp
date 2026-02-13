#ifndef RC4_CLIENT_SERVER_SERVER_IPC_MANAGER_HPP
#define RC4_CLIENT_SERVER_SERVER_IPC_MANAGER_HPP

#include "../common.hpp"
#include "rc4/encoder.hpp"
#include <vector>

class IPCManager final {
public:
  struct SessionData {
    size_t session_id;
    OperationType op;
    std::vector<uint8_t> data;
  };

  IPCManager();
  ~IPCManager();

  SessionData poll();

  crypto::rc4::Encoder &get_encoder(size_t session_id);

  bool send_result(size_t session_id, const std::vector<uint8_t> &data);

private:
  SharedMemory *m_shm;
  int m_shm_fd;
  std::array<crypto::rc4::Encoder, MAX_SESSIONS> m_encoders;
};

#endif // !RC4_CLIENT_SERVER_SERVER_IPC_MANAGER_HPP
