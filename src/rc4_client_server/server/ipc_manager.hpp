#ifndef RC4_CLIENT_SERVER_SERVER_IPC_MANAGER_HPP
#define RC4_CLIENT_SERVER_SERVER_IPC_MANAGER_HPP

#include "../common.hpp"
#include <optional>
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

  std::optional<SessionData> poll();

  bool send_result(size_t session_id, const std::vector<uint8_t> &data);

private:
  Session *m_sessions;
  int m_shm_fd;
  size_t m_sessions_count;
};

#endif // !RC4_CLIENT_SERVER_SERVER_IPC_MANAGER_HPP
