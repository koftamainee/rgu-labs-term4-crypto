#ifndef RC4_CLIENT_SERVER_SERVER_WORK_QUEUE_HPP
#define RC4_CLIENT_SERVER_SERVER_WORK_QUEUE_HPP

#include <condition_variable>
#include <mutex>
#include <queue>

#include "ipc_manager.hpp"

class WorkQueue final {
public:
  void push(IPCManager::SessionData job);

  IPCManager::SessionData pop();

  void close();

private:
  bool m_closed = false;
  std::mutex m_mutex;
  std::condition_variable m_cv;
  std::queue<IPCManager::SessionData> m_queue;
};

#endif // !RC4_CLIENT_SERVER_SERVER_WORK_QUEUE_HPP
