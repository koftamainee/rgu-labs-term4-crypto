#ifndef RC4_CLIENT_SERVER_COMMON_HPP
#define RC4_CLIENT_SERVER_COMMON_HPP

#include <atomic>
#include <cstdint>
#include <semaphore.h>

constexpr auto MAX_DATA_SIZE = 1 * 1024 * 1024; // 1 MB
constexpr auto MAX_SESSIONS = 2;
constexpr auto SHARED_MEMORY_NAME = "/rc4_shm";

enum class OperationType {
  Mutate,
  Encode,
};

struct Session {
  std::atomic<bool> claimed{false};
  OperationType operation = OperationType::Mutate;

  uint8_t data[MAX_DATA_SIZE];
  size_t data_size;

  sem_t sem_done;
  sem_t sem_ready;
};

struct SharedMemory {
  Session sessions[MAX_SESSIONS];
};

#endif // !RC4_CLIENT_SERVER_IPC_MANAGER_HPP
