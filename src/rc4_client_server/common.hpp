#ifndef RC4_CLIENT_SERVER_COMMON_HPP
#define RC4_CLIENT_SERVER_COMMON_HPP

#include <cstdint>
#include <semaphore.h>

constexpr auto MAX_DATA_SIZE = 10 * 1024 * 1024; // 256 MB
constexpr auto MAX_SESSIONS = 100;
constexpr auto SHARED_MEMORY_NAME = "/rc4_shm";

enum class OperationType {
  Mutate,
  Encode,
};

enum class SessionStatus {
  Free,
  Ready,
  Done,
};

struct Session {
  SessionStatus status = SessionStatus::Free;
  OperationType operation = OperationType::Mutate;

  uint8_t data[MAX_DATA_SIZE];
  size_t data_size;

  sem_t sem_done;
};

#endif // !RC4_CLIENT_SERVER_IPC_MANAGER_HPP
