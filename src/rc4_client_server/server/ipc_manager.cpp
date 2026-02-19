#include "ipc_manager.hpp"
#include "../common.hpp"
#include <cstring>
#include <fcntl.h>
#include <semaphore.h>
#include <stdexcept>
#include <sys/mman.h>
#include <thread>
#include <unistd.h>

extern std::atomic<bool> g_shutdown;

IPCManager::IPCManager() : m_shm(nullptr), m_shm_fd(-1) {
  m_shm_fd = shm_open(SHARED_MEMORY_NAME, O_CREAT | O_RDWR, 0666);
  if (m_shm_fd < 0) {
    throw std::runtime_error("shm_open failed");
  }

  if (ftruncate(m_shm_fd, sizeof(SharedMemory)) < 0) {
    throw std::runtime_error("ftruncate failed");
  }

  m_shm = static_cast<SharedMemory *>(mmap(nullptr, sizeof(SharedMemory),
                                           PROT_READ | PROT_WRITE, MAP_SHARED,
                                           m_shm_fd, 0));

  if (m_shm == MAP_FAILED)
    throw std::runtime_error("mmap failed");

  for (size_t i = 0; i < MAX_SESSIONS; ++i) {
    auto &s = m_shm->sessions[i];
    s.operation = OperationType::Mutate;
    s.data_size = 0;
    sem_init(&s.sem_done, 1, 0);
    sem_init(&s.sem_ready, 1, 0);
  }
}

IPCManager::~IPCManager() {
  for (auto i = 0; i < MAX_SESSIONS; ++i) {
    sem_destroy(&m_shm->sessions[i].sem_done);
  }

  munmap(m_shm, sizeof(SharedMemory));
  close(m_shm_fd);
  shm_unlink(SHARED_MEMORY_NAME);
}

IPCManager::SessionData IPCManager::poll() {
  while (!g_shutdown.load()) {
    for (auto i = 0; i < MAX_SESSIONS; ++i) {
      auto &s = m_shm->sessions[i];

      if (sem_trywait(&s.sem_ready) == 0) {
        SessionData out;
        out.session_id = i;
        out.op = s.operation;
        out.data.assign(s.data, s.data + s.data_size);
        return out;
      }
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }

  // REACHABLE ONLY ON ^C
  return {};
}

bool IPCManager::send_result(size_t session_id,
                             const std::vector<uint8_t> &data) {
  if (session_id >= MAX_SESSIONS) {
    return false;
  }

  auto &s = m_shm->sessions[session_id];

  size_t n = std::min(data.size(), sizeof(s.data));
  memcpy(s.data, data.data(), n);
  s.data_size = n;

  sem_post(&s.sem_done);
  return true;
}

crypto::rc4::Encoder &IPCManager::get_encoder(size_t session_id) {
  if (session_id >= MAX_SESSIONS) {
    throw std::invalid_argument("Session id out of range");
  }

  return m_encoders[session_id];
}
