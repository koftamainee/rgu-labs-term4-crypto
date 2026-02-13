#include "ipc_manager.hpp"
#include "../common.hpp"
#include <cstring>
#include <fcntl.h>
#include <optional>
#include <semaphore.h>
#include <stdexcept>
#include <sys/mman.h>
#include <unistd.h>

IPCManager::IPCManager()
    : m_sessions(nullptr), m_shm_fd(-1), m_sessions_count(0) {

  m_shm_fd = shm_open(SHARED_MEMORY_NAME, O_CREAT | O_RDWR, 0666);
  if (m_shm_fd < 0) {
    throw std::runtime_error("Failed to open shared memory");
  }

  if (ftruncate(m_shm_fd, sizeof(Session) * MAX_SESSIONS) < 0) {
    close(m_shm_fd);
    shm_unlink(SHARED_MEMORY_NAME);
    throw std::runtime_error("Failed to resize shared memory");
  }

  m_sessions = static_cast<Session *>(
      mmap(nullptr, sizeof(Session) * MAX_SESSIONS, PROT_READ | PROT_WRITE,
           MAP_SHARED, m_shm_fd, 0));
  if (m_sessions == MAP_FAILED) {
    close(m_shm_fd);
    shm_unlink(SHARED_MEMORY_NAME);
    throw std::runtime_error("Failed to map shared memory");
  }

  for (size_t i = 0; i < MAX_SESSIONS; ++i) {
    Session *s = m_sessions + i;
    s->status = SessionStatus::Free;
    s->operation = OperationType::Mutate;
    memset(s->data, 0, sizeof(s->data));

    if (sem_init(&s->sem_done, 1, 0) < 0) {
      munmap(m_sessions, sizeof(Session) * m_sessions_count);
      close(m_shm_fd);
      shm_unlink(SHARED_MEMORY_NAME);
      throw std::runtime_error("Failed to initialize semaphores");
    }
  }
}

IPCManager::~IPCManager() {
  for (size_t i = 0; i < MAX_SESSIONS; ++i) {
    sem_destroy(&m_sessions[i].sem_done);
  }

  if (m_sessions != NULL)
    munmap(m_sessions, sizeof(Session) * MAX_SESSIONS);

  if (m_shm_fd >= 0) {
    close(m_shm_fd);
    shm_unlink(SHARED_MEMORY_NAME);
  }
}

std::optional<IPCManager::SessionData> IPCManager::poll() {
  for (size_t i = 0; i < MAX_SESSIONS; ++i) {
    Session &s = m_sessions[i];

    if (s.status == SessionStatus::Ready) {
      SessionData result;
      result.op = s.operation;

      result.data.assign(s.data, s.data + s.data_size);

      return result;
    }
  }

  return std::nullopt;
}

bool IPCManager::send_result(size_t session_id,
                             const std::vector<uint8_t> &data) {
  if (session_id >= MAX_SESSIONS) {
    return false;
  }

  Session &s = m_sessions[session_id];

  if (s.status != SessionStatus::Ready)
    return false;

  size_t copy_size = std::min(data.size(), sizeof(s.data));
  std::memcpy(s.data, data.data(), copy_size);
  s.data_size = copy_size;

  s.status = SessionStatus::Done;

  sem_post(&s.sem_done);

  return true;
}
