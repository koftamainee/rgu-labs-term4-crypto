
#include "session.hpp"
#include "rc4_client_server/common.hpp"
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <stdexcept>
#include <sys/mman.h>

ClientSession::ClientSession() : m_shm(nullptr), m_session_id(-1) {
  if (!open_shared_memory()) {
    throw std::runtime_error(
        "Failed to open shared memory. Is server running?");
  }

  m_session_id = find_free_session();
  if (m_session_id < 0) {
    throw std::runtime_error("No free sessions available");
  }
}

ClientSession::~ClientSession() {
  if (m_shm && m_session_id >= 0) {
    m_shm->sessions[m_session_id].claimed.store(false);
  }

  if (m_shm) {
    munmap(m_shm, sizeof(SharedMemory));
  }
}

void ClientSession::mutate(const std::vector<uint8_t> &key) {
  auto &sess = m_shm->sessions[m_session_id];

  sess.data_size = std::min(key.size(), sizeof(sess.data));
  std::memcpy(sess.data, key.data(), sess.data_size);

  sess.operation = OperationType::Mutate;

  sem_post(&sess.sem_ready);
  sem_wait(&sess.sem_done);
}

std::vector<uint8_t> ClientSession::encode(const std::vector<uint8_t> &data) {
  auto &sess = m_shm->sessions[m_session_id];

  sess.data_size = std::min(data.size(), sizeof(sess.data));
  std::memcpy(sess.data, data.data(), sess.data_size);

  sess.operation = OperationType::Encode;

  sem_post(&sess.sem_ready);
  sem_wait(&sess.sem_done);
  return std::vector<uint8_t>(sess.data, sess.data + sess.data_size);
}

bool ClientSession::open_shared_memory() {
  int shm_fd = shm_open(SHARED_MEMORY_NAME, O_RDWR, 0666);
  if (shm_fd < 0) {
    return false;
  }

  void *ptr = mmap(nullptr, sizeof(SharedMemory), PROT_READ | PROT_WRITE,
                   MAP_SHARED, shm_fd, 0);
  if (ptr == MAP_FAILED) {
    return false;
  }

  m_shm = static_cast<SharedMemory *>(ptr);
  return true;
}

int ClientSession::find_free_session() {
  for (auto i = 0; i < MAX_SESSIONS; ++i) {
    auto &sess = m_shm->sessions[i];

    bool expected = false;
    if (sess.claimed.compare_exchange_strong(expected, true)) {
      return i;
    }
  }
  return -1;
}
