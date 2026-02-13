#include "work_queue.hpp"
#include <mutex>

void WorkQueue::push(IPCManager::SessionData job) {
  std::lock_guard<std::mutex> lock(m_mutex);

  if (m_closed) {
    return;
  }

  m_queue.push(std::move(job));
  m_cv.notify_one();
}

IPCManager::SessionData WorkQueue::pop() {
  std::unique_lock<std::mutex> lock(m_mutex);
  m_cv.wait(lock, [&] { return !m_queue.empty() || m_closed; });

  if (m_closed && m_queue.empty()) {
    throw std::runtime_error("Queue closed");
  }

  auto job = std::move(m_queue.front());
  m_queue.pop();
  return job;
}

void WorkQueue::close() {
  std::lock_guard<std::mutex> lock(m_mutex);
  m_closed = true;
  m_cv.notify_all();
}
