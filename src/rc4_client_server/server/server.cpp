#include "ipc_manager.hpp"
#include "work_queue.hpp"
#include <chrono>
#include <csignal>
#include <cstddef>
#include <iostream>
#include <thread>

const size_t THREAD_COUNT = std::thread::hardware_concurrency();

std::atomic<bool> g_shutdown{false};
WorkQueue *g_queue_ptr = nullptr;

void handle_sigint(int) {
  std::cout << "\nCtrl+C detected, shutting down server..." << std::endl;
  g_shutdown.store(true);

  if (g_queue_ptr != NULL) {
    g_queue_ptr->close();
  }
}

void worker_loop(IPCManager &ipc, WorkQueue &queue) {
  while (!g_shutdown.load()) {

    IPCManager::SessionData session;
    try {
      session = queue.pop();
    } catch (const std::runtime_error &) {
      break;
    }

    auto &encoder = ipc.get_encoder(session.session_id);

    switch (session.op) {
    case OperationType::Mutate:
      encoder.mutate(session.data);
      break;
    case OperationType::Encode:
      encoder.encode(session.data);
      break;
    }

    ipc.send_result(session.session_id, session.data);
  }
}

void dispatcher_loop(IPCManager &ipc, WorkQueue &queue) {
  while (!g_shutdown.load()) {
    auto job = ipc.poll();
    queue.push(std::move(job));
  }
}

int main() {
  try {
    IPCManager ipc;
    WorkQueue queue;

    g_queue_ptr = &queue;

    std::signal(SIGINT, handle_sigint);

    std::vector<std::thread> pool;
    pool.reserve(THREAD_COUNT);

    for (auto i = 0; i < THREAD_COUNT; ++i) {
      pool.emplace_back(worker_loop, std::ref(ipc), std::ref(queue));
    }

    std::cout << "Server running with " << THREAD_COUNT << " worker threads..."
              << std::endl;

    std::thread dispatcher(dispatcher_loop, std::ref(ipc), std::ref(queue));

    std::cout << "Server running..." << std::endl;

    dispatcher.join();

    for (auto &t : pool) {

      t.join();
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    std::cout << "Server shutdown complete." << std::endl;

    return 0;

  } catch (const std::exception &e) {
    std::cerr << "Server error: " << e.what() << std::endl;
    return 1;
  }
}
