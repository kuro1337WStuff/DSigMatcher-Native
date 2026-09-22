#pragma once

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <thread>
#include <type_traits>
#include <vector>

namespace DSig {

class ThreadPool {
public:
  explicit ThreadPool(unsigned WorkerCount = 0);
  ~ThreadPool();

  ThreadPool(const ThreadPool& Other) = delete;
  ThreadPool& operator=(const ThreadPool& Other) = delete;
  ThreadPool(ThreadPool&& Other) = delete;
  ThreadPool& operator=(ThreadPool&& Other) = delete;

  template <typename Body>
  void ParallelFor(size_t ItemCount, Body Handler) {
    using HandlerType = typename std::remove_reference<Body>::type;
    if (InWorker_) {
      for (size_t Index = 0; Index < ItemCount; ++Index) {
        Handler(Index);
      }
      return;
    }
    RunBatch(ItemCount, &ThreadPool::Invoke<HandlerType>, static_cast<void*>(&Handler));
  }

  unsigned WorkerCount() const { return WorkerCount_; }

private:
  using ItemHandler = void (*)(void*, size_t);

  template <typename HandlerType>
  static void Invoke(void* Context, size_t Index) {
    (*static_cast<HandlerType*>(Context))(Index);
  }

  static thread_local bool InWorker_;

  class WorkerScope {
  public:
    WorkerScope() : Previous_(InWorker_) { InWorker_ = true; }
    ~WorkerScope() { InWorker_ = Previous_; }

    WorkerScope(const WorkerScope& Other) = delete;
    WorkerScope& operator=(const WorkerScope& Other) = delete;

  private:
    bool Previous_;
  };

  void RunBatch(size_t ItemCount, ItemHandler Handler, void* Context);
  void Drain(size_t ItemCount, ItemHandler Handler, void* Context);
  void WorkerMain();

  const unsigned WorkerCount_ = 1;
  unsigned Spawned_ = 0;
  std::vector<std::thread> Threads_;

  std::mutex Batch_;
  std::mutex State_;
  std::condition_variable Wake_;
  std::condition_variable Done_;

  ItemHandler Handler_ = nullptr;
  void* Context_ = nullptr;
  size_t ItemCount_ = 0;
  std::atomic<size_t> NextItem_{0};
  std::atomic<bool> Stop_{false};
  unsigned Finished_ = 0;
  uint64_t Generation_ = 0;
};

}
