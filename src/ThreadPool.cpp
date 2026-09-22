#include "dsigmatcher/ThreadPool.h"

namespace DSig {

namespace {

unsigned NormaliseWorkerCount(unsigned Requested) {
  if (Requested != 0) {
    return Requested;
  }
  const unsigned Detected = std::thread::hardware_concurrency();
  return Detected != 0 ? Detected : 1u;
}

}

thread_local bool ThreadPool::InWorker_ = false;

ThreadPool::ThreadPool(unsigned WorkerCount) : WorkerCount_(NormaliseWorkerCount(WorkerCount)) {
  if (WorkerCount_ < 2) {
    return;
  }
  Spawned_ = WorkerCount_ - 1;
  Threads_.reserve(Spawned_);
  for (unsigned Slot = 0; Slot < Spawned_; ++Slot) {
    Threads_.emplace_back([this]() { WorkerMain(); });
  }
}

ThreadPool::~ThreadPool() {
  {
    const std::lock_guard<std::mutex> Lock(State_);
    Stop_.store(true);
  }
  Wake_.notify_all();
  for (std::thread& Worker : Threads_) {
    if (Worker.joinable()) {
      Worker.join();
    }
  }
}

void ThreadPool::WorkerMain() {
  const WorkerScope Scope;
  uint64_t Seen = 0;
  std::unique_lock<std::mutex> Lock(State_);
  for (;;) {
    Wake_.wait(Lock, [this, Seen]() { return Stop_.load() || Generation_ != Seen; });
    if (Stop_.load()) {
      return;
    }
    Seen = Generation_;
    const ItemHandler Handler = Handler_;
    void* Context = Context_;
    const size_t ItemCount = ItemCount_;
    Lock.unlock();
    Drain(ItemCount, Handler, Context);
    Lock.lock();
    ++Finished_;
    Done_.notify_one();
  }
}

void ThreadPool::Drain(size_t ItemCount, ItemHandler Handler, void* Context) {
  const size_t Divisor = static_cast<size_t>(WorkerCount_) * 2;
  for (;;) {
    if (Stop_.load(std::memory_order_relaxed)) {
      return;
    }
    const size_t Next = NextItem_.load(std::memory_order_relaxed);
    if (Next >= ItemCount) {
      return;
    }
    const size_t Remaining = ItemCount - Next;
    size_t Chunk = Remaining / Divisor;
    if (Chunk == 0) {
      Chunk = 1;
    }
    size_t Expected = Next;
    if (!NextItem_.compare_exchange_strong(Expected, Next + Chunk, std::memory_order_acq_rel)) {
      continue;
    }
    const size_t Limit = Next + Chunk;
    for (size_t Index = Next; Index < Limit; ++Index) {
      Handler(Context, Index);
    }
  }
}

void ThreadPool::RunBatch(size_t ItemCount, ItemHandler Handler, void* Context) {
  if (ItemCount == 0) {
    return;
  }
  if (Spawned_ == 0) {
    for (size_t Index = 0; Index < ItemCount; ++Index) {
      Handler(Context, Index);
    }
    return;
  }

  const std::lock_guard<std::mutex> Guard(Batch_);
  {
    const std::lock_guard<std::mutex> Lock(State_);
    Handler_ = Handler;
    Context_ = Context;
    ItemCount_ = ItemCount;
    NextItem_.store(0, std::memory_order_relaxed);
    Finished_ = 0;
    ++Generation_;
  }
  Wake_.notify_all();

  {
    const WorkerScope Scope;
    Drain(ItemCount, Handler, Context);
  }

  std::unique_lock<std::mutex> Lock(State_);
  Done_.wait(Lock, [this]() { return Finished_ == Spawned_; });
}

}
