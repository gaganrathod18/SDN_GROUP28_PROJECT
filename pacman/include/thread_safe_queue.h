#ifndef THREAD_SAFE_QUEUE_H
#define THREAD_SAFE_QUEUE_H

#include <queue>
#include <mutex>
#include <condition_variable>
#include <optional>
#include <chrono>

namespace DPI {

/**
 * @brief Bounded Thread-Safe Queue for producer-consumer pipelines.
 * Typically used to pass RawPacket items from capture thread to processing thread.
 * 
 * @tparam T The element type stored in the queue. Must be movable.
 */
template<typename T>
class ThreadSafeQueue {
public:
    /**
     * @brief Construct the queue with a maximum capacity limit.
     */
    explicit ThreadSafeQueue(size_t max_capacity = 10000) : max_capacity_limit_(max_capacity) {}
    
    /**
     * @brief Push an item into the queue. Blocks if the queue is full.
     * @param item The value to move or copy into the queue.
     */
    void push(T item) {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        // Wait until queue has space or a shutdown is requested.
        not_full_condition_.wait(lock, [this] { 
            return underlying_queue_.size() < max_capacity_limit_ || is_shutdown_requested_; 
        });
        
        if (is_shutdown_requested_) {
            return;
        }
        
        underlying_queue_.push(std::move(item));
        not_empty_condition_.notify_one();
    }
    
    /**
     * @brief Try to push an item without blocking.
     * @param item The value to move or copy into the queue.
     * @return true if successfully pushed, false if queue is full or shutdown.
     */
    bool tryPush(T item) {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        if (underlying_queue_.size() >= max_capacity_limit_ || is_shutdown_requested_) {
            return false;
        }
        underlying_queue_.push(std::move(item));
        not_empty_condition_.notify_one();
        return true;
    }
    
    /**
     * @brief Pop an item from the queue. Blocks if the queue is empty.
     * @return An optional containing the item, or std::nullopt if the queue is shut down.
     */
    std::optional<T> pop() {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        // Wait until there is an item or a shutdown is initiated.
        not_empty_condition_.wait(lock, [this] { 
            return !underlying_queue_.empty() || is_shutdown_requested_; 
        });
        
        if (underlying_queue_.empty()) {
            return std::nullopt;
        }
        
        T item = std::move(underlying_queue_.front());
        underlying_queue_.pop();
        not_full_condition_.notify_one();
        return item;
    }
    
    /**
     * @brief Pop an item from the queue with a maximum waiting timeout.
     * @param timeoutDuration The maximum time duration to wait.
     * @return The item if popped before timeout, otherwise std::nullopt.
     */
    std::optional<T> popWithTimeout(std::chrono::milliseconds timeoutDuration) {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        
        // Wait for timeout duration or until queue is ready/shutdown.
        const bool wait_success = not_empty_condition_.wait_for(
            lock, 
            timeoutDuration, 
            [this] { return !underlying_queue_.empty() || is_shutdown_requested_; }
        );
        
        if (!wait_success || underlying_queue_.empty()) {
            return std::nullopt;
        }
        
        T item = std::move(underlying_queue_.front());
        underlying_queue_.pop();
        not_full_condition_.notify_one();
        return item;
    }
    
    /**
     * @brief Check if the queue is currently empty.
     */
    [[nodiscard]] bool empty() const {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        return underlying_queue_.empty();
    }
    
    /**
     * @brief Get the current number of elements in the queue.
     */
    [[nodiscard]] size_t size() const {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        return underlying_queue_.size();
    }
    
    /**
     * @brief Signal the queue to shut down, waking up all blocked readers and writers.
     */
    void shutdown() {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        is_shutdown_requested_ = true;
        not_empty_condition_.notify_all();
        not_full_condition_.notify_all();
    }
    
    /**
     * @brief Check if a shutdown has been requested on this queue.
     */
    [[nodiscard]] bool isShutdown() const {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        return is_shutdown_requested_;
    }

private:
    std::queue<T> underlying_queue_;                     ///< The standard container holding queue elements
    mutable std::mutex queue_mutex_;                     ///< Mutex protecting all access to underlying_queue_
    std::condition_variable not_empty_condition_;       ///< Signaled when items are added to an empty queue
    std::condition_variable not_full_condition_;        ///< Signaled when items are removed from a full queue
    size_t max_capacity_limit_;                          ///< Configured upper bound on queue element count
    bool is_shutdown_requested_ = false;                ///< State flag indicating shutdown request status
};

} // namespace DPI

#endif // THREAD_SAFE_QUEUE_H