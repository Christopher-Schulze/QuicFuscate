#ifndef THREAD_OPTIMIZATIONS_HPP
#define THREAD_OPTIMIZATIONS_HPP

#include "cache_optimizations.hpp"
#include <atomic>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <chrono>
#include <vector>
#include <deque>
#include <functional>
#include <memory>
#include <future>
#include <type_traits>

namespace quicsand {

/**
 * @brief Thread-sichere Counter-Klasse mit Vermeidung von False Sharing.
 *
 * Diese Klasse verwendet Padding, um sicherzustellen, dass mehrere Counter-Instanzen
 * in unterschiedlichen Cache-Linien liegen und somit False Sharing zwischen Threads vermieden wird.
 */
class alignas(CACHE_LINE_SIZE) AtomicCounter {
private:
    std::atomic<int64_t> value_{0};
    // Padding, um sicherzustellen, dass unterschiedliche Counter auf verschiedenen Cache-Linien liegen
    char padding_[CACHE_LINE_SIZE - sizeof(std::atomic<int64_t>)];

public:
    AtomicCounter() = default;
    explicit AtomicCounter(int64_t initial) : value_(initial) {}

    // Atomare Operationen
    int64_t increment() {
        return value_.fetch_add(1, std::memory_order_relaxed) + 1;
    }

    int64_t decrement() {
        return value_.fetch_sub(1, std::memory_order_relaxed) - 1;
    }

    int64_t add(int64_t val) {
        return value_.fetch_add(val, std::memory_order_relaxed) + val;
    }

    int64_t subtract(int64_t val) {
        return value_.fetch_sub(val, std::memory_order_relaxed) - val;
    }

    int64_t get() const {
        return value_.load(std::memory_order_relaxed);
    }

    void set(int64_t val) {
        value_.store(val, std::memory_order_relaxed);
    }
};

/**
 * @brief Cache-optimierter Mutex für effiziente Thread-Synchronisation.
 *
 * Dieser Mutex wird cache-aligned, um False Sharing zu vermeiden und
 * die Leistung in Multithreading-Szenarien zu verbessern.
 */
class alignas(CACHE_LINE_SIZE) CacheOptimizedMutex {
private:
    std::mutex mutex_;
    // Padding zur Vermeidung von False Sharing
    char padding_[CACHE_LINE_SIZE - sizeof(std::mutex)];

public:
    void lock() {
        mutex_.lock();
    }

    bool try_lock() {
        return mutex_.try_lock();
    }

    void unlock() {
        mutex_.unlock();
    }
};

/**
 * @brief RAII-Lock für CacheOptimizedMutex.
 */
class CacheOptimizedLock {
private:
    CacheOptimizedMutex& mutex_;

public:
    explicit CacheOptimizedLock(CacheOptimizedMutex& mutex) : mutex_(mutex) {
        mutex_.lock();
    }

    ~CacheOptimizedLock() {
        mutex_.unlock();
    }

    // Nicht kopierbar
    CacheOptimizedLock(const CacheOptimizedLock&) = delete;
    CacheOptimizedLock& operator=(const CacheOptimizedLock&) = delete;
};

/**
 * @brief Cache-freundliche Condition Variable.
 *
 * Diese Bedingungsvariable ist an Cache-Linien ausgerichtet, um
 * False Sharing zu vermeiden.
 */
class alignas(CACHE_LINE_SIZE) CacheOptimizedConditionVariable {
private:
    std::condition_variable cv_;
    // Padding zur Vermeidung von False Sharing
    char padding_[CACHE_LINE_SIZE - sizeof(std::condition_variable)];

public:
    template <typename Predicate>
    void wait(std::unique_lock<std::mutex>& lock, Predicate pred) {
        cv_.wait(lock, std::move(pred));
    }

    template <typename Rep, typename Period, typename Predicate>
    bool wait_for(std::unique_lock<std::mutex>& lock,
                 const std::chrono::duration<Rep, Period>& rel_time,
                 Predicate pred) {
        return cv_.wait_for(lock, rel_time, std::move(pred));
    }

    void notify_one() {
        cv_.notify_one();
    }

    void notify_all() {
        cv_.notify_all();
    }
};

/**
 * @brief Thread-Pool mit optimierten Sleep-Zuständen für energieeffiziente Ausführung.
 *
 * Diese Thread-Pool-Implementierung verwendet adaptive Sleeping-Strategien,
 * um CPU-Verbrauch zu minimieren, wenn keine Aufgaben zur Bearbeitung vorliegen.
 */
class EnergyEfficientThreadPool {
public:
    explicit EnergyEfficientThreadPool(size_t num_threads = std::thread::hardware_concurrency()) {
        start(num_threads);
    }

    ~EnergyEfficientThreadPool() {
        stop();
    }

    // Nicht kopierbar oder bewegbar
    EnergyEfficientThreadPool(const EnergyEfficientThreadPool&) = delete;
    EnergyEfficientThreadPool& operator=(const EnergyEfficientThreadPool&) = delete;
    EnergyEfficientThreadPool(EnergyEfficientThreadPool&&) = delete;
    EnergyEfficientThreadPool& operator=(EnergyEfficientThreadPool&&) = delete;

    /**
     * @brief Fügt eine neue Aufgabe zur Warteschlange hinzu.
     *
     * @tparam F Der Funktionstyp
     * @tparam Args Die Argumenttypen
     * @param f Die auszuführende Funktion
     * @param args Die Funktionsargumente
     * @return std::future<typename std::invoke_result<F, Args...>::type> Ein Future für das Ergebnis
     */
    template<class F, class... Args>
    auto enqueue(F&& f, Args&&... args) 
        -> std::future<typename std::invoke_result<F, Args...>::type> 
    {
        using return_type = typename std::invoke_result<F, Args...>::type;

        auto task = std::make_shared<std::packaged_task<return_type()>>(
            std::bind(std::forward<F>(f), std::forward<Args>(args)...)
        );
            
        std::future<return_type> res = task->get_future();
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            
            if (stop_) {
                throw std::runtime_error("enqueue on stopped ThreadPool");
            }
            
            tasks_.emplace_back([task]() { (*task)(); });
        }
        condition_.notify_one();
        return res;
    }

    /**
     * @brief Setzt die Energieeffizienz-Konfiguration.
     *
     * @param aggressive_sleep Aktiviert aggressives Schlafen bei Inaktivität
     * @param spin_count Anzahl der Spin-Iterationen vor dem Schlafen
     */
    void set_energy_efficiency(bool aggressive_sleep, int spin_count = 1000) {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        aggressive_sleep_ = aggressive_sleep;
        spin_count_ = spin_count;
    }

private:
    // Thread-Pool-Mitglieder
    std::vector<std::thread> workers_;
    std::deque<std::function<void()>> tasks_;
    
    // Synchronisationsprimitiven
    std::mutex queue_mutex_;
    std::condition_variable condition_;
    bool stop_ = false;
    
    // Energieeffizienz-Einstellungen
    bool aggressive_sleep_ = true;
    int spin_count_ = 1000;
    
    /**
     * @brief Startet den Thread-Pool mit der angegebenen Anzahl von Threads.
     *
     * @param num_threads Anzahl der zu erstellenden Threads
     */
    void start(size_t num_threads) {
        for (size_t i = 0; i < num_threads; ++i) {
            workers_.emplace_back([this] {
                while (true) {
                    std::function<void()> task;
                    
                    {
                        // Besitzen wir eine Aufgabe?
                        std::unique_lock<std::mutex> lock(queue_mutex_);
                        
                        // Adaptive Sleeping-Strategie
                        if (aggressive_sleep_) {
                            // Wenn aggressive_sleep aktiviert ist, warten wir auf die Bedingung
                            condition_.wait(lock, [this] {
                                return stop_ || !tasks_.empty();
                            });
                        } else {
                            // Ansonsten versuchen wir zuerst zu spinnen
                            int spin = 0;
                            while (tasks_.empty() && !stop_ && spin < spin_count_) {
                                lock.unlock();
                                // CPU Yield-Befehl für energieeffizientes Spinnen
                                std::this_thread::yield();
                                spin++;
                                lock.lock();
                            }
                            
                            // Wenn Spinnen erfolglos war, warten wir auf die Bedingung
                            if (tasks_.empty() && !stop_) {
                                condition_.wait(lock, [this] {
                                    return stop_ || !tasks_.empty();
                                });
                            }
                        }
                        
                        if (stop_ && tasks_.empty()) {
                            return;
                        }
                        
                        task = std::move(tasks_.front());
                        tasks_.pop_front();
                    }
                    
                    // Führe die Aufgabe aus
                    task();
                }
            });
        }
    }
    
    /**
     * @brief Stoppt den Thread-Pool und wartet auf die Beendigung aller Threads.
     */
    void stop() {
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            stop_ = true;
        }
        condition_.notify_all();
        for (std::thread& worker : workers_) {
            if (worker.joinable()) {
                worker.join();
            }
        }
    }
};

/**
 * @brief Thread-Optimierungskonfiguration.
 *
 * Diese Struktur definiert Konfigurationsoptionen für die Thread-Optimierungen.
 */
struct ThreadOptimizationConfig {
    bool enable_false_sharing_prevention = true;  // Aktiviert Maßnahmen gegen False Sharing
    bool aggressive_sleep = true;                // Aktiviert aggressives Schlafen für Energieeffizienz
    int spin_count = 1000;                      // Anzahl der Spin-Iterationen vor dem Schlafen
};

/**
 * @brief Cache-alignierte atomare Variable zur Vermeidung von False Sharing.
 *
 * @tparam T Der Typ der atomaren Variable (muss trivial kopierbar sein).
 */
template <typename T>
class alignas(CACHE_LINE_SIZE) CacheAlignedAtomic {
    static_assert(std::is_trivially_copyable<T>::value, 
                 "CacheAlignedAtomic requires a trivially copyable type");
                 
private:
    std::atomic<T> value_;
    // Padding zur Vermeidung von False Sharing
    char padding_[CACHE_LINE_SIZE - sizeof(std::atomic<T>)];
    
public:
    CacheAlignedAtomic() = default;
    
    explicit CacheAlignedAtomic(T val) : value_(val) {}
    
    T load(std::memory_order order = std::memory_order_seq_cst) const {
        return value_.load(order);
    }
    
    void store(T val, std::memory_order order = std::memory_order_seq_cst) {
        value_.store(val, order);
    }
    
    T exchange(T val, std::memory_order order = std::memory_order_seq_cst) {
        return value_.exchange(val, order);
    }
    
    bool compare_exchange_weak(T& expected, T desired, 
                              std::memory_order success,
                              std::memory_order failure) {
        return value_.compare_exchange_weak(expected, desired, success, failure);
    }
    
    bool compare_exchange_weak(T& expected, T desired, 
                              std::memory_order order = std::memory_order_seq_cst) {
        return value_.compare_exchange_weak(expected, desired, order);
    }
    
    bool compare_exchange_strong(T& expected, T desired, 
                               std::memory_order success,
                               std::memory_order failure) {
        return value_.compare_exchange_strong(expected, desired, success, failure);
    }
    
    bool compare_exchange_strong(T& expected, T desired, 
                                std::memory_order order = std::memory_order_seq_cst) {
        return value_.compare_exchange_strong(expected, desired, order);
    }
    
    // Arithmetische und bitweise Operationen für atomare Integer-Typen
    template <typename U = T>
    typename std::enable_if<std::is_integral<U>::value, T>::type
    fetch_add(T val, std::memory_order order = std::memory_order_seq_cst) {
        return value_.fetch_add(val, order);
    }
    
    template <typename U = T>
    typename std::enable_if<std::is_integral<U>::value, T>::type
    fetch_sub(T val, std::memory_order order = std::memory_order_seq_cst) {
        return value_.fetch_sub(val, order);
    }
    
    template <typename U = T>
    typename std::enable_if<std::is_integral<U>::value, T>::type
    fetch_and(T val, std::memory_order order = std::memory_order_seq_cst) {
        return value_.fetch_and(val, order);
    }
    
    template <typename U = T>
    typename std::enable_if<std::is_integral<U>::value, T>::type
    fetch_or(T val, std::memory_order order = std::memory_order_seq_cst) {
        return value_.fetch_or(val, order);
    }
    
    template <typename U = T>
    typename std::enable_if<std::is_integral<U>::value, T>::type
    fetch_xor(T val, std::memory_order order = std::memory_order_seq_cst) {
        return value_.fetch_xor(val, order);
    }
    
    // Überladene Operatoren
    T operator++() {
        return ++value_;
    }
    
    T operator++(int) {
        return value_++;
    }
    
    T operator--() {
        return --value_;
    }
    
    T operator--(int) {
        return value_--;
    }
    
    T operator+=(T val) {
        return value_ += val;
    }
    
    T operator-=(T val) {
        return value_ -= val;
    }
    
    T operator&=(T val) {
        return value_ &= val;
    }
    
    T operator|=(T val) {
        return value_ |= val;
    }
    
    T operator^=(T val) {
        return value_ ^= val;
    }
    
    operator T() const {
        return value_.load();
    }
};

} // namespace quicsand

#endif // THREAD_OPTIMIZATIONS_HPP
