#pragma once

#include <vector>
#include <thread>
#include <functional>
#include <queue>
#include <mutex>
#include <condition_variable>

class c_thread_pool
{
public:
    c_thread_pool ( size_t thread_count );
    ~c_thread_pool ( );

    void enqueue ( std::function<void ( )> task );

private:
    std::vector<std::thread> workers;
    std::queue<std::function<void ( )>> tasks;

    std::mutex queue_mutex;
    std::condition_variable condition;
    bool stop;
};
