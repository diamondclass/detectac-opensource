#include "thread_pool.h"

c_thread_pool::c_thread_pool ( size_t thread_count ) : stop ( false )
{
    for ( size_t i = 0; i < thread_count; ++i )
    {
        workers.emplace_back ( [ this ]
            {
                while ( true )
                {
                    std::function<void ( )> task;
                    {
                        std::unique_lock<std::mutex> lock ( this->queue_mutex );
                        this->condition.wait ( lock , [ this ] { return this->stop || !this->tasks.empty ( ); } );
                        if ( this->stop && this->tasks.empty ( ) )
                            return;
                        task = std::move ( this->tasks.front ( ) );
                        this->tasks.pop ( );
                    }
                    task ( );
                }
            } );
    }
}

c_thread_pool::~c_thread_pool ( )
{
    {
        std::unique_lock<std::mutex> lock ( queue_mutex );
        stop = true;
    }
    condition.notify_all ( );
    for ( std::thread& worker : workers )
        worker.join ( );
}

void c_thread_pool::enqueue ( std::function<void ( )> task )
{
    {
        std::unique_lock<std::mutex> lock ( queue_mutex );
        if ( stop )
            throw std::runtime_error ( (  xorstr_("enqueue on stopped thread pool") ));
        tasks.emplace ( task );
    }
    condition.notify_one ( );
}
