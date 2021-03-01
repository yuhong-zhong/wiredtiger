#ifndef THREAD_MANAGER_H
#define THREAD_MANAGER_H

#include "thread_context.h"

namespace test_harness {
class thread_manager {
    public:
    ~thread_manager()
    {
        for (auto *worker : _workers) {
            /* Make sure the worker is done before deleting it. */
            worker->finish();
            delete worker;
        }
    }

    /*
     * Generic function to create threads that take contexts, typically these will be static
     * functions.
     */
    template <typename Callable>
    void
    add_thread(thread_context *tc, Callable &&fct)
    {
        tc->set_running(true);
        std::thread *t = new std::thread(fct, std::ref(*tc));
        tc->set_thread(t);
        _workers.push_back(tc);
    }

    /*
     * Generic function to create threads that do not take thread contexts but take a single
     * argument, typically these threads are calling non static member function of classes.
     */
    template <typename Callable, typename Args>
    void
    add_thread(thread_context *tc, Callable &&fct, Args&& args)
    {
        tc->set_running(true);
        std::thread *t = new std::thread(fct, args);
        tc->set_thread(t);
        _workers.push_back(tc);
    }

    void
    finish()
    {
        for (auto *worker : _workers) {
            if (worker == nullptr)
                debug_info("finish : worker is NULL", _trace_level, DEBUG_ERROR);
            else
                worker->finish();
        }
    }

    private:
    std::vector<thread_context *> _workers;
};
} // namespace test_harness

#endif
