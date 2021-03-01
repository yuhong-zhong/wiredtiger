#ifndef THREAD_MANAGER_H
#define THREAD_MANAGER_H

#include "thread_context.h"

namespace test_harness {
/* Class that handles threads, from their initialization to their deletion. */
class thread_manager {
    public:
    ~thread_manager()
    {
        for (const auto& it : _workers) {
            delete it;
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
        _workers.push_back(t);
    }

    /*
     * Generic function to create threads that do not take thread contexts but take a single
     * argument, typically these threads are calling non static member function of classes.
     */
    template <typename Callable, typename Args>
    void
    add_thread(Callable &&fct, Args&& args)
    {
        std::thread *t = new std::thread(fct, args);
        _workers.push_back(t);
    }

    private:
    std::vector<std::thread *> _workers;
};
} // namespace test_harness

#endif
