#ifndef RUNTIME_MONITOR_H
#define RUNTIME_MONITOR_H

#include "component.h"

namespace test_harness {
/*
 * The runtime monitor class is designed to track various statistics or other runtime signals
 * relevant to the given workload.
 */
class runtime_monitor : public component {
    public:
    void
    run() {
        while (_running) {
            /* Do something. */
        }
    }
};
} // namespace test_harness

#endif
