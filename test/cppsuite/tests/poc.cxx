#include <iostream>
#include <cstdlib>

#include "test_harness/test.h"

class poc_test : public test_harness::test {
    public:
    poc_test(const std::string &config, int64_t trace_level) : test(config)
    {
        test_harness::_trace_level = trace_level;
    }

    void
    run()
    {
        test::run();
    }
};

const std::string poc_test::test::name = "poc_test";
const std::string poc_test::test::default_config =
  "collection_count=2,key_count=5,value_size=20,"
  "read_threads=1,duration_seconds=1";

int
main(int argc, char *argv[])
{
    std::string cfg = "";
    int64_t trace_level = 0;
    int64_t error_code = 0;

    // Parse args
    // -C   : Configuration
    // -t   : Trace level
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "-C") {
            if ((i + 1) < argc)
                cfg = argv[++i];
            else {
                std::cerr << "No value given for option " << argv[i] << std::endl;
                return (-1);
            }
        } else if (std::string(argv[i]) == "-t") {
            if ((i + 1) < argc)
                trace_level = std::stoi(argv[++i]);
            else {
                std::cerr << "No value given for option " << argv[i] << std::endl;
                return (-1);
            }
        }
    }

    // Check if default configuration should be used
    if (cfg.empty())
        cfg = poc_test::test::default_config;

    std::cout << "Configuration\t:" << cfg << std::endl;
    std::cout << "Tracel level\t:" << trace_level << std::endl;

    poc_test(cfg, trace_level).run();
    return (0);
}
