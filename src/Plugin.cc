#include "Plugin.h"
#include "zeek/analyzer/Component.h"

namespace plugin {
    namespace Zeek_PROFINET {
        Plugin plugin;
        }
    }

using namespace plugin::Zeek_PROFINET;

zeek::plugin::Configuration Plugin::Configure() {
    AddComponent(new zeek::analyzer::Component("PROFINET", analyzer::profinet::PROFINET_Analyzer::Instantiate));

    zeek::plugin::Configuration config;
    config.name = "Zeek::PROFINET";
    config.description = "PROFINET protocol analyzer";
    return config;
    }
