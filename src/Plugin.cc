#include "Plugin.h"
#include "analyzer/Component.h"

namespace plugin { 
    namespace Zeek_PROFINET {
        Plugin plugin;
        }
    }

using namespace plugin::Zeek_PROFINET;

plugin::Configuration Plugin::Configure() {
    AddComponent(new ::analyzer::Component("PROFINET", ::analyzer::profinet::PROFINET_Analyzer::Instantiate));
    
    plugin::Configuration config;
    config.name = "Zeek::PROFINET";
    config.description = "Profinet Protocol analyzer";
    return config;
    }
