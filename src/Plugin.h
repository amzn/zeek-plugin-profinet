#ifndef ZEEK_PLUGIN_ZEEK_PROFINET
#define ZEEK_PLUGIN_ZEEK_PROFINET

#include <zeek/plugin/Plugin.h>
#include "PROFINET.h"

namespace plugin {
    namespace Zeek_PROFINET {
        class Plugin : public zeek::plugin::Plugin {
            protected:
                // Overridden from plugin::Plugin.
                virtual zeek::plugin::Configuration Configure();
            };

        extern Plugin plugin;
        }
    }

#endif
