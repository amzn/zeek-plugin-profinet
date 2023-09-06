
cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

project(Plugin)

include(ZeekPlugin)

zeek_plugin_begin(Zeek Profinet)
    zeek_plugin_cc(src/PROFINET.cc src/Plugin.cc)
    zeek_plugin_bif(src/events.bif)
    zeek_plugin_pac(src/profinet.pac src/profinet-analyzer.pac src/profinet-protocol.pac)
    zeek_plugin_dist_files(README CHANGES COPYING VERSION)
zeek_plugin_end()
