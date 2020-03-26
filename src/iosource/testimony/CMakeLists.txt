
include(ZeekPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

zeek_plugin_begin(Zeek Testimony)
zeek_plugin_cc(Plugin.cc Source.cc)
#bif_target(pcap.bif)
zeek_plugin_end()
