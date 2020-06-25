

aux_source_directory(. SRC_LIST)

add_library(om_dev
    # lib/ringbuffer.c
    # lib/cpu.c
    lib/hash.c
    lib/util.c
    lib/packet_helper.c
    lib/global.c
    lib/config.c
    # lib/adapter_record_ram.c
    # hash_table.c
)
target_link_libraries(om_dev pthread rt iniparser pcap)

add_executable(generate_omtrace
    data_preprocess/generate_omtrace.c
    lib/adapter_pcap_ram.c)
target_link_libraries(generate_omtrace om_dev dpdk dl numa zmq mtcp m gmp)

add_executable(omhost
    omhost.c
    lib/adapter_pcap_ram.c)
target_link_libraries(omhost om_dev dpdk dl numa mtcp m gmp)

add_executable(host_tx
    host_tx.c
    lib/adapter_pcap_ram.c)
target_link_libraries(host_tx om_dev dpdk dl numa mtcp m gmp)

add_executable(host_rx
    host_rx.c
    lib/adapter_pcap_ram.c)
target_link_libraries(host_rx om_dev dpdk dl numa mtcp m gmp)

add_executable(controller
    controller.c)
target_link_libraries(controller om_dev dpdk dl numa mtcp m gmp)

add_executable(add_mac
    data_preprocess/add_macaddr.c
    lib/adapter_pcap_ram.c)
target_link_libraries(add_mac om_dev)
