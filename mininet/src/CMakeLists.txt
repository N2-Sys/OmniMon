
add_library(my_library
        lib/ringbuffer.c
        lib/cpu.c
        lib/hash.c
        lib/util.c
        lib/packet_helper.c
        lib/global.c
        lib/config.c
        lib/adapter_record_ram.c
        hash_table.c
)
target_link_libraries(my_library pthread rt iniparser)

add_executable(receiver
	receiver.cpp)
target_link_libraries(receiver  pcap)


add_executable(end_host
        end_host.c
        )
target_link_libraries(end_host my_library dpdk dl numa zmq pcap)


add_executable(controller
        controller.c
        )

target_link_libraries(controller my_library zmq)




