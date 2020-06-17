cmake_minimum_required(VERSION 3.15)

PROJECT(network_capture)

ADD_SUBDIRECTORY(libpcap)

SET(
        SRC_LIST
        packet_capture.cpp
)

ADD_EXECUTABLE(
        ${PROJECT_NAME}
        ${SRC_LIST}
)

TARGET_LINK_LIBRARIES(
        ${PROJECT_NAME}
        pcap
)