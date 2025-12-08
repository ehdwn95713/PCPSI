cmake_minimum_required(VERSION 3.10)
project(PSI)

# SocketLink 
add_library(socket_link
    network/socket_link.cpp
)
target_include_directories(socket_link PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/network)

# SEAL intall path
list(APPEND CMAKE_PREFIX_PATH "${CMAKE_SOURCE_DIR}/../HE/seal")
find_package(SEAL 4.1 REQUIRED CONFIG)

# # netpeer server
# add_executable(netpeer network/netpeer.cpp)
# target_include_directories(netpeer PRIVATE "${CMAKE_SOURCE_DIR}/../HE/seal/include")
# target_link_libraries(netpeer SEAL::seal)

# # source file
# add_executable(main main.cpp 
#     seal_util/examples.cpp
#     seal_util/batching.cpp
#     data/data_generator.cpp
#     data/data_reader.cpp
#     hashing/cuckoo.cpp
#     hashing/simple.cpp
#     hashing/p_cuckoo.cpp
#     network/sim.cpp
#     network/recorder.cpp)

# # include directory
# target_include_directories(main PRIVATE "${CMAKE_SOURCE_DIR}/../HE/seal/include")
# # library link
# target_link_libraries(main SEAL::seal)
# target_link_libraries(main socket_link SEAL::seal)

# # main_batchmode
# add_executable(main_batchmode
#     main_batchmode.cpp
#     seal_util/examples.cpp
#     seal_util/batching.cpp
#     data/data_generator.cpp
#     data/data_reader.cpp
#     hashing/cuckoo.cpp
#     hashing/simple.cpp
#     hashing/p_cuckoo.cpp
#     network/sim.cpp
#     network/recorder.cpp
# )
# # include directory
# target_include_directories(main_batchmode PRIVATE "${CMAKE_SOURCE_DIR}/../HE/seal/include")
# # library link
# target_link_libraries(main_batchmode SEAL::seal)
# target_link_libraries(main_batchmode socket_link SEAL::seal)

# # =========================
# # [Added] main_test_comm
# # A simple program to test communication cost of a given upload/download byte size
# # =========================
# add_executable(main_test_comm
#     main_test_comm.cpp
#     network/recorder.cpp
#     network/sim.cpp
# )
# target_include_directories(main_test_comm PRIVATE "${CMAKE_SOURCE_DIR}/../HE/seal/include")
# target_link_libraries(main_test_comm SEAL::seal)
# target_link_libraries(main_test_comm socket_link SEAL::seal)

# ============================================================
# [NEW] psi_client : 실제 클라이언트 (client.cpp)
# ============================================================
add_executable(psi_client
    client.cpp
    seal_util/examples.cpp
    seal_util/batching.cpp
    data/data_generator.cpp
    data/data_reader.cpp
    hashing/cuckoo.cpp
    hashing/simple.cpp
    hashing/p_cuckoo.cpp
)

target_include_directories(psi_client PRIVATE "${CMAKE_SOURCE_DIR}/../HE/seal/include")
target_link_libraries(psi_client
    SEAL::seal
    socket_link             # Wire는 POSIX socket 쓰지만, 필요 없으면 이 줄 삭제 가능
)

# ============================================================
# [NEW] psi_server : 실제 서버 (server.cpp)
# ============================================================
add_executable(psi_server
    server.cpp
    seal_util/examples.cpp
    seal_util/batching.cpp
    data/data_generator.cpp
    data/data_reader.cpp
    hashing/cuckoo.cpp
    hashing/simple.cpp
    hashing/p_cuckoo.cpp
)

target_include_directories(psi_server PRIVATE "${CMAKE_SOURCE_DIR}/../HE/seal/include")
target_link_libraries(psi_server
    SEAL::seal
    socket_link
)


# ============================================================
# [NEW] psi_client_1d : 실제 클라이언트 (client_1d.cpp)
# ============================================================
add_executable(psi_client_1d
    client_1d.cpp
    seal_util/examples.cpp
    seal_util/batching.cpp
    data/data_generator.cpp
    data/data_reader.cpp
    hashing/cuckoo.cpp
    hashing/simple.cpp
    hashing/p_cuckoo.cpp
)

target_include_directories(psi_client_1d PRIVATE "${CMAKE_SOURCE_DIR}/../HE/seal/include")
target_link_libraries(psi_client_1d
    SEAL::seal
    socket_link             # Wire는 POSIX socket 쓰지만, 필요 없으면 이 줄 삭제 가능
)

# ============================================================
# [NEW] psi_server_1d : 실제 서버 (server_1d.cpp)
# ============================================================
add_executable(psi_server_1d
    server_1d.cpp
    seal_util/examples.cpp
    seal_util/batching.cpp
    data/data_generator.cpp
    data/data_reader.cpp
    hashing/cuckoo.cpp
    hashing/simple.cpp
    hashing/p_cuckoo.cpp
)

target_include_directories(psi_server_1d PRIVATE "${CMAKE_SOURCE_DIR}/../HE/seal/include")
target_link_libraries(psi_server_1d
    SEAL::seal
    socket_link
)

# ============================================================
# [NEW] client_test : 통신 시간 측정용 클라이언트
# ============================================================
add_executable(client_test
    client_test.cpp
)

target_link_libraries(client_test
    SEAL::seal
    socket_link
)

# ============================================================
# [NEW] server_test : 통신 시간 측정용 서버
# ============================================================
add_executable(server_test
    server_test.cpp
)

target_link_libraries(server_test
    SEAL::seal
    socket_link
)

