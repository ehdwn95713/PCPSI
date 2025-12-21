cmake_minimum_required(VERSION 3.10)
project(PSI)

# SEAL intall path
list(APPEND CMAKE_PREFIX_PATH "${CMAKE_SOURCE_DIR}/../HE/seal")
find_package(SEAL 4.1 REQUIRED CONFIG)



# ============================================================
# [NEW] psi_client : (client.cpp)
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

)

# ============================================================
# [NEW] psi_server : (server.cpp)
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
    
)

# # ============================================================
# # [NEW] client_test : 
# # ============================================================
# add_executable(client_test
#     client_test.cpp
# )

# target_link_libraries(client_test
#     SEAL::seal
#     socket_link
# )

# # ============================================================
# # [NEW] server_test : 
# # ============================================================
# add_executable(server_test
#     server_test.cpp
# )

# target_link_libraries(server_test
#     SEAL::seal
#     socket_link
# )

