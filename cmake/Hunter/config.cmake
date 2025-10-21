hunter_config(CURL VERSION ${HUNTER_CURL_VERSION} CMAKE_ARGS HTTP_ONLY=ON CMAKE_USE_OPENSSL=OFF CMAKE_USE_LIBSSH2=OFF CURL_CA_PATH=none)
hunter_config(Boost VERSION 1.66.0-p1
    URL https://archives.boost.io/release/1.66.0/source/boost_1_66_0.7z
    SHA1 075d0b43980614054b1f1bafd189f863bba6600e
)

hunter_config(ethash VERSION 0.4.1
    URL https://github.com/chfast/ethash/archive/v0.4.1.tar.gz
    SHA1 12a7ad52809ca74f2a5e8f849408f0ebf795719c
)
