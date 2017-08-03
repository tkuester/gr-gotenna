INCLUDE(FindPkgConfig)
PKG_CHECK_MODULES(PC_GOTENNA gotenna)

FIND_PATH(
    GOTENNA_INCLUDE_DIRS
    NAMES gotenna/api.h
    HINTS $ENV{GOTENNA_DIR}/include
        ${PC_GOTENNA_INCLUDEDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/include
          /usr/local/include
          /usr/include
)

FIND_LIBRARY(
    GOTENNA_LIBRARIES
    NAMES gnuradio-gotenna
    HINTS $ENV{GOTENNA_DIR}/lib
        ${PC_GOTENNA_LIBDIR}
    PATHS ${CMAKE_INSTALL_PREFIX}/lib
          ${CMAKE_INSTALL_PREFIX}/lib64
          /usr/local/lib
          /usr/local/lib64
          /usr/lib
          /usr/lib64
)

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(GOTENNA DEFAULT_MSG GOTENNA_LIBRARIES GOTENNA_INCLUDE_DIRS)
MARK_AS_ADVANCED(GOTENNA_LIBRARIES GOTENNA_INCLUDE_DIRS)

