set(_CAPSTONE_SEARCHES)

if (CAPSTONE_ROOT)
    set(_CAPSTONE_SEARCH_ROOT ${CAPSTONE_ROOT})
    list(APPEND _CAPSTONE_SEARCHES _CAPSTONE_SEARCH_ROOT)
endif()

foreach(search ${_CAPSTONE_SEARCHES})
    # Include dir
    find_path(CAPSTONE_INCLUDE_DIR
            NAMES capstone/capstone.h
            PATHS ${${search}}
            PATH_SUFFIXES include)
endforeach()

foreach(search ${_CAPSTONE_SEARCHES})
    # Find the library itself
    find_library(CAPSTONE_LIBRARY
            NAMES capstone
            PATHS ${${search}}
            PATH_SUFFIXES lib lib64)
endforeach()

mark_as_advanced(CAPSTONE_INCLUDE_DIR)

include(FindPackageHandleStandardArgs)

FIND_PACKAGE_HANDLE_STANDARD_ARGS(CAPSTONE REQUIRED_VARS CAPSTONE_LIBRARY CAPSTONE_INCLUDE_DIR
        VERSION_VAR CAPSTONE_VERSION_STRING)

if(CAPSTONE_FOUND)
    set(CAPSTONE_INCLUDE_DIRS ${CAPSTONE_INCLUDE_DIR})

    if(NOT CAPSTONE_LIBRARIES)
        set(CAPSTONE_LIBRARIES ${CAPSTONE_LIBRARY})
    endif()

    if(NOT TARGET CAPSTONE::CAPSTONE)
        add_library(CAPSTONE::CAPSTONE UNKNOWN IMPORTED)
        set_target_properties(CAPSTONE::CAPSTONE PROPERTIES
                INTERFACE_INCLUDE_DIRECTORIES "${CAPSTONE_INCLUDE_DIRS}")

        if(CAPSTONE_LIBRARY)
            set_property(TARGET CAPSTONE::CAPSTONE APPEND PROPERTY
                    IMPORTED_CONFIGURATIONS RELEASE)
            set_target_properties(CAPSTONE::CAPSTONE PROPERTIES
                    IMPORTED_LOCATION_RELEASE "${CAPSTONE_LIBRARY}")
        endif()

        if(NOT CAPSTONE_LIBRARY)
            set_property(TARGET CAPSTONE::CAPSTONE APPEND PROPERTY
                    IMPORTED_LOCATION "${CAPSTONE_LIBRARY}")
        endif()
    endif()
endif()
