set(_UNICORN_SEARCHES)

if (UNICORN_ROOT)
    set(_UNICORN_SEARCH_ROOT ${UNICORN_ROOT})
    list(APPEND _UNICORN_SEARCHES _UNICORN_SEARCH_ROOT)
endif()

foreach(search ${_UNICORN_SEARCHES})
    # Include dir
    find_path(UNICORN_INCLUDE_DIR
            NAMES UNICORN/UNICORN.h
            PATHS ${${search}}
            PATH_SUFFIXES include)
endforeach()

foreach(search ${_UNICORN_SEARCHES})
    # Find the library itself
    find_library(UNICORN_LIBRARY
            NAMES unicorn_static
            PATHS ${${search}}
            PATH_SUFFIXES msvc/x64/Debug msvc/Win32/Debug)
endforeach()

mark_as_advanced(UNICORN_INCLUDE_DIR)

include(FindPackageHandleStandardArgs)

FIND_PACKAGE_HANDLE_STANDARD_ARGS(UNICORN REQUIRED_VARS UNICORN_LIBRARY UNICORN_INCLUDE_DIR
        VERSION_VAR UNICORN_VERSION_STRING)

if(UNICORN_FOUND)
    set(UNICORN_INCLUDE_DIRS ${UNICORN_INCLUDE_DIR})

    if(NOT UNICORN_LIBRARIES)
        set(UNICORN_LIBRARIES ${UNICORN_LIBRARY})
    endif()

    if(NOT TARGET UNICORN::UNICORN)
        add_library(UNICORN::UNICORN UNKNOWN IMPORTED)
        set_target_properties(UNICORN::UNICORN PROPERTIES
                INTERFACE_INCLUDE_DIRECTORIES "${UNICORN_INCLUDE_DIRS}")

        if(UNICORN_LIBRARY)
            set_property(TARGET UNICORN::UNICORN APPEND PROPERTY
                    IMPORTED_CONFIGURATIONS RELEASE)
            set_target_properties(UNICORN::UNICORN PROPERTIES
                    IMPORTED_LOCATION_RELEASE "${UNICORN_LIBRARY}")
        endif()

        if(NOT UNICORN_LIBRARY)
            set_property(TARGET UNICORN::UNICORN APPEND PROPERTY
                    IMPORTED_LOCATION "${UNICORN_LIBRARY}")
        endif()
    endif()
endif()