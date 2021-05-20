# make cmake scripts believe we support dynamic linking
set_property(GLOBAL PROPERTY TARGET_SUPPORTS_SHARED_LIBS true)

# give it our pseudolinker
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  set(CMAKE_DL_LIBS "-lsolderd" CACHE STRING "" FORCE)
else()
  set(CMAKE_DL_LIBS "-lsolder" CACHE STRING "" FORCE)
endif()

# switch.cmake is missing these
set(CMAKE_SHARED_LINKER_FLAGS "-fPIE -specs=${DEVKITPRO}/libnx/switch.specs -rdynamic -shared -nostartfiles -nostdlib ${CMAKE_SHARED_LINKER_FLAGS}")
set(CMAKE_MODULE_LINKER_FLAGS "-fPIE -specs=${DEVKITPRO}/libnx/switch.specs -rdynamic -shared -nostartfiles -nostdlib ${CMAKE_MODULE_LINKER_FLAGS}")

# don't link anything by default
set(CMAKE_C_STANDARD_LIBRARIES "" CACHE STRING "" FORCE)
set(CMAKE_CXX_STANDARD_LIBRARIES "" CACHE STRING "" FORCE)

# warn user about all of this
message("!! Solder dynamic linking support enabled.")
message("!! Don't forget to link libnx to the main executable!")
