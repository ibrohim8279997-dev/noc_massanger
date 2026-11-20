# As per https://gitlab.kitware.com/cmake/community/-/wikis/FAQ#can-i-do-make-uninstall-with-cmake

if(NOT EXISTS "/home/user/noc_massanger/client-android/app/.cxx/RelWithDebInfo/6j132p96/arm64-v8a/install_manifest.txt")
  message(FATAL_ERROR "Cannot find install manifest: /home/user/noc_massanger/client-android/app/.cxx/RelWithDebInfo/6j132p96/arm64-v8a/install_manifest.txt")
endif()

file(READ "/home/user/noc_massanger/client-android/app/.cxx/RelWithDebInfo/6j132p96/arm64-v8a/install_manifest.txt" files)
string(REGEX REPLACE "\n" ";" files "${files}")
foreach(file ${files})
  message(STATUS "Uninstalling $ENV{DESTDIR}${file}")
  if(IS_SYMLINK "$ENV{DESTDIR}${file}" OR EXISTS "$ENV{DESTDIR}${file}")
    exec_program(
      "/opt/android-sdk/cmake/3.22.1/bin/cmake" ARGS "-E remove \"$ENV{DESTDIR}${file}\""
      OUTPUT_VARIABLE rm_out
      RETURN_VALUE rm_retval
      )
    if(NOT "${rm_retval}" STREQUAL 0)
      message(FATAL_ERROR "Problem when removing $ENV{DESTDIR}${file}")
    endif()
  else(IS_SYMLINK "$ENV{DESTDIR}${file}" OR EXISTS "$ENV{DESTDIR}${file}")
    message(STATUS "File $ENV{DESTDIR}${file} does not exist.")
  endif()
endforeach()

