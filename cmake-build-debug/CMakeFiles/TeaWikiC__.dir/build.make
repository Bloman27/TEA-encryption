# CMAKE generated file: DO NOT EDIT!
# Generated by "MinGW Makefiles" Generator, CMake Version 3.8

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

SHELL = cmd.exe

# The CMake executable.
CMAKE_COMMAND = "E:\Studia\tools\CLion 2017.2.1\bin\cmake\bin\cmake.exe"

# The command to remove a file.
RM = "E:\Studia\tools\CLion 2017.2.1\bin\cmake\bin\cmake.exe" -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = C:\Users\Kacper\CLionProjects\TeaWikiC++

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = C:\Users\Kacper\CLionProjects\TeaWikiC++\cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/TeaWikiC__.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/TeaWikiC__.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/TeaWikiC__.dir/flags.make

CMakeFiles/TeaWikiC__.dir/main.cpp.obj: CMakeFiles/TeaWikiC__.dir/flags.make
CMakeFiles/TeaWikiC__.dir/main.cpp.obj: ../main.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=C:\Users\Kacper\CLionProjects\TeaWikiC++\cmake-build-debug\CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/TeaWikiC__.dir/main.cpp.obj"
	C:\PROGRA~2\MINGW-~1\I686-7~1.0-P\mingw32\bin\G__~1.EXE  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles\TeaWikiC__.dir\main.cpp.obj -c C:\Users\Kacper\CLionProjects\TeaWikiC++\main.cpp

CMakeFiles/TeaWikiC__.dir/main.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/TeaWikiC__.dir/main.cpp.i"
	C:\PROGRA~2\MINGW-~1\I686-7~1.0-P\mingw32\bin\G__~1.EXE $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E C:\Users\Kacper\CLionProjects\TeaWikiC++\main.cpp > CMakeFiles\TeaWikiC__.dir\main.cpp.i

CMakeFiles/TeaWikiC__.dir/main.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/TeaWikiC__.dir/main.cpp.s"
	C:\PROGRA~2\MINGW-~1\I686-7~1.0-P\mingw32\bin\G__~1.EXE $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S C:\Users\Kacper\CLionProjects\TeaWikiC++\main.cpp -o CMakeFiles\TeaWikiC__.dir\main.cpp.s

CMakeFiles/TeaWikiC__.dir/main.cpp.obj.requires:

.PHONY : CMakeFiles/TeaWikiC__.dir/main.cpp.obj.requires

CMakeFiles/TeaWikiC__.dir/main.cpp.obj.provides: CMakeFiles/TeaWikiC__.dir/main.cpp.obj.requires
	$(MAKE) -f CMakeFiles\TeaWikiC__.dir\build.make CMakeFiles/TeaWikiC__.dir/main.cpp.obj.provides.build
.PHONY : CMakeFiles/TeaWikiC__.dir/main.cpp.obj.provides

CMakeFiles/TeaWikiC__.dir/main.cpp.obj.provides.build: CMakeFiles/TeaWikiC__.dir/main.cpp.obj


# Object files for target TeaWikiC__
TeaWikiC___OBJECTS = \
"CMakeFiles/TeaWikiC__.dir/main.cpp.obj"

# External object files for target TeaWikiC__
TeaWikiC___EXTERNAL_OBJECTS =

TeaWikiC__.exe: CMakeFiles/TeaWikiC__.dir/main.cpp.obj
TeaWikiC__.exe: CMakeFiles/TeaWikiC__.dir/build.make
TeaWikiC__.exe: CMakeFiles/TeaWikiC__.dir/linklibs.rsp
TeaWikiC__.exe: CMakeFiles/TeaWikiC__.dir/objects1.rsp
TeaWikiC__.exe: CMakeFiles/TeaWikiC__.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=C:\Users\Kacper\CLionProjects\TeaWikiC++\cmake-build-debug\CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable TeaWikiC__.exe"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles\TeaWikiC__.dir\link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/TeaWikiC__.dir/build: TeaWikiC__.exe

.PHONY : CMakeFiles/TeaWikiC__.dir/build

CMakeFiles/TeaWikiC__.dir/requires: CMakeFiles/TeaWikiC__.dir/main.cpp.obj.requires

.PHONY : CMakeFiles/TeaWikiC__.dir/requires

CMakeFiles/TeaWikiC__.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles\TeaWikiC__.dir\cmake_clean.cmake
.PHONY : CMakeFiles/TeaWikiC__.dir/clean

CMakeFiles/TeaWikiC__.dir/depend:
	$(CMAKE_COMMAND) -E cmake_depends "MinGW Makefiles" C:\Users\Kacper\CLionProjects\TeaWikiC++ C:\Users\Kacper\CLionProjects\TeaWikiC++ C:\Users\Kacper\CLionProjects\TeaWikiC++\cmake-build-debug C:\Users\Kacper\CLionProjects\TeaWikiC++\cmake-build-debug C:\Users\Kacper\CLionProjects\TeaWikiC++\cmake-build-debug\CMakeFiles\TeaWikiC__.dir\DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/TeaWikiC__.dir/depend

