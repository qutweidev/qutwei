solution "qutwei"
location ".."
language "C"
includedirs {
    "qucore/include",
    "../SDL2-2.0.7/i686-w64-mingw32/include/SDL2"
}
flags {"ExtraWarnings", "StaticRuntime"}
buildoptions {"-Wall", "-pedantic", "-std=c99"}
libdirs {
    "../SDL2-2.0.7/i686-w64-mingw32/lib",
}
linkoptions {"-mconsole", "-static"}
configurations {"debug",  "release"}

configuration "debug"
targetdir "../debug"
defines {"DEBUG"}
flags {"Symbols"}

configuration "release"
targetdir "../release"
defines {"RELEASE"}
flags {"OptimizeSpeed"}

project "qucore"
kind "StaticLib"
files {"qucore/src/**.c"}
