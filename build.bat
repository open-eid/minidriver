echo Environment setup
@call "C:\Program Files\Microsoft Visual Studio 9.0\Common7\Tools\vsvars32.bat"

echo Creating makefile for NMake with cmake
cmake -G "NMake Makefiles" -DCMAKE_VERBOSE_MAKEFILE=1 -DCMAKE_BUILD_TYPE=Release

echo Building MiniDriver, 32bit
nmake

pause
