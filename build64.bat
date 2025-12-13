cmake -G "Visual Studio 17 2022" -A x64 -S . -B buildw64
cd buildw64
cmake --build . --config Release 
