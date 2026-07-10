# Dependency:
libcap, libseccomp, libpthread.      
# Build using build.c (experimental):
We are very happy to introduce a new build system for ruri: build.c        
It's a pure C program that does not depend on any external build system.       
IT IS A BIG STEP BACKWARDS THE HISTORY OF COMPUTER SCIENCE!!!         
That's great :)         
To use it, just `cc build.c` and `./a.out`.       
For help, see `./a.out -h`.          
Btw, I prefer to use it to build ruri, because it is faster and the cmdline is simpler.    
# Build using autoconf (recommended):
```
git clone https://github.com/rurioss/ruri
cd ruri
autoreconf -fi
./configure --enable-static
make
make install
```
## NOTE:
The test script has a part that must be run with `sudo`, `DO NOT` run `make test` on your devices!!!!      
## Build options:
```
  --enable-coreonly       Compile core only
  --disable-libcap        Disable libcap support
  --disable-libseccomp    Disable libseccomp support
  --disable-rurienv       Disable .rurienv support
  --enable-static         Enable static build
  --enable-static-pie     Enable static-pie build
  --enable-debug          Enable debug log
  --enable-dev            Enable dev build
```
Note: `--enable-coreonly` will auto enable `--disable-libseccomp --disable-libcap --disable-rurienv`      
# Build using CMake (for downstream)
(if you'd prefer to use CMake)      
```
git clone https://github.com/rurioss/ruri
cd ruri
cmake .
make
make install
```
## Build options in CMake:
```
  -DSTRIP_DEBUGINFO=ON       Debug symbols are stripped by default
  -DDISABLE_LIBCAP=ON        Disable libcap support
  -DDISABLE_LIBSECCOMP=ON    Disable libseccomp support
  -DDISABLE_RURIENV=ON       Disable .rurienv support
  -DENABLE_STATIC=ON         Enable static build
  -DCMAKE_BUILD_TYPE=Debug   Enable debug log
```
Note:
-  -DENABLE_DEBUG=ON is equivalent to the traditional build options --enable-dev plus --enable-debug
- When DISABLE_RURIENV and DISABLE_LIBSECCOMP and DISABLE_LIBCAP are enabled at the same time, it is equivalent to --enable-coreonly in the traditional build process

## Other target in CMake while configuration complete:
```
  format      Run clang-format steps
  strip       Run strip steps
  tidy        Run clang-tidy steps
```
