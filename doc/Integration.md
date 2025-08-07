## Using ruri as container implementation:
Here is a simple example, to build file command in an alpine container with ruri:
```bash
# Download and unpack rootfs
bash -c ". <(curl -sL https://get.ruri.zip/rurima) -s"
./rurima lxc pull -o alpine -v edge -s ./alpine
# Get ruri
bash -c ". <(curl -sL https://get.ruri.zip/ruri) -s"
# Copy build script
sudo cp build.sh alpine/build.sh
sudo chmod +x alpine/build.sh
# Run container
sudo ./ruri ./alpine /bin/sh /build.sh
```

build.sh:      
```sh
# Fix DNS problem
rm /etc/resolv.conf
echo nameserver 1.1.1.1 > /etc/resolv.conf
# Add testing source
echo https://dl-cdn.alpinelinux.org/alpine/edge/testing >> /etc/apk/repositories
apk add wget make clang git xz-dev libintl libbsd-static libsemanage-dev libselinux-utils libselinux-static xz-libs zlib zlib-static libselinux-dev linux-headers libssl3 libbsd libbsd-dev gettext-libs gettext-static gettext-dev gettext python3 build-base openssl-misc openssl-libs-static openssl zlib-dev xz-dev openssl-dev automake libtool bison flex gettext autoconf gettext sqlite sqlite-dev pcre-dev wget texinfo docbook-xsl libxslt docbook2x musl-dev gettext gettext-asprintf gettext-dbg gettext-dev gettext-doc gettext-envsubst gettext-lang gettext-libs gettext-static
apk add upx
mkdir output

# build file
git clone https://github.com/file/file
cd file
autoreconf -vif
./configure LDFLAGS="-static -Wl,--gc-sections -ffunction-sections -fdata-sections" --disable-nss --enable-static --disable-shared --disable-liblastlog2
make -j8 LDFLAGS="-all-static -Wl,--gc-sections -ffunction-sections -fdata-sections"
strip src/file
cp src/file ../output/file-static
cp magic/magic.mgc ../output/
cc -static -o file ../file.c
strip file
upx file
cp file ../output/file
cp COPYING ../output/LICENSE-file
cd ..
cd output
tar -cvf ../$(uname -m).tar .
exit 0
```
## Using ruri config file:
If you have a container in `/test`,      
Use `ruri -D -o test.conf /test` to dump the config into test.conf      
You can also add other options like `ruri -D -o test.conf -d cap_chmod -k cap_sys_admin -w -u /test /bin/sh`      
So next time, just use `ruri -c /path/to/test.conf` to run the container.      
## integrate with source:
main() has been replaced to ruri, and every funcion in ruri have ruri_ or nekofeng_ prefix now, so you need not worry about conflicts of symbols now.      
If your project supports, you can remove `main()` function and use ruri as a lib. But make sure that you know how ruri.c works, especially how RURI_CONTAINER struct works.       
An example is [rurima](https://github.com/Moe-hacker/rurima), I made ruri to be its subcommand. So `rurima r` have the same effect with `ruri`.            
NOTE: ruri will re-exec itself from memfd to clear environment variables and avoid security issues. So you need to call ruri_clear_env() in your program with your argv so that the re-exec can work properly.