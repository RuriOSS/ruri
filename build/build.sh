if [ -f /etc/resolv.conf ]; then
    rm /etc/resolv.conf
fi
echo nameserver 1.1.1.1 >/etc/resolv.conf
apk update --no-cache
for i in wget make clang git libseccomp-dev libseccomp-static libcap-static libcap-dev xz-dev libintl libbsd-static libsemanage-dev libselinux-utils libselinux-static xz-libs zlib zlib-static libselinux-dev linux-headers libssl3 libbsd libbsd-dev gettext-libs gettext-static gettext-dev gettext python3 build-base openssl-misc openssl-libs-static openssl zlib-dev xz-dev openssl-dev automake libtool bison flex gettext autoconf gettext sqlite sqlite-dev pcre-dev wget texinfo docbook-xsl libxslt docbook2x musl-dev gettext gettext-asprintf gettext-dbg gettext-dev gettext-doc gettext-envsubst gettext-lang gettext-libs gettext-static
do
    if apk search -q $i >/dev/null 2>&1; then
        apk add $i || true
    fi
done

for package in upx lld; do
    if apk search -q $package >/dev/null 2>&1; then
        apk add $package || true
    fi
done

mkdir output output2 output3

git clone --depth 1 https://github.com/moe-hacker/ruri.git
cd ruri
cc build.c -o build-ruri
./build-ruri -s -f

cp ruri ../output/ruri
cp LICENSE ../output/LICENSE

cp ruri ../output2/ruri
cp LICENSE ../output2/LICENSE

./build-ruri -s -c -f
cp ruri ../output3/ruri
cp LICENSE ../output3/LICENSE

if command -v upx >/dev/null 2>&1; then
    cd ..
    upx --best output2/ruri
    upx --best output3/ruri
fi
# WTF? shell is not like rust!
exit $?