#!/bin/bash
apt-get update
apt-get upgrade
apt-get install git

#update release branch to latest stable!
git clone https://gitlab.torproject.org/tpo/core/tor.git --branch release-0.4.8

DEBIAN_FRONTEND=noninteractive apt-get install -y -q apt-utils automake build-essential ca-certificates file libevent-dev liblzma-dev libscrypt-dev libseccomp-dev libssl-dev pkg-config python3 zlib1g-dev libzstd-dev

cp minwork.patch tor
cd tor || { echo "Error: No tor git folder. Check if you have the right branch!"; exit 1; }

#patch with POW
git apply minwork.patch > /dev/null 2>&1 || { echo "Error: Failed to patch the Tor source code."; exit 1; }

#Updating the min introduction value from 16384 to 163840.
sed -i 's/16384/163840/g' src/core/or/or.h || { echo "Error: Failed to update min introduction value."; exit 1; }

./autogen.sh
./configure --enable-fatal-warnings --disable-asciidoc --enable-gpl --enable-zstd --enable-lzma --disable-module-relay --disable-module-dirauth --disable-html-manual --prefix="/usr/" --sysconfdir="/etc/"
make -j4 -k all || { echo "Error: Failed to compile Tor."; exit 1; }

cd ..
mv tor/src/app/tor tor-patched-binary
cp tor-patched-binary /usr/sbin/tor

# echo -n "Finished Binary Patch!"
# echo -n "----------"
# echo -n "Do you want to install the patched tor binary? [y/n] "
# read answer || { echo "Error: User input not provided."; exit 1; }
#
# if [[ "$answer" =~ ^[Yy]$ ]]; then
#     mv tor-patched-binary /usr/sbin/tor
# else
#     echo "Patched tor binary saved as tor-patched-binary."
# fi



