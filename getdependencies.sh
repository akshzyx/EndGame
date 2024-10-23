#!/bin/bash

shopt -s nullglob dotglob
directory=(dependencies/*)
if [ ${#directory[@]} -gt 0 ]; then
read -p "Found Dependency Directory. Did you want to wipe? (y/n) " -n 1 -r
if [[ $REPLY =~ ^[Yy]$ ]]
then
     rm -R dependencies
     printf '\nStarting Resync'
else
     printf "\nCancelled Sync"
     exit 0
fi
fi

apt-get update
apt-get -y install git

mkdir dependencies
cd dependencies

git clone https://github.com/nbs-system/naxsi.git
git clone https://github.com/openresty/headers-more-nginx-module.git
git clone https://github.com/openresty/echo-nginx-module.git

#some required stuff for lua/luajit. Versions should be checked and updated with every install/update or nginx won't boot!
git clone https://github.com/openresty/lua-nginx-module

git clone https://github.com/openresty/luajit2
cd luajit2
git checkout v2.1-agentzh
cd ..

git clone https://github.com/vision5/ngx_devel_kit

git clone https://github.com/openresty/lua-resty-string

git clone https://github.com/cloudflare/lua-resty-cookie

git clone https://github.com/bungle/lua-resty-session

clear
echo "Dependencies have been got!"
exit 0
