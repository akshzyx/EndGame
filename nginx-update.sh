#!/bin/bash
apt-get update
apt-get -y upgrade

nginx -V
command="nginx -v"
nginxv=$( ${command} 2>&1 )
NGINXVERSION=$(echo $nginxv | grep -o '[0-9.]*$')

modulecache=$NGINXVERSION-modules.tar.gz
if test -f $modulecache; then
    rm -R /etc/nginx/modules
    mkdir /etc/nginx/modules
    tar zxvf $modulecache
    mv modules /etc/nginx/modules/
    nginx -t
    exit 0
else
    rm -R *-modules.tar.gz

fi

wget https://nginx.org/download/nginx-$NGINXVERSION.tar.gz
tar -xzvf nginx-$NGINXVERSION.tar.gz

cp -R dependencies/* nginx-$NGINXVERSION/

cd nginx-$NGINXVERSION

export LUAJIT_LIB=/usr/local/lib
export LD_LIBRARY_PATH=/usr/local/lib
export LUAJIT_INC=/usr/local/include/luajit-2.1
./configure \
--with-ld-opt="-Wl,-rpath,/usr/local/libm,-lpcre" \
--with-compat \
--add-dynamic-module=naxsi/naxsi_src \
--add-dynamic-module=headers-more-nginx-module \
--add-dynamic-module=echo-nginx-module \
--add-dynamic-module=ngx_devel_kit \
--add-dynamic-module=lua-nginx-module

make -j8 modules

cp -r objs modules
rm -R /etc/nginx/modules
mkdir /etc/nginx/modules
tar -zcvf $modulecache modules
mv modules /etc/nginx/modules

cd ..
mv nginx-$NGINXVERSION/$modulecache $modulecache
rm -R nginx-*.tar.gz
rm -R nginx-$NGINXVERSION

nginx -t
exit 0
