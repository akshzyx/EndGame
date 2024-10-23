# ENDGAME V3

This is the third and most likely final version of EndGame. The most popular anti-ddos solution on the darknet.

EndGame is

- a front system designed to protect the core application servers on an onion service in a safe and private way.
- locally complied and locally run (no trusted or middle party).
- a combination of multiple different technologies working together in harmony (listed below).
- FREE FOR ALL TO USE!
- *arguably* magic ㄟ( ▔, ▔ )ㄏ

## Main Features

- Fully scripted and easily deploy-able (for mass scaling!) on blank Debian 11 systems.
- Full featured NGINX LUA script to filter packets and provide a captcha directly using the NGINX layer.
- Rate limiting via Tor's V3 onion service circuit ID system with secondary rate limiting based on a testcookie like system.
- Easy Configuration for both local and remote (over Tor) front systems.
- Easily configurable and change-able to meet an onion service's needs.
- I2P support out of the box (using i2pd)
- NEW hardening and compromise check processes (fail2ban, rkhunter, debsecan)
- NEW captcha processes and a captcha built in rust with zero runtime dependencies!
- Various updates and security improvements in the lua script (it now sends you back to the queue if you fail 3 captchas)
- Caching of nginx modules for faster deployment!
- LOTS of kernel tweaks for both hardening and more efficient memory allocation for Tor (not so much i2p)
- Fresh html and css that makes it very clear you are using the latest endgame!
- Includes an onionbalance process completely written in go built for high traffic sites (see it in the sourcecode folder)
- Includes a tor patch to require some minimum POW work for all introduction requests (stopping the introduction cell DDOS attacks bites)

It can also:
- Cause you to grow a bigger dick than the asshole DDOSER (true *figurally*, lies *probably*)
- Save you millions of dollars do to DDOSER's downing your site for ransom or for their extorting fees.
- Make it look like you know what the fuck you are doing.

## How it works

EndGame is a FRONT system. That is to say it filters the requests that a service will receive, blocks bad requests, and only passes good ones to the application server.

At a request level it works like this:

`USER -> Tor/i2p -> Endgame Front -> Tor(optional) -> Backend (origin) Application Server`

*Endgame should be on a separate server to your backend server.* It only proxies content from your backend to the user. You will still need to configure your backend to handle requests from the Endgame Front.

This is the same system that anti-DDOS services like Cloudflare, Indusface, and Imperva use to protect websites from attacks. The difference is this is self-hosted and fully controlled by you for your own needs and made for darknet networks.

**On Tor, GoBalance (onionbalance) is central to really scale up protection and should be used with EndGame in production environments.**

What GoBalance does is take the various Endgame Front addresses and combine the descriptors together to create a distributed DNS round-robin like system on Tor. This allows for load balancing and prevents a single front from being overloaded. With GoBalance you can scale to hundreds of EndGame fronts that users can access from a single master onion (which we call in the configuration MASTERONION). The master onion is the address that GoBalance uses to sign and publish to the Tor network.

If you want to learn more about how GoBalance works go and read the [onionbalance documentation](https://onionbalance.readthedocs.io/en/latest/index.html). GoBalance is an improved fork of it written in go. To learn more about what makes Gobalance different go into the sourcecode directory and open the GoBalance folder.

You can use Endgame without Gobalance (or onionbalance) but the protection would be limited by the single EndGame front.

## Setup Process

If you want to use Gobalance, so you can load balance the requests coming in and get the real scalable protection, follow the parts below. If you don't skip to step 3 after setup 1.

1. [Download the Latest EndGame Source from Dread](http://dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion/d/endgame). Verify the archive signature and that it matches what is signed by /u/Paris. Extract the archive to your local machine. DO NOT BLINDLY USE ENDGAME FROM A RANDOM GITHUB REPO YOU FOUND. DON'T BE STUPID.
2. Go to sourcecode/gobalance and build gobalance with [go](https://go.dev). Read the README.md about how to compile and generate the gobalance configuration. With that configuration you will be able to see your MASTERONION url. The starting before .key is your master onion address. You will use that as your MASTERONION in the EndGame.config ending it with '.onion'.
3. Open up and edit the endgame.config, you will need to change your TORAUTHPASSWORD. Change it to a random alphanumeric password of your choice. This is just used for authentication on nginx's layer to send circuit kill commands.
4. You have two options for how EndGame sends the traffic to your backend. You can have it direct it to an onion address, or you can have it locally proxy to a server on the same network.
   1. Tor Proxy: You will need to set both of the BACKENDONION variables to your main onion service you want protected. This means your origin application server needs to have tor running with its own onion service address. You put that onion address on the BACKENDONION(1/2). If you have multiple backends (highly recommended) you can put different backend addresses to have load balancing and fallover. It's easy to add in even more by customizing endgame for your needs.
   2. Local Proxy: Change LOCALPROXY to true and edit the PROXYPASSURL to the specific IP or hostname of your backend location. It will default to connect on port 80 via http but you can edit line 320 of the site.conf to change that to your specific needs.
5. Enable I2PSETUP and/or TORSETUP by setting them to true. You can also enable TORINTRODEFENSE and TORPOWDEFENSE to provide more protection against introduction attacks on the Tor network.
6. Edit KEY and SALT to a secure cookie value. PROTECT THESE VALUES. If they get leaked, an attacker could generate EndGame cookies and hurt your EndGame protection.
   1. KEY: is your encryption key used for encryption. It should be to be between 68 and 128 random alphanumeric characters.
   2. SALT: is your salt for the encryption key. It must be exactly 8 alphanumeric characters.
7. Branding is important. EndGame makes it easy to use your own branding on it. By default, it will use dread's branding, but you should change it.
   1. HEXCOLOR and HEXCOLORDARK are for the specific colors used on the pages. Set HEXCOLOR to your main site color and HEXCOLORDARK to just a slightly darker version of it.
   2. SITENAME, SITETAGLINE, SITESINCE is all information about your site. Self-explanatory.
   3. FAVICON is used as your site's favicon in base64. This limits the amount of requests a browser may do when first loading the queue page. Make sure this value is set to something. Otherwise people's connections will get cut off from the queue when their browser makes a request to the favicon.ico.
   4. SQUARELOGO is used as the icon for the queue running man and the main splash logo on the captcha page. In base64 format.
   5. NETWORKLOGO is used as a bottom network icon for on the captcha page which allows different sites a part of the same organization to be shown. In base64 format.
8. After you are done EndGame's configuration, you should archive everything except the sourcecode folder. Transfer the archive to a blank debian 12 system. As root, extract the archive and run setup.sh like './setup.sh'. At the end of the setup, it will export an onion address (and i2p if set but don't add that to gobalance) which you can provide to users or add to your gobalance configuration.
9. Go out into the world knowing your service is protected by the best and most tested anti-DDOS solution for the darknet.

### Tech Overview

EndGame uses a number of open-source projects (and libraries) to work properly.

Projects:
* [NGINX](https://NGINX.org/) - NGINX! A web server *obviously* to provide the packet handling, threading, and proxying.
* [Tor](https://www.torproject.org/) - Tor is free and open-source software for enabling anonymous communication. It's awesome and makes all this possible.
* [STEM](https://stem.torproject.org/) - A python controller for Tor.
* [NYX](https://nyx.torproject.org/) - A command-line monitor for Tor (to easily check the EndGame front's Tor process.
* [GoBalance](http://yylovpz7taca7jfrub3wltxabzzjp34fngj5lpwl6eo47ekt5cxs6mid.onion/n0tr1v/gobalance) - A distributed DNS round-robin like system on Tor to allow load-balancing and eliminate single points of failure.
* [OpenSSL](https://www.openssl.org/) - A dependency for a lot of this projects and libraries.
* [Socat](http://www.dest-unreach.org/socat/) - Socat is a command line based utility that establishes two bidirectional byte streams and transfers data between them. (used for backend tor proxying)

Hardening Projects:
* [Fail2ban](https://www.fail2ban.org/) - A set of server and client programs to limit brute force authentication attempts. (automatically configured)
* [Rkhunter](http://rkhunter.sourceforge.net/) - rkhunter is a shell script which carries out various checks on the local system to try and detect known rootkits and malware.
* [Chkrootkit](https://www.chkrootkit.org/) - chkrootkit is a tool to locally check for signs of a rootkit.

NGINX Modules:
* [NAXSI](https://github.com/nbs-system/naxsi) - A high performance web application firewall for NGINX.
* [Headers More](https://github.com/openresty/headers-more-NGINX-module) - A module for better control of headers in NGINX.
* [Echo NGINX](https://github.com/openresty/echo-nginx-module) - A NGINX module which allows shell style commands in the NGINX configuration file.
* [LUA NGINX](https://github.com/openresty/lua-nginx-module) - The power of LUA into NGINX via a module. This allows all the scripting, packet filtering, and captcha functionality EndGame does.
* [NGINX Development Kit](https://github.com/vision5/ngx_devel_kit) - Development Kit for NGINX (dependency)

Libraries:
* [LUAJIT2 NGINX](https://github.com/openresty/luajit2) - Just in time compiler for LUA.
* [LUA Resty String](https://github.com/openresty/lua-resty-string) - String functions for ngx_lua and LUAJIT2
* [LUA Resty Cookie](https://github.com/cloudflare/lua-resty-cookie) - Provides cookie manipulation
* [LUA Resty Session](https://github.com/bungle/lua-resty-session) - Provides session manipulation
* [LUA Resty AES](https://github.com/c64bob/lua-resty-aes/raw/master/lib/resty/aes_functions.lua) - AES Functions file for LUA. Used for shared session cookies.
