# Tor Source Code Adjustment

Due to the nature of introduction attacks, different adjustments can be made to the tor source layer which will counter onion downtime. By using these patches, tor will more effectively handle introduction traffic and introduction point rotation.

It's important to note the two issues that tor's onion service circuit protocol has that introduction cell DDOSERs exploit and how these patches counter them.

When your tor process launches an onion service, it will, by default, connect to three
'introduction' points. These points are long-lasting circuits to specific relays. The tor process then creates a descriptor of these introduction points and signs it with your onion service key, publishing it to certain HSDIRs on the tor network. When a user goes to connect to your onion service, they will first pull the descriptor of these introduction points from a HSDIR and then make an 'introduction cell' request to one of them. The introduction point will then relay this request to the onion service's tor process. Included within this introduction cell is where the user wants to meet the onion service. This meeting point is called the rendezvous point. The onion service needs to build out a circuit to this rendezvous point to start the connection with the user.

While this design has strong protection for privacy, there are a few issues. Mainly, there is no way to know if the introduction cell is from a user or an attacker. The onion service NEEDS to build the circuit to the rendezvous point to find out. And that process is both computationally expensive and hard on the tor network to do a lot. While just sending an introduction cell is cheap,.

The Tor Project fixes this with Proof of Work (POW). POW is basically a computationally expensive puzzle a user's computer would need to solve for them to send an introduction cell. This switches back the computation required by the onion service to the attacker. But there is an oversight in its design. An attacker can still send an introduction cell with no POW, and it can still be accepted. For compatibility sake, this makes sense. Only require POW when it is needed, and still accept cells from clients who don't have POW yet. But when you are attacked, you want your tor process not to accept these trash zero-work introduction cells.

Thus the minwork.patch. It creates a new option that sets a minimum required effort for an introduction cell to be accepted in the Tor process. A user can still send a zero-work introduction cell, but the tor process will not build the circuit to the rendezvous point. This immediately kills the introduction attack in its tracks.

Being that it sets a requirement for POW, this means users will need to have POW. It also means that gobalance **will not work** with it. As POW requires a specific "seed" per front for the POW puzzle, you can't combine multiple introduction points from different fronts to provide the load balancing. This is a limitation that can't be overcome without all fronts communicating a shared seed. With no way to set this seed from the tor control port, it's a standstill until that work is done or a patch is developed for it.


### Introduction points being "expired" (spent)

While the POW patch does protect against building trash circuits to the rendezvous point, it doesn't counter your introduction points being expired.

It might come as a surprise to you that introduction points have a lifetime both in time and in requests. It makes sense, as you don't really want a compromised introduction point to just send a massive amount of introduction cells to overload your front or keep a circuit alive forever.

You can find the specific limits outlined in tor's C source at /src/core/or/or.h lines starting at 959. There is a single value that you need to care about. Specifically INTRO_POINT_MIN_LIFETIME_INTRODUCTIONS.

When an introduction cell attack happens, they spam introduction points. This causes the minimal value of 16384 (maximum of 32768) to get "spent." Causing the introduction point circuit to expire and be closed. This is extra problematic for onion services, being that it publishes these introduction points to a HSDIR the user will need to request from. The tor process also caches this information, and after the whole descriptor is expired, it can take a few minutes for the tor process to grab a new one.

Keeping your introduction points alive for longer counters the 'onion site not found' error. The solution is to increase the number of circuits an introduction point can pass before becoming expired. When compiling your updated tor, take time to edit the or.h INTRO_POINT_MIN_LIFETIME_INTRODUCTIONS value to a more fitting number. Generally, add a zero or two there. It hurts the front's privacy, but not as bad as building a lot of introduction circuits does. Specifically to introduction points that it then publishes for the world to see.


### Script to make it easy.

Included is an automated script you will need to run as root on a Debian 12 system to compile an ideal tor process. You only need to do this once, and then replace the tor process on the endgame fronts with the patched tor process.

Just put the tor-patch directory into a Debian 12 system and run the tor-build.sh with sudo. It will pull the tor binary to the working directory after it's all done. Transfer that binary over to your other endgame fronts (assuming they are also Debian 12). Put it in /usr/sbin/tor like

`mv tor-patched-binary /usr/sbin/tor`

### Questions? Ask /u/paris.
