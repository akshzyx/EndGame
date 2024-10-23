# GoBalance Enhanced

GoBalance is a rewrite of [onionbalance](https://onionbalance.readthedocs.io) written in Golang by n0tr1v.

The enhanced version has several customizations on top of the rewrite specifically designed for high traffic onion sites.

### Pros over Python version

- Fast multicore threaded design
- Async Communication layer with the Tor process
- Can be complied to a single binary for container use
- Can be used as a library in a go app

### Pros over forked version

- First class distinct descriptor support!
- Option to adaptively tune and adjust the timings of both fetching and pushing descriptors. Safer and no more wondering about tuning params!
- Option for tight timings on introduction rotation. Better results than introduction spam while having more front safety (removed because of correlation potential contact /u/Paris on dread if absolutely required.)
- Ability to split the descriptor push process of multiple different gobalance and Tor processes, allowing for more scalability
- Smart introduction selection based upon the now "fresh" the descriptor is and how many instances are active
- 'Strict' checks to see if configuration is optimal for best performance with easy to understand and follow messages if not

# Tuning Methodology 

The goal of any tuning is to have better results. The results we are looking for in gobalance are as follows:

- Fetch and Publish descriptors at the most ideal times to heighten availability and overall reachability of an onion service

Now the question is, what's "most ideal times" and how do we know if it's making the service more available and reachable?

Being that a configuration can have tens to hundreds of instances the most ideal times vastly changes. It's impossible to realistically set reasonable default configuration params with such variability.

This is why most of the tuning methodology deals with changing and tightening the params based on both the amount of instances but also network conditions.

There are inherent limitations on the Tor network (tor-c) when dealing with onion services:

- Introduction points have a set limit of "life". After 16384 to 32768 (random value between these) introduce2 cells the introduction point expires. They also expire due to old age between 18 and 24 hours. These values can be seen in /src/core/or/or.h of the tor source code.
- A max of 20 introduction points per descriptor
- Set HSDIR relays based upon a changing network consensus randomization value
- Single circuit, single descriptor push/fetch (meaning you need to create a new circuit every time you want to do stuff)
- Latency to build the circuits
- No quick way to check if an introduction point is still active or not
- We need to build a circuit to HSDIR to both get descriptors and push descriptors (which may or may not return the correct results)
- Soft limit of 32 general-purpose pending circuits which limit the overall scalability of an onionbalance process

It's impossible to overcome all these limitations completely. But that isn't to say we can't make improvements in the way gobalance handles the Tor network.

For example the 20 introduction point maximum can be sidestepped if different descriptors are pushed to different HSDIR. By default, the Tor process publishes the same descriptor to all assigned HSDIR (based on network consensus value). With distinct descriptors we publish distinct descriptors (good name, right?) to all assigned HSDIR. So instead of one descriptor publish process at max pushing 20 introduction points, we push at max 20 introduction points PER HSDIR. Generally there is 8 HSDIR per consensus that means 180 introduction points. A max of 180 instances individual load balancing. Technically there is enough space in the descriptor to fit 30 introduction points instead of 20. But 20 is hard coded as a limit. Why? Because someone didn't do the math. 

Anyway this has distinct descriptors built directly in to give the largest spread of introduction points on the Tor network. Up to 8 times more reachability!

There is also tuning we do when it comes to when we both fetch and push these descriptors. Traditionally there is a set value that would be hard coded for this. But that makes little sense because some people might have just one or a few hundred fronts. So gobalance, on boot, records the time it takes for the Tor process to get the descriptors of all the configured fronts. It then does some simple calculations to base the fetching and descriptor pushes in a way more optimal way. It's not perfect, but it does automatically account for the variability in the Tor network. Which is much better than what onionbalance was traditionally doing; nothing.

We also tune which descriptors are pushed to the network. Accounting for the most recently received descriptor to be first on the list. Under regular onion load this would be not optimal (being that it becomes obvious you are running gobalance), but this fork is not designed for regular load. It's designed to be used on high traffic onion service sites. The most recent valid descriptor received has the highest potential of being the most reachable under DDOS attack. Of course this isn't perfect either but has shown considerably better outcomes under high load situations with minor load balancing implications under regular load.

Distinct descriptors allow us to push different kinds of introduction points but that doesn't help if we are not able to get the introduction points fast enough. If you had 180 instances it takes time for a Tor process to grab the latest introduction points from all of them. With this fork you can use the up to 8 gobalance and tor individual processes to split the load of both getting the introduction points and pushing the descriptors. The way we do this is simple. We limit which HSDIRs the gobalance process thinks is responsible based on the placement around the ring. Being that all tor processes will have the same consensus the selection will be the same. This means there are zero overlapping processes which conflict with each other allowing for much higher availability potential. You can effectively have 32 fronts on each gobalance processes for each of the 8 HSDIR. That's 256 fronts where only 180 of them are active in a single time. Allowing for front recovery, the best overall performance, and a much higher refresh rate timings. When maxed out on the latest Ryzen processors it's possible to handle a high tens of thousands of circuits per second all together. That number goes up with the optimizations from endgame.

TLDR: There are optimizations in both the fetching, selecting, and pushing of introduction points to the Tor network allowing for better reachability for onion services of all sizes. More valuable for large ones which are getting DDOSED to death. 
# Boot Config Flags
You can see all these by running
- `./gobalance --help`


-  --ip value, -i value                       Tor control IP address (default: "127.0.0.1")
-  --port value, -p value                     Tor control port (default: 9051)
-  --torPassword value, --tor-password value  Tor control password
-  --config value, -c value                   Config file location (default: "config.yaml")
-  --quick, -q                                Quickly publish a new descriptor (for HSDIR descriptor failures/tests) (default: false)
-  --adaptive, -a                             Adaptive publishing changes the way descriptors are published to prioritize descriptor rotation on the HSDIR. A counter to introduction cell attacks (with enough scale) and a more private version of introduction spamming. (default: true)
-  --strict, -s                               Strictly adhere to adaptive algorithms and, at the start, panic if non-optimal conditions are found. (default: false) 
- --dirsplit value, --ds value               Splits the descriptor submission to the network. Allowing for multiple gobalance processes to work as a single noncompetitive unit. This allows for more flexible scaling on fronts as many Tor processes can be safely used. Valid values are ranges (like 1-2 or 3-8). Cover all ranges from 1-8 on all processes! The default is 1-8. (default: "1-8")
-  --verbosity value, --vv value              Minimum verbosity level for logging. Available in ascending order: debug, info, warning, error, critical). The default is info. (default: "info")
-  --help, -h                                 show help (default: false)
-  --version, -v                              print the version (default: false)

# Compiling

- `go get -u` - updates all dependencies
- `go mod vendor` - stores the updates in the vendor folder
- `go build -o gobalance main.go` - builds the gobalance application

# Generate Configuration

- `./gobalance g`

or simply use your python onionbalance one! Drop in replacement support (no multisite)!

# Running
After you have configured your gobalance, you will need a tor process on your localhost. There is a provided torrc file. Run it with Tor like this:

- `tor -f torrc`

After that run gobalance

- `./gobalance`

If you need to run these in the background (in the event your server connection dies or drops) you can use `nohup` or a detached terminal session.
I, /u/Paris, recommend just running it locally with geo redundancy to not need to worry about server crashes or compromises. Onion key safety is your absolute priority. When it's compromised your operation is done.

# Notes

POW is around the corner and this gobalance process does not parse the new POW descriptor variables. After POW is released to the network an update will need to come.
