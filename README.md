# Errox_MITM

A python based Man In The Middle automation script

## Warning:

Using this script is not a guantee that you will intercept packets, matter of a fact, you will likely raise network based alarms due to secrurity on networks being fairly good these days.

## What is Errox_MITM

Errox_MITM is a very basic / bare bones Man In The Middle script and proxy / packet-sniffer script. In non-geek speek, it means that the scripts when used together can re-route traffic from one destination to you, then the desination. It is very usefull for spying on people and detecting flaws in networks without having to go through all the red tape (is joke).

## How it works

To have the wanted outcome, simply be on any IPv4 enabled network (70% of them these days) and select the right arguments on the proxy first. (While not the best, the proxy can be used to examine at a high level what all is going through a network.) Then start the MITM script, this script will start and continue the MITM attack, meaning all data will be routed through you then the destination. 

  ### proxy.py

  This script works by collecting all packets being sent to it, then filtering out the requested types, displaying the captured packets, then finnaly sending it on to the destination. This script is what allows for packets to be routed through you and not instantly dropped.

  ### mitm.py

  This script works by exploiting the trust system inside of IPv4, it will use two main methods of changing the routing information to be through your device.

  Method one:

    Method one will ping the two devices as the other, changing it's IPv4 address to match the wanted one. Then continuing with the secon method, which is below. This works against Linux based devices.

  Method two:

    Method two will send an ARP reply to the device, so when the device responds to us the internal MAC addressing table will route data through our MAC address instead of the real destination's. This process will repeat for both devices and continue so that the targets do not revert to the real MAC address.


## Future:

  This script is likely to not be updated, but if one is made it would be for fixing the MITM methods from not working anymore or to support IPv6 based MITM routing attacks.
