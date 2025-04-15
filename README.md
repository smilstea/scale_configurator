# scale_configurator
Create configurations incrementing numbers, hex, ip addresses, etc with ease

Usage: python3 {scale_configurator.py} [--config][--file <filename>]
<prompted for number of runs>

packages:

import sys
import re
import ipaddress


    
    1. For numbers
    Ranges such as [10-50] will automatically increment by 1.
    For a different multiplier use a ',' such as [10-50,5].
    
    2. For hex
    Ranges such as {0-a} or {0-A} will automatically increment by 1.
    For a different multiplier use a ',' such as {0-A,5}.
    Case insensitive
    
    3. For letters
    Ranges such as (a-g) or (A-G) will automatically increment by 1.
    For a different multiplier use a ',' such as (a-g,5).
    Case sensitive
    
    4. For IPv4 Addresses (note the subnet is not calculated,
    you must calculate the right host addresses).
    Ranges such as [[192.168.0.1 255.255.255.0]] or
    [[192.168.0.1/24]] will automatically increment by 1.
    For a different multiplier use a ',' such as [[192.168.0.1 255.255.255.0,3]]
    
    6. For IPv6 addresses (note the subnet is not calculated,
    you must calculate the right host addresses).
    Ranges such as {{2001::1/64}} will automatically increment by 1 in hex.
    For a different multiplier use a ',' such as {{2001::1/64,7}}
    
    Returns:
    - Scale config

    ###Example###
    Example Times to Run: 5

    Example File:
    interface GigabitEthernet0/0/0/13.[1-200] l2transport
     vrf vrf(a-e,3)
     description IPv4 {0-f,6}
     encapsulation dot1Q [1-200] second-dot1q [30-35,3] exact
     ipv4 address [[192.168.0.1/30,4]]
     ipv4 secondary-address [[10.0.0.1 255.255.255.0]]
     ipv6 address {{2001::1/124,7}}
     no shut
    !

    Example Output:
    interface GigabitEthernet0/0/0/13.1 l2transport
     vrf vrfa
     description IPv4 0
     encapsulation dot1Q 1 second-dot1q 30 exact
     ipv4 address 192.168.0.1/30
     ipv4 secondary-address 10.0.0.1/30
     ipv6 address 2001::1/124
     no shut
    !

    interface GigabitEthernet0/0/0/13.2 l2transport
     vrf vrfd
     description IPv4 6
     encapsulation dot1Q 2 second-dot1q 33 exact
     ipv4 address 192.168.0.9/30
     ipv4 secondary-address 10.0.0.2/30
     ipv6 address 2001::8/124
     no shut
    !

    interface GigabitEthernet0/0/0/13.3 l2transport
     vrf vrfb
     description IPv4 C
     encapsulation dot1Q 3 second-dot1q 30 exact
     ipv4 address 192.168.0.17/30
     ipv4 secondary-address 10.0.0.5/30
     ipv6 address 2001::f/124
     no shut
    !

    interface GigabitEthernet0/0/0/13.4 l2transport
     vrf vrfe
     description IPv4 2
     encapsulation dot1Q 4 second-dot1q 33 exact
     ipv4 address 192.168.0.25/30
     ipv4 secondary-address 10.0.0.6/30
     ipv6 address 2001::17/124
     no shut
    !

    interface GigabitEthernet0/0/0/13.5 l2transport
     vrf vrfc
     description IPv4 8
     encapsulation dot1Q 5 second-dot1q 30 exact
     ipv4 address 192.168.0.33/30
     ipv4 secondary-address 10.0.0.9/30
     ipv6 address 2001::1e/124
     no shut
    !
