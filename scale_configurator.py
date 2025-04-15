#!/usr/bin/env python

__author__     = "Sam Milstead"
__copyright__  = "Copyright 2022-2025 (C) Cisco TAC"
__credits__    = "Sam Milstead"
__version__    = "1.0.0"
__maintainer__ = "Sam Milstead"
__email__      = "smilstea@cisco.com"
__status__     = "maintenance"

import sys
import re
import ipaddress

def task():
    ###__author__     = "Sam Milstead"
    ###__copyright__  = "Copyright 2025 (C) Cisco TAC"
    ###__version__    = "1.0.0"
    ###__status__     = "maintenance"
    is_error = False
    file = ''
    for index, arg in enumerate(sys.argv):
        if arg in ['--file'] and len(sys.argv) > index + 1:
            file = str(sys.argv[index + 1])
            del sys.argv[index]
            del sys.argv[index]
            break
    for index, arg in enumerate(sys.argv):
        if arg in ['--help', '-h']:
            print("Usage: python3 {" + sys.argv[0] + "} [--config][--file <filename>]")
            return
    if len(sys.argv) > 1:
        is_error = True
    else:
        for arg in sys.argv:
            if arg.startswith('-'):
                is_error = True

    if is_error:
        print(str(sys.argv))
        print("Usage: python3 {" + sys.argv[0] + "} [--config][--file <filename>]")
        return
    if not file:
        print("Usage: python3 {" + sys.argv[0] + "} [--config][--file <filename>]")
        return
    Scale_Configurator(file)
    return

def Scale_Configurator(file):
    ###__author__     = "Sam Milstead"
    ###__copyright__  = "Copyright 2022 (C) Cisco TAC"
    ###__version__    = "1.0.0"
    ###__status__     = "maintenance"
    #generate configuration file
    """    This script is designed to generate scale configurations.
    
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
    - Scale config to webpage

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
    """
    option = int(input("How many times would you like to iterate through the configuration\n" + "Please enter an integer: "))
    if option < 1:
        print("Enter a valid number of times to run")
        return
    else:
        timestorun = option
    with open(file, "r") as myfile:
        textarea = myfile.read()
    # Call the function to do the parsing
    result = test_parse(textarea, timestorun)
    if len(result) == 0:
        parse(textarea, timestorun)
    else:
        for error in result:
            print(error)
def parse(textarea, timestorun):
    ###__author__     = "Sam Milstead"
    ###__copyright__  = "Copyright 2025 (C) Cisco TAC"
    ###__version__    = "1.0.0"
    ###__status__     = "maintenance"
    x = 0
    while (x < timestorun):
        for line in textarea.split("\n"):
            if "[[" and "]]" in line:
                line = parse_ipv4_address(line, x)
            if "[" and "]" in line:
                line = parse_numbers(line, x)
            if "{{" and "}}" in line:
                line = parse_ipv6_address(line, x)
            if "{" and "}" in line:
                line = parse_hex(line, x)
            if "(" and ")" in line:
                line = parse_letters(line, x)
            print(line)
        x += 1
    return

def parse_ipv4_address(line, x):
    ###__author__     = "Sam Milstead"
    ###__copyright__  = "Copyright 2025 (C) Cisco TAC"
    ###__version__    = "1.0.0"
    ###__status__     = "maintenance"
    """
    This is for IPv4 addresses
    """
    regex_int = re.compile(r'(\[\[((\d+\.\d+\.\d+\.\d+)((\/(\d+)?)| (\d+\.\d+\.\d+\.\d+)?)),?(\d*)?\]\])')
    matches = re.findall(regex_int, line)

    for match in matches:
        original_ip = match[2]
        subnet_or_mask = match[4] or '/30'  # Default to /30 if no mask is provided
        increment = int(match[7]) if match[7] else 1
        total_increment = x * increment

        # Create a network object
        network = ipaddress.IPv4Network(original_ip + subnet_or_mask, strict=False)
        current_ip = ipaddress.IPv4Address(original_ip)
        new_ip_int = int(current_ip)

        # Increment while respecting subnet boundaries
        while total_increment > 0:
            # Calculate the next IP
            new_ip_int += 1
            new_ip = ipaddress.IPv4Address(new_ip_int)

            # Check if the new IP is a network or broadcast address
            if new_ip == network.network_address or new_ip == network.broadcast_address:
                continue  # Skip to the next possible IP

            # Check if the new IP exceeds the broadcast address
            if new_ip > network.broadcast_address:
                # Move to the next subnet
                next_network_start = int(network.broadcast_address) + 1
                network = ipaddress.IPv4Network((next_network_start, network.prefixlen), strict=False)
                new_ip_int = int(network.network_address)
                continue

            total_increment -= 1

        # After the loop, ensure new_ip has a valid address
        new_ip = ipaddress.IPv4Address(new_ip_int)

        # Replace the original IP with the new IP in the line
        new_address_with_subnet = f"{new_ip}{subnet_or_mask}"
        original = match[0]
        line = line.replace(original, new_address_with_subnet, 1)

    return line

def parse_ipv6_address(line, x):
    ###__author__     = "Sam Milstead"
    ###__copyright__  = "Copyright 2025 (C) Cisco TAC"
    ###__version__    = "1.0.0"
    ###__status__     = "maintenance"
    """
    This is for IPv6 addresses
    """
    regex_ipv6 = re.compile(r'(\{\{(([a-f0-9:]+:+)+[a-f0-9]+)(\/\d+)(,(\d+))?\}\})')
    matches = regex_ipv6.finditer(line)

    for match in matches:
        original_ip = match.group(2)  # Full IPv6 address
        prefix_length = match.group(4)  # Prefix length, e.g., /64
        increment = int(match.group(6)) if match.group(6) else 1  # Optional increment
        total_increment = x * increment

        # Create a network object
        network = ipaddress.IPv6Network(original_ip + prefix_length, strict=False)
        current_ip = ipaddress.IPv6Address(original_ip)
        new_ip_int = int(current_ip)

        # Increment while respecting subnet boundaries
        while total_increment > 0:
            new_ip_int += 1
            new_ip = ipaddress.IPv6Address(new_ip_int)

            # Check if the new IP exceeds the broadcast address of the current subnet
            if new_ip >= network.network_address + network.num_addresses:
                # Move to the next subnet
                next_network_start = int(network.network_address) + network.num_addresses
                network = ipaddress.IPv6Network((next_network_start, network.prefixlen), strict=False)
                new_ip_int = int(network.network_address)
                continue  # Continue to the next iteration of the while loop

            total_increment -= 1

        new_ip = ipaddress.IPv6Address(new_ip_int)
        new_address_with_prefix = f"{new_ip}{prefix_length}"
        original_placeholder = match.group(0)
        line = line.replace(original_placeholder, new_address_with_prefix, 1)

    return line

def parse_numbers(line, x):
    ###__author__     = "Sam Milstead"
    ###__copyright__  = "Copyright 2025 (C) Cisco TAC"
    ###__version__    = "1.0.0"
    ###__status__     = "maintenance"
    """
    This is for incrementing base 10
    """
    increment = 1
    regex_int = re.compile(r'\[\d+-\d+,?(\d+)?\]')
    match = re.findall(regex_int, line)
    for i in match:
        match2 = re.search(r'(\[(\d+)-(\d+),?(\d+)?\])', line)
        if match2.group(4):
            increment = int(match2.group(4))
        temp = int(match2.group(2))+(x*increment)
        while temp > int(match2.group(3)):
            temp += int(match2.group(2)) - int(match2.group(3)) -1
        line = re.sub(r'(\[(\d+)-(\d+),?(\d+)?\])', str(temp), str(line), count=1)
    return line

def parse_hex(line, x):
    ###__author__     = "Sam Milstead"
    ###__copyright__  = "Copyright 2025 (C) Cisco TAC"
    ###__version__    = "1.0.0"
    ###__status__     = "maintenance"
    """
    This is for incrementing in hex
    """
    increment = 1
    regex_hex = re.compile(r'\{[0-9a-fA-F]+-[0-9a-fA-F]+,?(\d+)?\}')
    match = re.findall(regex_hex, line)
    for i in match:
        match2 = re.search(r'(\{([0-9a-fA-F]+)-([0-9a-fA-F]+),?(\d+)?\})', line)
        if match2.group(4):
            increment = int(match2.group(4))
        starthex = int(match2.group(2), 16)
        endhex = int(match2.group(3), 16)
        temp = starthex +(x*increment)
        while temp > endhex:
            temp += starthex - endhex - 1
        temp = '{:X}'.format(temp)
        line = re.sub(r'(\{([0-9a-fA-F]+)-([0-9a-fA-F]+),?(\d+)?\})', str(temp), str(line), count=1)
    return line

def parse_letters(line, x):
    ###__author__     = "Sam Milstead"
    ###__copyright__  = "Copyright 2025 (C) Cisco TAC"
    ###__version__    = "1.0.0"
    ###__status__     = "maintenance"
    """
    This is for incrementing letters, we must use the ASCII
    representation to do this
    """
    increment = 1
    regex_letter = re.compile(r'\([a-zA-Z]+-[a-zA-Z]+,?(\d+)?\)')
    match = re.findall(regex_letter, line)
    for i in match:
        match2 = re.search(r'(\(([a-zA-Z]+)-([a-zA-Z]+),?(\d+)?\))', line)
        startletter = ord(match2.group(2))
        endletter = ord(match2.group(3))
        if match2.group(4):
            increment = int(match2.group(4))
        temp = startletter +(x*increment)
        while temp > endletter:
            temp += startletter - endletter - 1
        temp = str(chr(temp))
        line = re.sub(r'(\(([a-zA-Z]+)-([a-zA-Z]+),?(\d+)?\))', str(temp), str(line), count=1)
    return line

def test_parse(textarea, timestorun):
    ###__author__     = "Sam Milstead"
    ###__copyright__  = "Copyright 2025 (C) Cisco TAC"
    ###__version__    = "1.0.0"
    ###__status__     = "maintenance"
    """
    Create the finaloutput list, parse line by line for the number of times specified
    and return final output
    """
    result = []
    for line in textarea.split("\n"):
        # Check if any manipulation needs to be done
        if "[[" and "]]" in line:
            line = test_parse_ipv4_address(line)
        if "[" and "]" in line:
            result = test_parse_numbers(line, result)
        if "{{" and "}}" in line:
            line = test_parse_ipv6_address(line)
        if "{" and "}" in line:
            result = test_parse_hex(line, result)
        if "(" and ")" in line:
            result = test_parse_letters(line, result)
    return result

def test_parse_ipv4_address(line):
    ###__author__     = "Sam Milstead"
    ###__copyright__  = "Copyright 2025 (C) Cisco TAC"
    ###__version__    = "1.0.0"
    ###__status__     = "maintenance"
    """
    This is for IPv4 addresses
    """
    regex_int = re.compile(r'(\[\[((\d+\.\d+\.\d+\.\d+)((\/(\d+)?)| (\d+\.\d+\.\d+\.\d+)?)),?(\d*)?\]\])')
    matches = re.findall(regex_int, line)

    for match in matches:
        original_ip = match[2]
        subnet_or_mask = match[4] or '/30'  # Default to /30 if no mask is provided
        increment = int(match[7]) if match[7] else 1

        # Create a network object
        network = ipaddress.IPv4Network(original_ip + subnet_or_mask, strict=False)
        current_ip = ipaddress.IPv4Address(original_ip)
        new_ip_int = int(current_ip)

        # Increment while respecting subnet boundaries
        for _ in range(increment):
            new_ip_int += 1
            new_ip = ipaddress.IPv4Address(new_ip_int)

            # Check if the new IP is a network or broadcast address
            if new_ip == network.network_address or new_ip == network.broadcast_address:
                new_ip_int += 1
                new_ip = ipaddress.IPv4Address(new_ip_int) # Increment again after skipping
                if new_ip > network.broadcast_address:
                    next_network_start = int(network.broadcast_address) + 1
                    network = ipaddress.IPv4Network((next_network_start, network.prefixlen), strict=False)
                    new_ip_int = int(network.network_address)
                    new_ip = ipaddress.IPv4Address(new_ip_int) # Set to the start of the next

            # Check if the new IP exceeds the broadcast address
            elif new_ip > network.broadcast_address:
                # Move to the next subnet
                next_network_start = int(network.broadcast_address) + 1
                network = ipaddress.IPv4Network((next_network_start, network.prefixlen), strict=False)
                new_ip_int = int(network.network_address)
                new_ip = ipaddress.IPv4Address(new_ip_int) # Set to the start of the next

        # Replace the original IP with the new IP in the line
        new_address_with_subnet = f"{new_ip}{subnet_or_mask}"
        line = line.replace(f"[[{original_ip}{subnet_or_mask}]]", new_address_with_subnet)

    return line

def test_parse_ipv6_address(line):
    ###__author__     = "Sam Milstead"
    ###__copyright__  = "Copyright 2025 (C) Cisco TAC"
    ###__version__    = "1.0.0"
    ###__status__     = "maintenance"
    """
    This is for IPv6 addresses
    """
    regex_ipv6 = re.compile(r'(\{\{(([a-f0-9:]+:+)+[a-f0-9]+)(\/\d+)(,(\d+))?\}\})')
    matches = regex_ipv6.finditer(line)

    for match in matches:
        original_ip = match[2]
        prefix_length = match[4]  # e.g., /64
        total_increment = int(match[6]) if match[6] else 1

        # Create a network object
        network = ipaddress.IPv6Network(original_ip + prefix_length, strict=False)
        current_ip = ipaddress.IPv6Address(original_ip)
        new_ip_int = int(current_ip)

        # Increment while respecting subnet boundaries
        for _ in range(total_increment):
            new_ip_int += 1
            new_ip = ipaddress.IPv6Address(new_ip_int)

            # Check if the new IP exceeds the broadcast address of the current subnet
            if new_ip >= network.network_address + network.num_addresses:
                # Move to the next subnet
                next_network_start = int(network.network_address) + network.num_addresses
                network = ipaddress.IPv6Network((next_network_start, network.prefixlen), strict=False)
                new_ip_int = int(network.network_address)
                continue  # Continue to the next iteration of the while loop

            total_increment -= 1

        new_ip = ipaddress.IPv6Address(new_ip_int)
        new_address_with_prefix = f"{new_ip}{prefix_length}"
        original_placeholder = match.group(0)
        line = line.replace(original_placeholder, new_address_with_prefix, 1)

    return line

def test_parse_numbers(line, result):
    ###__author__     = "Sam Milstead"
    ###__copyright__  = "Copyright 2025 (C) Cisco TAC"
    ###__version__    = "1.0.0"
    ###__status__     = "maintenance"
    """
    This is for incrementing base 10
    """
    regex_int = re.compile(r'\[\d+-\d+,?(\d+)?\]')
    match = re.findall(regex_int, line)
    for i in match:
        match2 = re.search(r'(\[(\d+)-(\d+),?(\d+)?\])', line)
        if int(match2.group(2)) > int(match2.group(3)):
            result.append("Error beginning number is smaller than ending number: " + str(match2.group(1)))
    return result

def test_parse_hex(line, result):
    ###__author__     = "Sam Milstead"
    ###__copyright__  = "Copyright 2025 (C) Cisco TAC"
    ###__version__    = "1.0.0"
    ###__status__     = "maintenance"
    """
    This is for incrementing in hex
    """
    regex_hex = re.compile(r'\{[0-9a-fA-F]+-[0-9a-fA-F]+,?(\d+)?\}')
    match = re.findall(regex_hex, line)
    for i in match:
        match2 = re.search(r'(\{([0-9a-fA-F]+)-([0-9a-fA-F]+),?(\d+)?\})', line)
        if int(match2.group(2), 16) > int(match2.group(3), 16):
            result.append("Error beginning hex is smaller than ending hex: " + str(match2.group(1)))
    return result

def test_parse_letters(line, result):
    ###__author__     = "Sam Milstead"
    ###__copyright__  = "Copyright 2025 (C) Cisco TAC"
    ###__version__    = "1.0.0"
    ###__status__     = "maintenance"
    """
    This is for incrementing letters, we must use the ASCII
    representation to do this
    """
    regex_letter = re.compile(r'\([a-zA-Z]+-[a-zA-Z]+,?(\d+)?\)')
    match = re.findall(regex_letter, line)
    for i in match:
        match2 = re.search(r'(\(([a-zA-Z]+)-([a-zA-Z]+),?(\d+)?\))', line)
        if ord(match2.group(2)) > ord(match2.group(3)):
            result.append("Error beginning ASICC is smaller than ending ASCII: " + str(match2.group(1)))
    return result

if __name__ == '__main__':
    task()
