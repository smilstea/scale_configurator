#!/usr/bin/env python

__author__     = "Sam Milstead"
__copyright__  = "Copyright 2022-2025 (C) Cisco TAC"
__credits__    = "Sam Milstead"
__version__    = "1.0.1"
__maintainer__ = "Sam Milstead"
__email__      = "smilstea@cisco.com"
__status__     = "maintenance"

import re
import ipaddress
import sys

# Define the regex with named groups
IPV4_REGEX = re.compile(
    r'\[\['
    r'(?P<ip_address>\d+\.\d+\.\d+\.\d+)'  # Named Group: ip_address (e.g., 192.168.0.1)
    r'(?:'                                 # Non-capturing group for subnet/mask options
        r'(?P<slash_prefix>\/\d+)'         # Named Group: slash_prefix (e.g., /24)
        r'|'
        r'\s*(?P<dotted_mask>\d+\.\d+\.\d+\.\d+)' # Named Group: dotted_mask (e.g., 255.255.255.0), with optional space
    r')?'                                  # Make the entire subnet/mask part optional
    r',?'                                  # Optional comma
    r'(?P<increment>\d*)?'                 # Named Group: increment (e.g., 3)
    r'\]\]'
)

IPV6_REGEX = re.compile(
    r'\{\{'
    r'(?P<ip_address>([a-f0-9:]+:+)+[a-f0-9]+)' # Named Group: ip_address
    r'(?P<prefix_length>\/\d+)'                 # Named Group: prefix_length (e.g., /64)
    r',?'
    r'(?P<increment>\d*)?'                      # Named Group: increment
    r'\}\}'
)

def task():
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
    """1. For numbers
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
     ipv4 secondary-address 10.0.0.1/24
     ipv6 address 2001::1/124
     no shut
    !
interface GigabitEthernet0/0/0/13.2 l2transport
     vrf vrfd
     description IPv4 6
     encapsulation dot1Q 2 second-dot1q 33 exact
     ipv4 address 192.168.0.9/30
     ipv4 secondary-address 10.0.0.2/24
     ipv6 address 2001::8/124
     no shut
    !
interface GigabitEthernet0/0/0/13.3 l2transport
     vrf vrfb
     description IPv4 C
     encapsulation dot1Q 3 second-dot1q 30 exact
     ipv4 address 192.168.0.17/30
     ipv4 secondary-address 10.0.0.3/24
     ipv6 address 2001::f/124
     no shut
    !
interface GigabitEthernet0/0/0/13.4 l2transport
     vrf vrfe
     description IPv4 2
     encapsulation dot1Q 4 second-dot1q 33 exact
     ipv4 address 192.168.0.25/30
     ipv4 secondary-address 10.0.0.4/24
     ipv6 address 2001::16/124
     no shut
    !
interface GigabitEthernet0/0/0/13.5 l2transport
     vrf vrfc
     description IPv4 8
     encapsulation dot1Q 5 second-dot1q 30 exact
     ipv4 address 192.168.0.33/30
     ipv4 secondary-address 10.0.0.5/24
     ipv6 address 2001::1d/124
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
    x = 0
    while (x < timestorun):
        for line_original in textarea.split("\n"):
            line = line_original

            # Use the compiled regex objects for re.sub
            line = IPV4_REGEX.sub(lambda m, current_x=x: _replace_ipv4_match(m, current_x), line)
            line = re.sub(r'\[(\d+)-(\d+),?(\d+)?\]', lambda m, current_x=x: _replace_numbers_match(m, current_x), line)
            line = IPV6_REGEX.sub(lambda m, current_x=x: _replace_ipv6_match(m, current_x), line)
            line = re.sub(r'\{([0-9a-fA-F]+)-([0-9a-fA-F]+),?(\d+)?\}', lambda m, current_x=x: _replace_hex_match(m, current_x), line)
            line = re.sub(r'\(([a-zA-Z]+)-([a-zA-Z]+),?(\d+)?\)', lambda m, current_x=x: _replace_letters_match(m, current_x), line)
            print(line)
        x += 1
    return

def _get_next_usable_ipv4_address(current_ip_obj, current_network_obj):
    """
    Finds the next usable IPv4 address, skipping network and broadcast addresses
    for prefixes < 31. For /31 and /32, all addresses are considered usable.
    Moves to the next subnet if the current one is exhausted.
    Returns the next usable IP address object and its new network object.
    """
    # Special handling for /31 and /32 prefixes
    # For these, all addresses are considered "usable" host addresses.
    if current_network_obj.prefixlen in (31, 32):
        next_candidate_int = int(current_ip_obj) + 1

        # If incrementing goes beyond the current /31 or /32 network's broadcast address,
        # move to the start of the next network of the same prefix length.
        if next_candidate_int > int(current_network_obj.broadcast_address):
            next_network_start_int = int(current_network_obj.broadcast_address) + 1
            current_network_obj = ipaddress.IPv4Network(
                (next_network_start_int, current_network_obj.prefixlen), strict=False
            )
            # The first address in the new /31 or /32 network is its network_address
            next_ip = current_network_obj.network_address
        else:
            next_ip = ipaddress.IPv4Address(next_candidate_int)

        return next_ip, current_network_obj

    # Original logic for prefixes < 31 (i.e., networks with dedicated host addresses)
    next_candidate_int = int(current_ip_obj) + 1

    while True:
        next_ip = ipaddress.IPv4Address(next_candidate_int)

        # Check if we've gone past the broadcast address of the current network
        if next_ip > current_network_obj.broadcast_address:
            # Move to the start of the next network
            next_network_start_int = int(current_network_obj.broadcast_address) + 1
            current_network_obj = ipaddress.IPv4Network(
                (next_network_start_int, current_network_obj.prefixlen), strict=False
            )
            # The first usable host in the new network is network_address + 1
            next_candidate_int = int(current_network_obj.network_address) + 1
            continue # Re-evaluate this new candidate IP

        # Check if the current candidate is a network or broadcast address
        if next_ip == current_network_obj.network_address or \
           next_ip == current_network_obj.broadcast_address:
            next_candidate_int += 1 # Skip this address and try the next one
            continue

        # If we reached here, next_ip is a usable host address
        return next_ip, current_network_obj

def _get_next_ipv6_address(current_ip_obj, current_network_obj):
    """
    Finds the next IPv6 address. Moves to the next subnet if the current one is exhausted.
    Returns the next IP address object and its new network object.
    """
    next_candidate_int = int(current_ip_obj) + 1

    while True:
        next_ip = ipaddress.IPv6Address(next_candidate_int)

        # Check if we've gone past the end of the current network
        if next_ip >= current_network_obj.network_address + current_network_obj.num_addresses:
            # Move to the start of the next network
            next_network_start_int = int(current_network_obj.network_address) + current_network_obj.num_addresses
            current_network_obj = ipaddress.IPv6Network(
                (next_network_start_int, current_network_obj.prefixlen), strict=False
            )
            # The first address in the new network is its network_address
            next_candidate_int = int(current_network_obj.network_address)
            continue # Re-evaluate this new candidate IP

        # If we reached here, next_ip is a valid address within the current or new network
        return next_ip, current_network_obj

def _replace_ipv4_match(match, x):
    original_ip = match.group('ip_address')
    slash_prefix = match.group('slash_prefix')       # e.g., "/24"
    dotted_mask = match.group('dotted_mask')         # e.g., "255.255.255.0"
    increment_str = match.group('increment')

    # Determine the prefix length as an integer
    prefix_len_int = None
    if slash_prefix:
        prefix_len_int = int(slash_prefix[1:]) # Convert "/24" to 24
    elif dotted_mask:
        # Create a dummy network to get the prefix length from the dotted mask
        prefix_len_int = ipaddress.IPv4Network(f"0.0.0.0/{dotted_mask}").prefixlen
    else:
        # Default to /30 if neither was provided
        prefix_len_int = 30

    increment = int(increment_str) if increment_str else 1
    total_increment_steps = x * increment

    current_ip_obj = ipaddress.IPv4Address(original_ip)
    # Use the integer prefix length for network object creation
    network_obj = ipaddress.IPv4Network((original_ip, prefix_len_int), strict=False)

    for _ in range(total_increment_steps):
        current_ip_obj, network_obj = _get_next_usable_ipv4_address(current_ip_obj, network_obj)

    # For the return value, always format as IP/prefixlen
    return f"{current_ip_obj}/{prefix_len_int}"

def _replace_ipv6_match(match, x):
    original_ip = match.group('ip_address')
    prefix_length = match.group('prefix_length')
    increment_str = match.group('increment')

    increment = int(increment_str) if increment_str else 1
    total_increment_steps = x * increment

    current_ip_obj = ipaddress.IPv6Address(original_ip)
    network_obj = ipaddress.IPv6Network(f"{original_ip}{prefix_length}", strict=False)

    for _ in range(total_increment_steps):
        current_ip_obj, network_obj = _get_next_ipv6_address(current_ip_obj, network_obj)

    return f"{current_ip_obj}{prefix_length}"

def _replace_numbers_match(match, x):
    start_num = int(match.group(1)) # Adjusted group index for generic regex
    end_num = int(match.group(2))   # Adjusted group index for generic regex
    increment = int(match.group(3)) if match.group(3) else 1 # Adjusted group index for generic regex
    
    temp = start_num + (x * increment)
    range_size = end_num - start_num + 1
    temp = start_num + ((temp - start_num) % range_size)
    
    return str(temp)

def _replace_hex_match(match, x):
    start_hex = int(match.group(1), 16) # Adjusted group index for generic regex
    end_hex = int(match.group(2), 16)   # Adjusted group index for generic regex
    increment = int(match.group(3)) if match.group(3) else 1 # Adjusted group index for generic regex
    
    temp = start_hex + (x * increment)
    range_size = end_hex - start_hex + 1
    temp = start_hex + ((temp - start_hex) % range_size)
    
    return '{:X}'.format(temp)

def _replace_letters_match(match, x):
    start_letter_ord = ord(match.group(1)) # Adjusted group index for generic regex
    end_letter_ord = ord(match.group(2))   # Adjusted group index for generic regex
    increment = int(match.group(3)) if match.group(3) else 1 # Adjusted group index for generic regex
    
    temp = start_letter_ord + (x * increment)
    range_size = end_letter_ord - start_letter_ord + 1
    temp = start_letter_ord + ((temp - start_letter_ord) % range_size)
    
    return str(chr(temp))

def test_parse(textarea, timestorun):
    result = []
    for line in textarea.split("\n"):
        # Use compiled regex objects
        line = IPV4_REGEX.sub(lambda m: _test_replace_ipv4_match(m), line)
        line = IPV6_REGEX.sub(lambda m: _test_replace_ipv6_match(m), line)

        result = test_parse_numbers(line, result)
        result = test_parse_hex(line, result)
        result = test_parse_letters(line, result)
    return result

def test_parse_numbers(line, result):
    regex_int = re.compile(r'\[(\d+)-(\d+),?(\d+)?\]')
    matches = regex_int.findall(line)
    for match_groups in matches:
        start_num = int(match_groups[0])
        end_num = int(match_groups[1])
        if start_num > end_num:
            result.append(f"Error beginning number ({start_num}) is greater than ending number ({end_num}): {match_groups[0]}-{match_groups[1]}")
    return result

def test_parse_hex(line, result):
    regex_hex = re.compile(r'\{([0-9a-fA-F]+)-([0-9a-fA-F]+),?(\d+)?\}')
    matches = regex_hex.findall(line)
    for match_groups in matches:
        start_hex = int(match_groups[0], 16)
        end_hex = int(match_groups[1], 16)
        if start_hex > end_hex:
            result.append(f"Error beginning hex ({match_groups[0]}) is greater than ending hex ({match_groups[1]}): {match_groups[0]}-{match_groups[1]}")
    return result

def test_parse_letters(line, result):
    regex_letter = re.compile(r'\(([a-zA-Z]+)-([a-zA-Z]+),?(\d+)?\)')
    matches = regex_letter.findall(line)
    for match_groups in matches:
        start_letter = match_groups[0]
        end_letter = match_groups[1]
        if ord(start_letter) > ord(end_letter):
            result.append(f"Error beginning ASCII ({start_letter}) is greater than ending ASCII ({end_letter}): {start_letter}-{end_letter}")
    return result


def _test_replace_ipv4_match(match):
    original_ip = match.group('ip_address')
    slash_prefix = match.group('slash_prefix')
    dotted_mask = match.group('dotted_mask')
    increment_str = match.group('increment')

    # Determine the prefix length as an integer
    prefix_len_int = None
    if slash_prefix:
        prefix_len_int = int(slash_prefix[1:])
    elif dotted_mask:
        prefix_len_int = ipaddress.IPv4Network(f"0.0.0.0/{dotted_mask}").prefixlen
    else:
        prefix_len_int = 30

    increment = int(increment_str) if increment_str else 1

    current_ip_obj = ipaddress.IPv4Address(original_ip)
    # Use the integer prefix length for network object creation
    network_obj = ipaddress.IPv4Network((original_ip, prefix_len_int), strict=False)

    for _ in range(increment):
        current_ip_obj, network_obj = _get_next_usable_ipv4_address(current_ip_obj, network_obj)

    # For the return value, always format as IP/prefixlen
    return f"{current_ip_obj}/{prefix_len_int}"

def _test_replace_ipv6_match(match):
    original_ip = match.group('ip_address')
    prefix_length = match.group('prefix_length')
    increment_str = match.group('increment')

    increment = int(increment_str) if increment_str else 1

    current_ip_obj = ipaddress.IPv6Address(original_ip)
    network_obj = ipaddress.IPv6Network(f"{original_ip}{prefix_length}", strict=False)

    for _ in range(increment):
        current_ip_obj, network_obj = _get_next_ipv6_address(current_ip_obj, network_obj)

    return f"{current_ip_obj}{prefix_length}"

if __name__ == '__main__':
    task()
