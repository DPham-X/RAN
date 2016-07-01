

def proto_check(proto):
    """Checks if protocol is TCP or UDP

    Parameters
    ----------
    proto: int
        The protocol number in the FCN/CN message
    Returns
    -------
        The protocol name if TCP/UDP else returns nothing

    """
    # Check for TCP
    if proto == 6:
        return 'tcp'
    # Check for UDP
    elif proto == 17:
        return 'udp'
    else:
        return None


def ipv4_to_int(string):
    """Converts an IPv4 string to integer

    Parameters
    ----------
    string: str eg. '1.1.1.1'
        The IPv4 string
    Returns
    -------
        The integer representation of the IPv4 string

    """
    ip = string.split('.')
    assert len(ip) == 4
    i = 0
    for b in ip:
        b = int(b)
        i = (i << 8) | b
    return i
