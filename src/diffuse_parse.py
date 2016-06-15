

# Protocol TCP or UDP
def proto_check(proto):
    # TCP
    if proto == 6:
        return 'tcp'
    # UDP
    elif proto == 17:
        return 'udp'
    else:
        return None


# IPv4 to int
def ipv4_to_int(string):
    ip = string.split('.')
    assert len(ip) == 4
    i = 0
    for b in ip:
        b = int(b)
        i = (i << 8) | b
    return i
