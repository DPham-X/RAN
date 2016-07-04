# Version Check


def version_check(version):
    """Checks if OpenFlow version is compatible and returns the version if it is

    Parameters
    ----------
    version: hex
        The OpenFlow version taken from the SDN switch 'hello' message
    Returns
    -------
        The OpenFlow version if match, else 0 for unsupported version

    """
    return {
            4: 'OF13',  # 0x04 -> OF1.3
            5: 'OF14',  # 0x05 -> OF1.4
            6: 'OF15',  # 0x06 -> OF1.5
        }.get(version, 0)
