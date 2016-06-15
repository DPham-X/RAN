# Version Check


def version_check(version):
    return {
            4: 'OF13',  # 0x04 -> OF1.3
            5: 'OF14',  # 0x05 -> OF1.4
            6: 'OF15',  # 0x06 -> OF1.5
        }.get(version, 0)