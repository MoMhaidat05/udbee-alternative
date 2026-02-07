def check_missing_packets(packets, total):
    # Find which packet chunks weren't received (helps detect transmission losses)
    missing_packets = []
    
    # Check each expected packet index
    for i in range(0, total):
        # If we didn't get this packet, add it to the list of missing ones
        if not packets.get(i):
            missing_packets.append(i)
    
    # Return None if everything came through, otherwise return the list of gaps
    return missing_packets if len(missing_packets) > 0 else None