##! Adds the OUI name based on Mac Address

module OUI;
# This script adds link-layer address (MAC) information to the connection logs

export {
	redef record Conn::Info += 
{
		# The name of the new field will be orig_mac_oui
		orig_mac_oui: string &log &optional;
	};
}

# Add the vendor to the Conn::Info structure after the connection
# has been removed. This ensures it's only done once, and is done before the
# connection information is written to the log.
event connection_state_remove(c: connection) {
        if ( c$orig?$l2_addr )
                c$conn$orig_mac_oui = lookup_oui(c$orig$l2_addr);
}
