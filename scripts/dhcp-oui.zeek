##! Adds the OUI name based on Mac Address

module OUI;
# This script adds link-layer address (MAC) information to the dhcp logs

export {
        redef record DHCP::Info +=
{
                # The name of the new field will be orig_mac_oui
                orig_mac_oui: string &log &optional;
        };
}

# Add the vendor to DHCP::Info
# connection information is written to the log.
# DHCP::aggregate_msgs is used to distribute data around clusters.
# In this case, this event is used to extend the DHCP logs. 
event DHCP::aggregate_msgs(ts: time, id: conn_id, uid: string, 
	is_orig: bool, msg: DHCP::Msg, options: DHCP::Options) {
		local vendor = lookup_oui(msg$chaddr);
		DHCP::log_info$orig_mac_oui = vendor;
	}
