package arp

import "github.com/mdlayher/arp"
import "fmt"
import "net"

//SendUnsolicited sends an unsolicited ARP neighbour advertisement to all nodes.
func SendUnsolicited(iface string, addr string) error {
	// Select a network interface by its name to use for NDP communications.
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return fmt.Errorf("failed to get interface: %v", err)
	}

	// Set up an *arp.Conn, bound to this interface.
	c, err := arp.Dial(ifi)
	if err != nil {
		return fmt.Errorf("failed to dial ARP connection: %v", err)
	}
	// Clean up after the connection is no longer needed.
	defer c.Close()

	// Get target address.
	ip := net.ParseIP(addr)
	if ip == nil {
		return fmt.Errorf("invalid address")
	}

	p, err := arp.NewPacket(arp.OperationReply, ifi.HardwareAddr, ip,
		net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, ip)
	if err != nil {
		return fmt.Errorf("failed to create ARP packet: %v", err)
	}

	if err = c.WriteTo(p, net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}); err != nil {
		return fmt.Errorf("failed to write neighbor advertisement: %v", err)
	}

	return nil
}
