package ndp

import "github.com/mdlayher/ndp"
import "fmt"
import "net"

//SendUnsolicited sends an unsolicited NDP neighbour advertisement to all nodes.
func SendUnsolicited(iface string, addr string) error {
	// Select a network interface by its name to use for NDP communications.
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return fmt.Errorf("failed to get interface: %v", err)
	}

	// Set up an *ndp.Conn, bound to this interface's link-local IPv6 address.
	c, _, err := ndp.Dial(ifi, ndp.LinkLocal)
	if err != nil {
		return fmt.Errorf("failed to dial NDP connection: %v", err)
	}
	// Clean up after the connection is no longer needed.
	defer c.Close()

	// Choose a target with a known IPv6 link-local address.
	ip := net.ParseIP(addr)
	if ip == nil {
		return fmt.Errorf("invalid address")
	}

	// Send to all node multicast address.
	snm := net.ParseIP("ff02::1")
	if snm == nil {
		return fmt.Errorf("failed to determine solicited-node multicast address: %v", err)
	}

	// Build a neighbor advert message.
	m := &ndp.NeighborAdvertisement{
		TargetAddress: ip,
		Override:      true,
		Options: []ndp.Option{
			&ndp.LinkLayerAddress{
				Direction: ndp.Target,
				Addr:      ifi.HardwareAddr,
			},
		},
	}

	// Send the multicast message.
	if err := c.WriteTo(m, nil, snm); err != nil {
		return fmt.Errorf("failed to write neighbor solicitation: %v", err)
	}

	return nil
}
