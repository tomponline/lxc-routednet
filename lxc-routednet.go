// +build linux,cgo

// lxc-routednet hook that provides routed network connectivity for LXC containers.
package main

import (
	"flag"
	"fmt"
	"github.com/tomponline/lxc-routednet/internal/arp"
	"github.com/tomponline/lxc-routednet/internal/ndp"
	"gopkg.in/lxc/go-lxc.v2"
	"io/ioutil"
	"log"
	"log/syslog"
	"net"
	"os"
	"os/exec"
	"strings"
)

var (
	lxcpath string
)

func init() {
	flag.Parse()
	log.SetFlags(0)
	syslogWriter, err := syslog.New(syslog.LOG_INFO, "lxc-routednet")
	if err == nil {
		log.SetOutput(syslogWriter)
	}
}

// gwDev contains the network device name and IPs (v4 and v6) that the container uses as gateways.
type gwDev struct {
	dev   string
	gwIps []string
}

func main() {
	//Extract hook arguments from LXC.
	ctName := flag.Arg(0)
	context := flag.Arg(2)
	devType := flag.Arg(3)
	hostDevName := flag.Arg(4)

	//Load the container's config to get IP information.
	c, err := lxc.NewContainer(ctName, lxc.DefaultConfigPath())
	if err != nil {
		log.Fatalf("Cannot load config for: %s, %s\n", ctName, err.Error())
	}

	if !c.Defined() {
		log.Fatalf("Container %s not defined", ctName)
	}

	if devType != "veth" {
		log.Fatal("Unsupported dev type: ", devType)
	}

	var v4Ips []string
	var v6Ips []string

	gwProxyDevs := make(map[string]gwDev)

	//Sections of LXC container config to check for networking config.
	netPrefixes := []string{"lxc.net", "lxc.network"}

	for _, netPrefix := range netPrefixes {
		//Check for network interfaces configured to use this hook script.
		for i := 0; i < len(c.ConfigItem(netPrefix)); i++ {
			upScript := c.ConfigItem(fmt.Sprintf("%s.%d.script.up", netPrefix, i))
			//Check up script is this program.
			if strings.HasSuffix(upScript[0], os.Args[0]) {

				//Extract container IPs from config.
				if netPrefix == "lxc.network" {
					v4Ips = c.ConfigItem(fmt.Sprintf("%s.%d.ipv4", netPrefix, i))
					v6Ips = c.ConfigItem(fmt.Sprintf("%s.%d.ipv6", netPrefix, i))

				} else {
					v4Ips = c.ConfigItem(fmt.Sprintf("%s.%d.ipv4.address", netPrefix, i))
					v6Ips = c.ConfigItem(fmt.Sprintf("%s.%d.ipv6.address", netPrefix, i))
				}

				gwProxyDev := gwDev{
					dev:   hostDevName,
					gwIps: make([]string, 0),
				}

				//Extract gateway IPs from config.
				v4Gws := c.ConfigItem(fmt.Sprintf("%s.%d.ipv4.gateway", netPrefix, i))
				if v4Gws[0] != "" {
					gwProxyDev.gwIps = append(gwProxyDev.gwIps, v4Gws[0])
				}
				v6Gws := c.ConfigItem(fmt.Sprintf("%s.%d.ipv6.gateway", netPrefix, i))
				if v6Gws[0] != "" {
					gwProxyDev.gwIps = append(gwProxyDev.gwIps, v6Gws[0])
				}

				gwProxyDevs[hostDevName] = gwProxyDev
				break //Found what we needed
			}
		}
	}

	if len(v4Ips) <= 0 && len(v6Ips) <= 0 {
		log.Fatal("No IPs defined for CT Dev Ref: ", ctName)
	}

	if len(gwProxyDevs[hostDevName].gwIps) <= 0 {
		log.Fatal("No Gateways defined for CT Dev Ref: ", ctName)
	}

	ipAddrs := make([]*net.IPNet, 0, 2)
	parseCIDRs(v4Ips, &ipAddrs)
	parseCIDRs(v6Ips, &ipAddrs)

	switch context {
	case "up":
		runUp(c, ctName, hostDevName, ipAddrs, gwProxyDevs)
	case "down":
		runDown(c, ctName, hostDevName, ipAddrs)
	default:
		log.Fatal("Unknown context: ", context)
	}
}

// parseCIDRs converts a slice of string IPs to a slice of net.IPNet structs.
// Continues over any invalid CIDRs.
func parseCIDRs(cidrs []string, outIps *[]*net.IPNet) {
	for _, cidr := range cidrs {
		_, parsedCIDR, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Print("Invalid CIDR for '", cidr, "': ", err)
			continue
		}
		*outIps = append(*outIps, parsedCIDR)
	}
}

// getRouteDev finds any local addressed interfaces whose subnet contains the targetIP.
// Returns empty string if no match found. Returns error if parsing of targetIP or local interface
// information fails
func getRouteDev(targetIP net.IP) (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return "", err
		}

		for _, addr := range addrs {
			_, IPNet, err := net.ParseCIDR(addr.String())
			if err != nil {
				return "", err
			}
			if IPNet.Contains(targetIP) {
				return iface.Name, nil
			}
		}
	}

	//No local match found, meaning IP is probably routed to this host.
	//No need for proxy ARP/NDP.
	return "", nil
}

// activateProxyNdp sets up proxy NDP on the network device specified.
func activateProxyNdp(dev string) error {
	//Enable proxy ndp on  interface (needed before adding specific proxy entries)
	proxyNdpFile := "/proc/sys/net/ipv6/conf/" + dev + "/proxy_ndp"
	return ioutil.WriteFile(proxyNdpFile, []byte("1"), 0644)
}

// runUp called for each network interface that uses this hook script when the container comes up.
func runUp(c *lxc.Container, ctName string, hostDevName string, cidrs []*net.IPNet, gwProxyDevs map[string]gwDev) {
	log.Printf("LXC Net UP: %s %s %s", ctName, hostDevName, cidrs)

	//Activate IPv6 proxy ndp on all interfaces to ensure IPv6 connectivity works.
	//There is some unexpected behaviour when proxy ndp is only enabled on selected interfaces
	//that does not occur with proxy arp for IPv4.
	if err := activateProxyNdp("all"); err != nil {
		log.Fatal("Error activating proxy ndp: ", err)
	}
	log.Print("Activated proxy ndp")

	for _, gwDev := range gwProxyDevs {
		for _, gwIp := range gwDev.gwIps {
			//Setup proxy arp for default IP route on host interface
			cmd := exec.Command("ip", "neigh", "replace", "proxy", gwIp, "dev", gwDev.dev)
			if stdoutStderr, err := cmd.CombinedOutput(); err != nil {
				log.Fatal("Error adding proxy IP '", gwIp, "': ", err, " ", string(stdoutStderr))
			}
			log.Print("Added proxy for IP ", gwIp, " on ", gwDev.dev)

		}
	}

	//Add static route and proxy entry for each IP
	for _, cidr := range cidrs {
		//Lookup current route dev so we can setup proxy arp/ndp.
		ip := cidr.IP.String()
		routeDev, err := getRouteDev(cidr.IP)

		if err != nil {
			log.Fatal("Error finding route dev: '", ip, "': ", err)
		}

		cmd := exec.Command("ip", "route", "add", ip, "dev", hostDevName)
		if stdoutStderr, err := cmd.CombinedOutput(); err != nil {
			log.Fatal("Error adding static route for IP '", ip, "': ", err, " ", string(stdoutStderr))
		}
		log.Print("Added static route for IP ", ip, " to ", hostDevName)

		if routeDev == "" {
			continue //If not route dev found, IP is probably routed to this host.
		}

		cmd = exec.Command("ip", "neigh", "replace", "proxy", ip, "dev", routeDev)
		if stdoutStderr, err := cmd.CombinedOutput(); err != nil {
			log.Fatal("Error adding proxy for IP '", ip, "': ", err, " ", string(stdoutStderr))
		}
		log.Print("Added proxy for IP ", ip, " on ", routeDev)

		//Send NDP or ARP (IPv6 and IPv4 respectively) adverts
		if strings.Contains(ip, ":") {
			if err := ndp.SendUnsolicited(routeDev, ip); err != nil {
				log.Print("Error sending NDP for IP '", ip, " on iface ", routeDev, ": ", err)
			}
		} else {
			if err := arp.SendUnsolicited(routeDev, ip); err != nil {
				log.Print("Error sending ARP for IP '", ip, " on iface ", routeDev, ": ", err)
			}
		}

		log.Print("Advertised NDP/ARP for IP ", ip, " on ", routeDev)
	}
}

// runDown called for each network interface that uses this hook script when the container comes up.
func runDown(c *lxc.Container, ctName string, hostDevName string, cidrs []*net.IPNet) {
	log.Printf("LXC Net Down: %s %s %s", ctName, hostDevName, cidrs)

	//Remove static route and proxy entry for each IP
	for _, cidr := range cidrs {
		ip := cidr.IP.String()
		cmd := exec.Command("ip", "route", "del", ip, "dev", hostDevName)
		if stdoutStderr, err := cmd.CombinedOutput(); err != nil {
			log.Fatal("Error deleting static route for IP '", ip, "': ", err, " ", string(stdoutStderr))
		}
		log.Print("Deleted static route for IP ", ip, " to ", hostDevName)

		//Now static route is removed, find original route dev so we can remove proxy arp/ndp config.
		routeDev, err := getRouteDev(cidr.IP)

		if err != nil {
			log.Print("Error finding route dev: '", ip, "': ", err)
			continue
		}

		if routeDev == "" {
			continue //Can't clean up proxy ARP/NDP rule if can't find route dev.
		}

		cmd = exec.Command("ip", "neigh", "del", "proxy", ip, "dev", routeDev)
		if stdoutStderr, err := cmd.CombinedOutput(); err != nil {
			log.Print("Error remove proxy for IP '", ip, "': ", err, " ", string(stdoutStderr))
		}
		log.Print("Deleted proxy for IP ", ip, " on ", routeDev)
	}
}
