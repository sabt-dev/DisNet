package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorCyan   = "\033[36m"
)

const (
	timeout          = 1000 * time.Millisecond // Timeout for port scanning
	defaultRangePort = 1024                    // Maximum port number to scan
	defaultMaxPort   = 65535                   // Maximum port number for user input validation
)

func main() {
	var ipNet string
	var portRange string

	// Check if the program is run with administrator privileges
	if os.Geteuid() != 0 {
		fmt.Printf("%s[!] Error: This program requires administrator privileges to run.%s\n", ColorRed, ColorReset)
	}

	// Prompt user for CIDR notation, host, or domain and port range
	fmt.Printf("Enter CIDR notation, host, or domain (e.g., 192.168.0.0/24 or example.com): ")
	fmt.Scan(&ipNet)
	fmt.Printf("Enter port range (e.g., 20-80 or single port): ")
	fmt.Scan(&portRange)

	// Check if input is CIDR notation, host, or domain
	var network *net.IPNet
	var isCIDR, isDomain bool
	var err error
	if _, network, err = net.ParseCIDR(ipNet); err == nil {
		isCIDR = true
	} else if net.ParseIP(ipNet) == nil {
		isDomain = true
	}

	fmt.Printf("%s[*]%s Starting...\n", ColorCyan, ColorReset)

	var chosenIP string
	if isCIDR {
		fmt.Printf("%s[*]%s Scanning for hosts in the network: %s\n", ColorCyan, ColorReset, network)
		chosenIP, err = scanNetworkConcurrently(network)
		if err != nil {
			fmt.Printf("%s[!] Error: %s%s\n", ColorRed, err, ColorReset)
			fmt.Printf("%s[!]%s Exiting...\n", ColorRed, ColorReset)
			return
		}
	} else if isDomain {
		fmt.Printf("%s[*]%s Skipping host discovery and proceeding to port scanning for domain: %s\n", ColorCyan, ColorReset, ipNet)
		chosenIP = ipNet
	} else {
		fmt.Printf("%s[*]%s Skipping host discovery and proceeding to port scanning for host: %s\n", ColorCyan, ColorReset, ipNet)
		chosenIP = ipNet
	}

	// Check if the chosen IP is private or public
	parsedIP := net.ParseIP(chosenIP)
	if parsedIP != nil {
		if isPrivateIP(parsedIP) {
			fmt.Printf("%s[*]%s The IP address %s is private.%s\n", ColorCyan, ColorReset, chosenIP, ColorReset)
		} else {
			fmt.Printf("%s[*]%s The IP address %s is public.%s\n", ColorCyan, ColorReset, chosenIP, ColorReset)
		}
	}

	// Parse port range
	var startPort, endPort int
	if portRange != "" {
		if strings.Contains(portRange, "-") {
			n, err := fmt.Sscanf(portRange, "%d-%d", &startPort, &endPort)
			if n != 2 || err != nil || startPort < 1 || endPort > defaultMaxPort || startPort > endPort {
				fmt.Printf("%s[!] Error: Invalid port range.%s\n", ColorRed, ColorReset)
				return
			}
		} else {
			n, err := fmt.Sscanf(portRange, "%d", &startPort)
			if n != 1 || err != nil || startPort < 1 || startPort > defaultMaxPort {
				fmt.Printf("%s[!] Error: Invalid port range.%s\n", ColorRed, ColorReset)
				return
			}
			endPort = startPort
		}
	} else {
		startPort, endPort = 1, defaultRangePort
	}

	// Scan for open ports on the chosen host or domain
	fmt.Printf("%s[*]%s Scanning host/domain: %s for open ports in range %d-%d...\n", ColorCyan, ColorReset, chosenIP, startPort, endPort)
	portScanner(chosenIP, startPort, endPort)
	fmt.Printf("%s[*]%s Scan completed\n", ColorCyan, ColorReset)

	// Exit message
	var null string
	fmt.Printf("%sPress Enter to exit...%s\n", ColorYellow, ColorReset)
	_, _ = fmt.Scan(&null) // Wait for user input before exiting
}

func portScanner(hostname string, startPort, endPort int) {
	var wg sync.WaitGroup
	results := make(chan int, endPort-startPort+1) // Buffered channel to hold open ports

	// Predefined mapping of common ports to services
	commonServices := map[int]string{
		20:    "FTP Data",
		21:    "FTP",
		22:    "SSH",
		23:    "Telnet",
		25:    "SMTP",
		53:    "DNS",
		67:    "DHCP Server",
		68:    "DHCP Client",
		69:    "TFTP",
		80:    "HTTP",
		110:   "POP3",
		111:   "RPCbind",
		119:   "NNTP",
		123:   "NTP",
		135:   "MS RPC",
		137:   "NetBIOS Name",
		138:   "NetBIOS Datagram",
		139:   "NetBIOS Session",
		143:   "IMAP",
		161:   "SNMP",
		162:   "SNMP Trap",
		179:   "BGP",
		389:   "LDAP",
		443:   "HTTPS",
		445:   "Microsoft-DS",
		465:   "SMTPS",
		514:   "Syslog",
		515:   "LPD",
		520:   "RIP",
		587:   "SMTP Submission",
		631:   "IPP",
		636:   "LDAPS",
		993:   "IMAPS",
		995:   "POP3S",
		1080:  "SOCKS Proxy",
		1433:  "MSSQL",
		1521:  "Oracle DB",
		1723:  "PPTP",
		2049:  "NFS",
		2082:  "cPanel",
		2083:  "cPanel SSL",
		2181:  "Zookeeper",
		2375:  "Docker",
		2376:  "Docker SSL",
		3306:  "MySQL",
		3389:  "RDP",
		3690:  "Subversion",
		4000:  "ICQ",
		4040:  "HTTP Proxy",
		4369:  "Erlang Port Mapper",
		5000:  "UPnP",
		5432:  "PostgreSQL",
		5631:  "pcAnywhere",
		5900:  "VNC",
		5984:  "CouchDB",
		6379:  "Redis",
		6667:  "IRC",
		7001:  "WebLogic",
		8000:  "HTTP Alt",
		8008:  "HTTP Alt",
		8080:  "HTTP Proxy",
		8081:  "HTTP Alt",
		8443:  "HTTPS Alt",
		8888:  "HTTP Alt",
		9000:  "SonarQube",
		9200:  "Elasticsearch",
		9300:  "Elasticsearch",
		11211: "Memcached",
		27017: "MongoDB",
		27018: "MongoDB",
		27019: "MongoDB",
		50000: "SAP",
	}

	// Start scanning ports concurrently
	for port := startPort; port <= endPort; port++ {
		wg.Add(1)
		go scanPorts(&wg, "tcp", hostname, port, timeout, results)
	}

	// Wait for all goroutines to finish
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	for port := range results {
		service := "Unknown"
		if svc, exists := commonServices[port]; exists {
			service = svc
		}
		fmt.Printf("%s[+]%s Open port found: %d\t(%s)\n", ColorGreen, ColorReset, port, service)
	}
}

func scanPorts(wg *sync.WaitGroup, protocol, hostname string, port int, timeout time.Duration, results chan int) {
	defer wg.Done()

	address := net.JoinHostPort(hostname, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout(protocol, address, timeout)
	if err != nil {
		return // Port is closed or host is unreachable
	}
	defer conn.Close()

	results <- port // Port is open
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func isHostAlive(ip string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ping", "-n", "1", "-w", "1000", ip)
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return false // Ping timed out
	}
	return err == nil
}

func scanNetworkConcurrently(network *net.IPNet) (string, error) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 50) // Limit concurrency to 50 goroutines

	aliveHosts := []string{}

	for ip := network.IP.Mask(network.Mask); network.Contains(ip); incrementIP(ip) {
		ipCopy := make(net.IP, len(ip))
		copy(ipCopy, ip)
		wg.Add(1)
		sem <- struct{}{}
		go func(ip net.IP) {
			defer wg.Done()
			defer func() { <-sem }()
			if isHostAlive(ip.String()) {
				fmt.Printf("%s[+]%s Host Discovered: %s\n", ColorGreen, ColorReset, ip)
				aliveHosts = append(aliveHosts, ip.String())
			}
		}(ipCopy)
	}
	wg.Wait()

	// List all alive hosts with numbers
	fmt.Println("\n=====================================")
	for i, host := range aliveHosts {
		fmt.Printf("%s(%d)%s %s\n", ColorCyan, i+1, ColorReset, host)
	}
	fmt.Print("=====================================\n\n")

	// Prompt user to choose a host
	var choice int
	fmt.Printf("%sSelect number> %s", ColorBlue, ColorReset)
	_, err := fmt.Scan(&choice)
	if err != nil || choice < 1 || choice > len(aliveHosts) {
		return "", fmt.Errorf("invalid choice")
	}

	return aliveHosts[choice-1], nil
}

func isPrivateIP(ip net.IP) bool {
	privateBlocks := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",    // Loopback
		"169.254.0.0/16", // Link-local
	}

	for _, block := range privateBlocks {
		_, cidr, _ := net.ParseCIDR(block)
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}
