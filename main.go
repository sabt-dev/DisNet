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
	timeout          = 300 * time.Millisecond // Timeout for port scanning
	defaultRangePort = 1024                   // Maximum port number to scan
	defaultMaxPort   = 65535                  // Maximum port number for user input validation
)

func main() {
	var ipNet string
	var portRange string

	// Check if the program is run with administrator privileges
	if os.Geteuid() != 0 {
		fmt.Printf("%s[!] Error: This program requires administrator privileges to run.%s\n", ColorRed, ColorReset)
	}

	// Prompt user for CIDR notation and port range
	fmt.Printf("Enter CIDR notation (e.g., 192.168.0.0/24): ")
	fmt.Scan(&ipNet)
	fmt.Printf("Enter port range (e.g., 20-80 or single port): ")
	fmt.Scan(&portRange)

	// Parse the CIDR notation
	_, network, err := net.ParseCIDR(ipNet)
	if err != nil {
		fmt.Printf("%s[!] Error: Invalid CIDR notation.%s\n", ColorRed, ColorReset)
		return
	}

	fmt.Printf("%s[*]%s Starting...\n", ColorCyan, ColorReset)
	fmt.Printf("%s[*]%s Scanning for hosts in the network: %s\n", ColorCyan, ColorReset, network)

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

	// Scan for alive hosts
	chosenIP, err := scanNetworkConcurrently(network)
	if err != nil {
		fmt.Printf("%s[!] Error: %s%s\n", ColorRed, err, ColorReset)
		fmt.Printf("%s[!]%s Exiting...\n", ColorRed, ColorReset)
		return
	}

	// Scan for open ports on the chosen host
	fmt.Printf("%s[*]%s Scanning host: %s for open ports in range %d-%d...\n", ColorCyan, ColorReset, chosenIP, startPort, endPort)
	portScanner(chosenIP, startPort, endPort)
	fmt.Printf("%s[*]%s Scan completed.\n", ColorCyan, ColorReset)

	// Exit message
	var null string
	fmt.Printf("%sPress Enter to exit...%s\n", ColorYellow, ColorReset)
	_, _ = fmt.Scan(&null) // Wait for user input before exiting
}

func portScanner(hostname string, startPort, endPort int) {
	var wg sync.WaitGroup
	results := make(chan int, endPort-startPort+1) // Buffered channel to hold open ports

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
		fmt.Printf("%s[+]%s Open port found: %d\n", ColorGreen, ColorReset, port)
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
