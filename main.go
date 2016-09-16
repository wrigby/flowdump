package main

import (
	"fmt"
	"net"
	"os"
	"strings"

	flag "github.com/ogier/pflag"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var (
	iface    string
	snaplen  int
	pcapFile string
	force    bool
)

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [options] [filter]\n", os.Args[0])
	fmt.Println()
	fmt.Println("Options:")
	flag.PrintDefaults()
}

func main() {
	os.Exit(flowDump())
}

func flowDump() int {
	flag.Usage = usage
	flag.StringVarP(&iface, "interface", "i", defaultIface(), "Interface to listen on")
	flag.IntVarP(&snaplen, "snaplen", "s", 1600, "Maximum number of bytes to read from each packet")
	flag.StringVarP(&pcapFile, "file", "r", "", "Read from a pcap file instead of listening")
	flag.BoolVarP(&force, "force", "f", false, "Run even if no filter is provided")
	flag.Parse()

	var handle *pcap.Handle
	var err error
	if pcapFile != "" {
		// Read from file
		handle, err = pcap.OpenOffline(pcapFile)

		if err != nil {
			fmt.Fprintf(os.Stderr, "Couldn't open %s: %s\n", pcapFile, err)
			return 1
		}
	} else {
		// Live packet capture
		handle, err = pcap.OpenLive(iface, int32(snaplen), true, pcap.BlockForever)

		if err != nil {
			fmt.Fprintf(os.Stderr, "Couldn't listen on %s: %s\n", iface, err)
			return 1
		} else {
			fmt.Fprintf(os.Stderr, "Listening on %s (snaplen %d bytes)\n", iface, snaplen)
		}
	}
	defer handle.Close()

	// Set packet filter if provided
	filterParts := flag.Args()
	if len(filterParts) > 0 {
		if err = handle.SetBPFFilter(strings.Join(filterParts, " ")); err != nil {
			panic(err)
		}
	} else {
		fmt.Fprintln(os.Stderr, "No packet filter provided - this probably isn't what you want!")
		if !force {
			fmt.Fprintln(os.Stderr, "Exiting; use --force if you really want to do this.")
			return 1
		}
	}

	// Now dump all of the packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		tl := packet.TransportLayer()
		if tl != nil {
			os.Stdout.Write(tl.LayerPayload())
		}
	}

	return 0
}

// Find the first non-loopback interface that's up
func defaultIface() string {
	var iface string
	ifaces, _ := net.Interfaces()
	for _, candidate := range ifaces {
		f := candidate.Flags
		if (f&net.FlagUp != 0) && (f&net.FlagLoopback == 0) {
			iface = candidate.Name
			break
		}
	}
	return iface
}
