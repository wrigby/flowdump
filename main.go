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
	iface    string // Interface to listen on
	pcapFile string // PCAP file to read from
	snaplen  int    // Snaplen when live-capturing
)

func main() {
	iface := flag.StringP("interface", "i", defaultIface(), "Interface to listen on")
	snaplen := flag.IntP("snaplen", "s", 1600, "Maximum number of bytes to read from each packet")
	pcapFile := flag.StringP("file", "r", "", "Read from a pcap file instead of listening")
	flag.Parse()

	var handle *pcap.Handle
	var err error
	if *pcapFile != "" {
		// Read from file
		if handle, err = pcap.OpenOffline(*pcapFile); err != nil {
			panic(err)
		}
	} else {
		fmt.Fprintf(os.Stderr, "Listening on %s (snaplen %d bytes)\n", *iface, *snaplen)
		if handle, err = pcap.OpenLive(*iface, int32(*snaplen), true, pcap.BlockForever); err != nil {
			panic(err)
		}
	}

	// Set packet filter if provided
	filterParts := flag.Args()
	if len(filterParts) > 0 {
		if err = handle.SetBPFFilter(strings.Join(filterParts, " ")); err != nil {
			panic(err)
		}
	} else {
		fmt.Fprintln(os.Stderr, "No packet filter provided - this probably isn't what you want!")
	}

	dumpPackets(handle)
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

func dumpPackets(handle *pcap.Handle) {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		tl := packet.TransportLayer()
		if tl != nil {
			os.Stdout.Write(tl.LayerPayload())
		}
	}
}
