// +build go1.7

package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	flag "github.com/ogier/pflag"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/pkg/errors"
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
	var (
		errC   chan error
		sigC   = make(chan os.Signal, 1)
		ctx    context.Context
		cancel context.CancelFunc
	)
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()

	signal.Notify(sigC,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGPIPE,
	)

	errC = flowDump(ctx)

	for {
		select {
		case <-sigC:
			cancel()
		case err := <-errC:
			if err != nil {
				if err == context.Canceled {
					fmt.Fprintln(os.Stderr, "Terminated by user")
				} else {
					fmt.Fprintln(os.Stderr, err.Error())
					os.Exit(1)
				}
			}
			os.Exit(0)
		}
	}
}

func flowDump(ctx context.Context) chan error {
	errC := make(chan error)

	go func() {
		defer close(errC)

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
				errC <- errors.Wrapf(err, "couldn't open %s", pcapFile)
				return
			}
		} else {
			// Live packet capture
			handle, err = pcap.OpenLive(iface, int32(snaplen), true, pcap.BlockForever)

			if err != nil {
				errC <- errors.Wrapf(err, "couldn't listen on %s", iface)
				return
			}
			fmt.Fprintf(os.Stderr, "Listening on %s (snaplen %d bytes)\n", iface, snaplen)
		}
		defer handle.Close()

		// Set packet filter if provided
		filterParts := flag.Args()
		if len(filterParts) > 0 {
			if err = handle.SetBPFFilter(strings.Join(filterParts, " ")); err != nil {
				errC <- errors.Wrap(err, "filter compilation failure")
			}
		} else {
			fmt.Fprintln(os.Stderr, "No packet filter provided - this probably isn't what you want!")
			if !force {
				fmt.Fprintln(os.Stderr, "Exiting; use --force if you really want to do this.")
				return
			}
		}

		// Now dump all of the packets
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		packetC := packetSource.Packets()

		for {
			select {
			case <-ctx.Done():
				errC <- ctx.Err()
				return
			case packet, ok := <-packetC:
				if !ok {
					return
				}
				tl := packet.TransportLayer()
				if tl != nil {
					_, _ = os.Stdout.Write(tl.LayerPayload())
				}
			}
		}

	}()
	return errC
}

// Find the first non-loopback interface that's up
func defaultIface() string {
	ifaces, _ := net.Interfaces()
	for _, candidate := range ifaces {
		f := candidate.Flags
		if (f&net.FlagUp != 0) && (f&net.FlagLoopback == 0) {
			return candidate.Name
		}
	}
	return "any"
}
