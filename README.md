# flowdump

flowdump is a tool for extracting payloads from packet captures.

## Why?

After looking for an easy way to extract just the TCP or UDP payload from a flow of packets captured in a .pcap file, I had to settle for opening up the capture in WireShark, using the 'Follow Stream' functionality, and then saving the output in a raw format. This works well, but is inconvenient and slow compared to having a quick CLI utility to do the same task.

## How?

flowdump is written in Go, and uses the fantastic [gopacket](https://github.com/google/gopacket) to parse packets, either from a live capture or from a pre-recorded pcap file.

## Installation

`$ go get github.com/wrigby/flowdump`

## Usage

flowdump relies on you writing an appropriate BPF filter rule that isolates the flow (or flows) you want to dump data from. For instance, to see all outgoing HTTP requests from our machine, we could run:

`$ flowdump dst port 80`

This would print just the transport-layer payload from packets destined for port 80. Note that flowdump does no formatting on the payloads, so if the payload is binary data, your terminal may get trashed. It's useful, though, to redirect the output to a file, so you can process it later:

`$ flowdump dst port 80 > requests.txt`

Later on, we can take a look at the data (I have a bit of a Hacker News addiction, apparently):

```
$ grep ^Host: requests.txt | awk '{print $2}' | sort | uniq -c
   1 google.com
   7 news.ycombinator.com
   3 reddit.com
```

## Roadmap

- [x] Read PCAP files
- [x] Live packet captures
- [ ] Intelligent TCP stream re-assembly (right now flowdump just doesn't care about silly things like sequence numbers)
- [ ] Split out each flow automatically and write each to its own file
- [ ] Summary tools to show a list of flows identified

## License

flowdump is licensed under the MIT license. For more details, see the LICENSE file
provided with this source code.

