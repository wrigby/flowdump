# flowdump

## Why?

flowdump is a tool for extracting payloads from packet captures. After fumbling around with WireShark and other tools for doing this, I wanted a simple and quick solution to get the actual UDP or TCP payloads out of a flow that was captured off the wire in a PCAP file.

## Installation

`$ go get github.com/wrigby/flowdump`

## Basic usage

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


## License

flowdump is licensed under the MIT license. For more details, see the LICENSE file
provided with this source code.

