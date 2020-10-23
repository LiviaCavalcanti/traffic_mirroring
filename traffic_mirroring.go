package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
//	"github.com/google/gopacket/tcpassembly"
//	"github.com/google/gopacket/tcpassembly/tcpreader"
	"strings"
	"time"
)

//type httpStreamFactory struct{}

// httpStream will handle the actual decoding of http requests.
//type httpStream struct {
//	net, transport gopacket.Flow
//	r              tcpreader.ReaderStream
//}

//func (h *httpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
//	hstream := &httpStream{
//		net:       net,
//		transport: transport,
//		r:         tcpreader.NewReaderStream(),
//	}
//	return &hstream.r
//}

func main() {
	defer util.Run()()

	handle, err := pcap.OpenLive("eth0", 9001, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}

	filter := "udp"
	if err := handle.SetBPFFilter(filter); err != nil {
		panic(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	var reqs strings.Builder
	var sep = ";"

	for overlayPacket := range packetSource.Packets() {
		vxlanLayer := overlayPacket.Layer(layers.LayerTypeVXLAN)
		if vxlanLayer != nil {
			vxlanPacket, _ := vxlanLayer.(*layers.VXLAN)
			packet := gopacket.NewPacket(vxlanPacket.LayerPayload(), layers.LayerTypeEthernet, gopacket.Default)

			applicationLayer := packet.ApplicationLayer()
			if applicationLayer != nil {
				if strings.Contains(string(applicationLayer.Payload()), "HTTP"){
					now := time.Now()
					nsec := now.UnixNano()
					netFlow := packet.NetworkLayer().NetworkFlow()
					reqs.WriteString(netFlow)
//					src,dst := netFlow.Endpoints()
//					fmt.Printf("[SRC HOST IP: %s] [DEST HOST IP: %s]\n", src, dst)
//					fmt.Printf("%s\n", applicationLayer.Payload())
					fmt.Println(nsec)
				}
			}
//			fmt.Println(packet.Dump())
//			assembler := tcpassembly.NewAssembler(streamPool)
//			go process_packet(packet, assembler)
		}
	}
}

//func process_packet(packet gopacket.Packet, assembler *tcpassembly.Assembler) {
//	tcpLayer := packet.Layer(layers.LayerTypeTCP)
//	tcp, _ := tcpLayer.(*layers.TCP)
//	if tcp != nil {
//		assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)
//	}
//}

