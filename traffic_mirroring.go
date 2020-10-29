package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"io"
	"log"
	"os"
)


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
	packetsList := make(chan []byte, 22)
	filePath := "dump_file"

	f, err := os.Create(filePath)
	check(err)

	defer f.Close()

	go WriteFile(packetsList, f)
	NetworkListener(packetSource.Packets(), packetsList)
}


func check(e error) {
	if e != nil {
		panic(e)
	}
}

func NetworkListener(source chan gopacket.Packet, dest chan []byte) {
	for overlayPacket := range source {
		vxlanLayer := overlayPacket.Layer(layers.LayerTypeVXLAN)
		if vxlanLayer == nil {
			log.Printf("Unable to get VXLAN Layer for packet with metadata (%+v)\n", overlayPacket.Metadata())
		}
		vxlanPacket, ok := vxlanLayer.(*layers.VXLAN)
		if !ok {
			log.Printf("Unable to cast packet (%+v) to vxlan layer", overlayPacket.Metadata())
		}
		dest <- vxlanPacket.LayerPayload()
	}
}

func WriteFile(packetsList chan []byte, file io.Writer) {
	// TODO: on the program exit, you need to write the remain packets inside the channel.
	batchSize := 20

	for {
		if len(packetsList) >= batchSize {
			for i := 0; i < batchSize; i++ {
				value := <-packetsList
				n, err := file.Write(value)
				if len(value) != n {
					// nao escreveu.
				}
				check(err)
			}
		}
	}
}

