package main

import (
	"fmt"
	"os"
	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
//	"encoding/json"
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
	filePath := "Test"
	go writeFile(packetsList, filePath)

	for overlayPacket := range packetSource.Packets() {
		vxlanLayer := overlayPacket.Layer(layers.LayerTypeVXLAN)
		if vxlanLayer != nil {
			vxlanPacket, _ := vxlanLayer.(*layers.VXLAN)
			packetsList <- vxlanPacket.LayerPayload()
			fmt.Println(vxlanPacket.LayerPayload())

		}
	}
}

func writeFile(packetsList chan []byte, filePath string) {
	numberPackets := 20
	f, err := os.Create(filePath)
	if err != nil {
		panic(err)
	}

	for {
		if len(packetsList) >= numberPackets {
			for i := 0; i < numberPackets; i++ {
				value := <-packetsList
				fmt.Fprintln(f, value)
			}
		}
	}
	defer f.Close()
}

