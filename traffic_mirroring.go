package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"io"
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

	go writeFile(packetsList, f)
	networkListener(packetSource, packetsList)
}


func check(e error) {
	if e != nil {
		panic(e)
	}
}
func networkListener(packetSource *gopacket.PacketSource, packetsList chan []byte) {
	for overlayPacket := range packetSource.Packets() {
		vxlanLayer := overlayPacket.Layer(layers.LayerTypeVXLAN)
		if vxlanLayer != nil {
			vxlanPacket, _ := vxlanLayer.(*layers.VXLAN)
			packetsList <- vxlanPacket.LayerPayload()
		}
	}
}

func writeFile(packetsList chan []byte, file io.Writer) {
	batchSize := 20

	for {
		if len(packetsList) >= batchSize {
			for i := 0; i < batchSize; i++ {
				value := <-packetsList
				_, err := file.Write(value)
				check(err)
			}
		}
	}
}

