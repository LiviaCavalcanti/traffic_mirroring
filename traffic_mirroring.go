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
	filePath := "Test"
	f, err := os.Create(filePath)
        if err != nil {
                 panic(err)
        }

	handle, err := pcap.OpenLive("eth0", 9001, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}

	filter := "udp"
	if err := handle.SetBPFFilter(filter); err != nil {
		panic(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	max_size := 10
	packets_list := make([][]byte,max_size) 
	current_packet := 0

	for overlayPacket := range packetSource.Packets() {
		vxlanLayer := overlayPacket.Layer(layers.LayerTypeVXLAN)
		if vxlanLayer != nil {
			vxlanPacket, _ := vxlanLayer.(*layers.VXLAN)
			
			fmt.Println(current_packet)
			packets_list[current_packet] = vxlanPacket.LayerPayload()
			current_packet += 1
			fmt.Println(vxlanPacket.LayerPayload())
			if current_packet == max_size {
				newSlice := make([][]byte, max_size)
				copy(newSlice, packets_list)
				fmt.Println(current_packet)
				current_packet = 0
				go write_file(newSlice, f)


			}
		}
	}
	defer f.Close()
}

func write_file(packets_list [][]byte, f *os.File) {
	for _, value := range packets_list {
		fmt.Fprintln(f, value)  
	}
}

