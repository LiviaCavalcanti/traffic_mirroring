package main

import (

	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"io"
	"log"
	"os"
	"os/signal"
	"time"
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
	batchSize := 20

	f, err := os.Create(filePath)
	check(err)
	defer f.Close()

	sigChan := make(chan os.Signal)
	quit := make(chan bool)
	signal.Notify(sigChan, os.Interrupt)

	go WriteFile(packetsList, f, quit, batchSize)
	go NetworkListener(packetSource, packetsList)
	handleSignal(sigChan, packetsList, quit, os.Exit)

}


func check(e error) {
	if e != nil {
		panic(e)
	}
}

func handleSignal(sigChan chan os.Signal, packetsList chan []byte, quit chan bool, end func(int)) {
	<-sigChan
	exitCode := 0
	close(packetsList)
	quit <- true
	end(exitCode)
}

func NetworkListener(source *gopacket.PacketSource, dest chan []byte) {
	for overlayPacket := range source.Packets() {
		vxlanLayer := overlayPacket.Layer(layers.LayerTypeVXLAN)
		if vxlanLayer != nil {
			vxlanPacket, ok := vxlanLayer.(*layers.VXLAN)
			if !ok {
				log.Printf("Unable to cast packet to vxlan layer")
			} else {
				dest <- vxlanPacket.LayerPayload()
			}
		}
	}
}

func WriteFile(packetsList chan []byte, file io.Writer, quit chan bool, batchSize int) {

	for {
		select {
		case <- quit:
			for value := range packetsList {
				_, err := file.Write(value)
				if err != nil {
					panic(err)
				}
			}
			return
		default:
			if len(packetsList) >= batchSize {
				for i := 0; i < batchSize; i++ {
					value := <-packetsList
					_, err := file.Write(value)
					if err != nil {
						panic(err)
					}
				}
			}
		}
		time.Sleep(1 * time.Millisecond)
	}
}
