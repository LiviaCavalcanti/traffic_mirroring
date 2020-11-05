package main

import (

	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
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
	filePath := "dump_file.pcap"
	batchSize := 20

	f, err := os.Create(filePath)
	check(err)
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(65535, layers.LinkTypeEthernet)
	defer f.Close()

	sigChan := make(chan os.Signal)
	quit := make(chan bool)
	signal.Notify(sigChan, os.Interrupt)

	go ChannelControl(packetsList, w, quit, batchSize)
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
	quit <- true
	close(packetsList)
	close(quit)
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

func ChannelControl(packetsList chan []byte, file *pcapgo.Writer, quit chan bool, batchSize int) {

	for {
		select {
		case <- quit:
			WriteFile(packetsList, file, len(packetsList))
			return
		default:
			if len(packetsList) >= batchSize {
				WriteFile(packetsList, file, batchSize)
			}
		}
		time.Sleep(1 * time.Millisecond)
	}
}

func WriteFile(packetsList chan []byte, file *pcapgo.Writer, batchSize int) {
	for i := 0; i < batchSize; i++ {
		packetPayload := <-packetsList
		packet := gopacket.NewPacket(packetPayload, layers.LayerTypeEthernet, gopacket.Default)
		err := file.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		if err != nil {
			panic(err)
		}
	}
}
