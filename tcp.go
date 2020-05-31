package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"os/exec"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/songgao/water"
)

const WSIZE = 50

type sendSequence struct {
	una       uint32
	urgentptr bool
	nxt       uint32
	wl1       uint32
	wl2       uint32
	wnd       uint16
	iss       uint32
}

type recvSequence struct {
	next uint32
	wnd  uint16
	up   bool
	iss  uint32
}

const (
	CLOSED = iota
	SYN_SENT
	SYN_RECV
	ESTABLISHED
	FIN_WAIT1
	FIN_WAIT2
	CLOSE_WAIT
	CLOSING
	LAST_ACK
	TIME_WAIT
	LISTEN
)

/* default goPacketOptions for generating */
var goPacketOptions = gopacket.SerializeOptions{
	FixLengths:       true,
	ComputeChecksums: true,
}

/*
Quad is ... a tuple of IP and ports for
both directions */
type Quad struct {
	Source     uint32
	Dest       uint32
	SourcePort uint16
	DestPort   uint16
}

/*
TCPStream is "one" connection
*/
type TCPStream struct {
	State int
	Send  sendSequence
	Recv  recvSequence
}

/*
NewTCPStream returns
a tcp connection */
func NewTCPStream(Quad Quad) *TCPStream {
	return &TCPStream{
		Recv:  recvSequence{},
		Send:  sendSequence{iss: rand.Uint32()},
		State: CLOSED,
	}
}

func (t *TCPStream) listen() {
	t.State = LISTEN
}

func (t *TCPStream) handlePacket(ip *layers.IPv4, tcp *layers.TCP) (gopacket.SerializeBuffer, error) {
	fmt.Println("State of SYNs", t.Send.una, tcp.Ack, t.Send.nxt)

	if t.State == CLOSED {
		/* send RST */
		t.Recv.iss = tcp.Seq
		t.Recv.next = tcp.Seq + 1

		/* send sequence generation */
		t.Send.iss = rand.Uint32()
		t.Send.una = t.Send.iss
		t.Send.urgentptr = false
		t.Send.wnd = 0

		/* prepare tcp header for send */
		tcpLayerSend := &layers.TCP{SrcPort: tcp.DstPort, DstPort: tcp.SrcPort,
			Seq:    t.Send.iss,
			Ack:    t.Recv.next,
			RST:    true,
			ACK:    true,
			Window: 0,
		}

		/* prepare ip header */
		ipLayerSend := &layers.IPv4{
			SrcIP:    ip.DstIP,
			DstIP:    ip.SrcIP,
			Version:  4,
			Protocol: layers.IPProtocolTCP,
		}

		/* serialize and return buffer */
		buffer := gopacket.NewSerializeBuffer()
		tcpLayerSend.SetNetworkLayerForChecksum(ipLayerSend)

		err := gopacket.SerializeLayers(buffer, goPacketOptions, ipLayerSend, tcpLayerSend)
		if err != nil {
			return nil, err
		}

		t.State = CLOSED
		return buffer, errors.New("Not listening on this socket")
	}

	/* state machine */
	switch t.State {
	case LISTEN:

		if !tcp.SYN {
			return nil, errors.New("No SYN received")
		}

		/* respond with SYN+ACK*/
		t.Recv.wnd = tcp.Window
		t.Recv.iss = tcp.Seq
		t.Recv.next = tcp.Seq + 1

		/* send sequence generation */
		t.Send.iss = rand.Uint32()
		t.Send.una = t.Send.iss
		t.Send.urgentptr = false
		t.Send.wnd = WSIZE

		/* prepare tcp header for send */
		tcpLayerSend := &layers.TCP{SrcPort: tcp.DstPort, DstPort: tcp.SrcPort,
			Seq:    t.Send.iss,
			Ack:    t.Recv.next,
			SYN:    true,
			ACK:    true,
			Window: 2000,
		}

		/* increase next expected sequence size */
		t.Send.nxt = t.Send.iss + 1

		/* prepare ip header */
		ipLayerSend := &layers.IPv4{
			SrcIP:    ip.DstIP,
			DstIP:    ip.SrcIP,
			Version:  4,
			Protocol: layers.IPProtocolTCP,
		}

		/* serialize and return buffer */
		buffer := gopacket.NewSerializeBuffer()
		tcpLayerSend.SetNetworkLayerForChecksum(ipLayerSend)

		err := gopacket.SerializeLayers(buffer, goPacketOptions, ipLayerSend, tcpLayerSend)
		if err != nil {
			return nil, err
		}

		t.State = SYN_RECV
		return buffer, nil
	case SYN_RECV:
		/* FIXME, check for wrappend */
		if (t.Send.una < tcp.Ack) && (tcp.Ack <= t.Send.nxt) {
			t.Send.una = tcp.Ack
			t.State = ESTABLISHED
			return nil, nil
		}
	case ESTABLISHED:
		fmt.Println("Need send/receive")
		return nil, nil
	case SYN_SENT:
		fmt.Println("Client code only")
	}

	return nil, errors.New("Huch?")
}

func main() {
	/* seed the randomizer */
	rand.Seed(time.Now().UnixNano())

	/* set a hash map for managing tcp connections */
	TCPConns := make(map[Quad]*TCPStream)

	/* open, set up and do other things to tun  device */
	tun, err := water.New(water.Config{DeviceType: water.TUN})
	if err != nil {
		log.Fatal(err)
	}
	defer tun.Close()

	log.Println("Opened", tun.Name())

	err = exec.Command("./ips.sh", "version").Run()
	if err != nil {
		log.Fatal(err)
	}

	/* create buffer for reading packets and
	starting the main loop */
	var frame = make([]byte, 1508)
	for {
		n, err := tun.Read(frame)
		if err != nil {
			log.Fatal(err)
		}
		frame = frame[:n]

		packet := gopacket.NewPacket(frame, layers.LayerTypeIPv4, gopacket.Default)
		if packet == nil {
			continue
		}

		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		/* exit early */
		if ipLayer == nil {
			continue
		}
		ip, _ := ipLayer.(*layers.IPv4)

		var tcpLayer gopacket.Layer
		if tcpLayer = packet.Layer(layers.LayerTypeTCP); tcpLayer == nil {
			continue
		}
		tcp, _ := tcpLayer.(*layers.TCP)

		/* Generate a quad of destination and source ips and ports */
		quad := Quad{
			binary.BigEndian.Uint32(ip.SrcIP),
			binary.BigEndian.Uint32(ip.DstIP),
			uint16(tcp.SrcPort),
			uint16(tcp.DstPort),
		}

		/* handlePacket will save the buffer, that we need to write out to */
		var buffer gopacket.SerializeBuffer

		/* Check if our map has tracked this connection already, else create new */
		if _, exists := TCPConns[quad]; !exists {
			TCPConns[quad] = NewTCPStream(quad)
			/* telnet, then auto listening */
			if tcp.DstPort == 23 {
				TCPConns[quad].listen()
			}
		}

		buffer, err = TCPConns[quad].handlePacket(ip, tcp)

		if err != nil {
			log.Println(err)
			continue
		}

		if buffer != nil {
			_, err = tun.Write(buffer.Bytes())
			if err != nil {
				log.Println(err)
			}
		}

		/* GC the connection if closed */
		if TCPConns[quad].State == CLOSED {
			TCPConns[quad] = nil
		}

	}
}
