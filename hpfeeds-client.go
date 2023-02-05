// based on https://github.com/hpfeeds/go-hpfeeds 
//   (2017) which was very broken
// By default, just dumps out the json payload from hpfeeds
// Reworked by Noah Axon in 2013
// ax0n@h-i-r.net | IG: @4x0nn | Twitter: @ax0n
package main

import (
	"os"
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strconv"
)

type Message struct {
	Name    string
	Payload []byte
}

type rawMsgHeader struct {
	Length uint32
	Opcode uint8
}

const (
	opcode_err  = 0
	opcode_info = 1
	opcode_auth = 2
	opcode_pub  = 3
	opcode_sub  = 4
)

type Hpfeeds struct {
	LocalAddr net.TCPAddr

	conn  *net.TCPConn
	host  string
	port  int
	ident string
	auth  string

	authSent     chan bool
	Disconnected chan error

	channel map[string]chan Message

	Log bool
}

func NewHpfeeds(ident, auth, host string, port int) Hpfeeds {
	return Hpfeeds{
		host:  host,
		port:  port,
		ident: ident,
		auth:  auth,

		authSent:     make(chan bool),
		Disconnected: make(chan error, 1),

		channel: make(map[string]chan Message),
	}
}

func (hp *Hpfeeds) Connect() error {
	hp.clearDisconnected()

	addr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%d", hp.host, hp.port))
	if err != nil {
		return err
	}

	conn, err := net.DialTCP("tcp", &hp.LocalAddr, addr)
	if err != nil {
		return err
	}

	hp.conn = conn
	go hp.recvLoop()
	<-hp.authSent

	select {
	case err = <-hp.Disconnected:
		return err
	default:
	}

	return nil
}

func (hp *Hpfeeds) clearDisconnected() {
	select {
	case <-hp.Disconnected:
	default:
	}
}

func (hp *Hpfeeds) setDisconnected(err error) {
	hp.clearDisconnected()
	hp.Disconnected <- err
}

// Close closes the hpfeeds connection and signals the Disconnected channel.
func (hp *Hpfeeds) Close() {
	hp.close(nil)
}

func (hp *Hpfeeds) close(err error) {
	hp.conn.Close()
	hp.setDisconnected(err)
	select {
	case hp.authSent <- false:
	default:
	}
	hp.conn = nil
}

func (hp *Hpfeeds) recvLoop() {
	buf := []byte{}
	for hp.conn != nil {
		readbuf := make([]byte, 1024)

		n, err := hp.conn.Read(readbuf)
		if err != nil {
			hp.log("Read(): %s\n", err)
			hp.close(err)
			return
		}

		buf = append(buf, readbuf[:n]...)

		for len(buf) > 5 {
			hdr := rawMsgHeader{}
			hdr.Length = binary.BigEndian.Uint32(buf[0:4])
			hdr.Opcode = uint8(buf[4])
			if len(buf) < int(hdr.Length) {
				break
			}
			data := buf[5:int(hdr.Length)]
			hp.parse(hdr.Opcode, data)
			buf = buf[int(hdr.Length):]
		}
	}
}

func (hp *Hpfeeds) parse(opcode uint8, data []byte) {
	switch opcode {
	case opcode_info:
		hp.sendAuth(data[(1 + uint8(data[0])):])
		hp.authSent <- true
	case opcode_err:
		hp.log("Received error from server: %s\n", string(data))
	case opcode_pub:
		len1 := uint8(data[0])
		name := string(data[1:(1 + len1)])
		len2 := uint8(data[1+len1])
		channel := string(data[(1 + len1 + 1):(1 + len1 + 1 + len2)])
		payload := data[1+len1+1+len2:]
		hp.handlePub(name, channel, payload)
	default:
		hp.log("Received message with unknown type %d\n", opcode)
	}
}

func (hp *Hpfeeds) handlePub(name string, channelName string, payload []byte) {
	channel, ok := hp.channel[channelName]
	if !ok {
		hp.log("Received message on unsubscribed channel %s\n", channelName)
		return
	}
	channel <- Message{name, payload}
}

func writeField(buf *bytes.Buffer, data []byte) {
	buf.WriteByte(byte(len(data)))
	buf.Write(data)
}

func (hp *Hpfeeds) sendRawMsg(opcode uint8, data []byte) {
	buf := make([]byte, 5)
	binary.BigEndian.PutUint32(buf, uint32(5+len(data)))
	buf[4] = byte(opcode)
	buf = append(buf, data...)
	for len(buf) > 0 {
		n, err := hp.conn.Write(buf)
		if err != nil {
			hp.log("Write(): %s\n", err)
			hp.close(err)
			return
		}
		buf = buf[n:]
	}
}

func (hp *Hpfeeds) sendAuth(nonce []byte) {
	buf := new(bytes.Buffer)
	mac := sha1.New()
	mac.Write(nonce)
	mac.Write([]byte(hp.auth))
	writeField(buf, []byte(hp.ident))
	buf.Write(mac.Sum(nil))
	hp.sendRawMsg(opcode_auth, buf.Bytes())
}

func (hp *Hpfeeds) sendSub(channelName string) {
	buf := new(bytes.Buffer)
	writeField(buf, []byte(hp.ident))
	buf.Write([]byte(channelName))
	hp.sendRawMsg(opcode_sub, buf.Bytes())
}

func (hp *Hpfeeds) sendPub(channelName string, payload []byte) {
	buf := new(bytes.Buffer)
	writeField(buf, []byte(hp.ident))
	writeField(buf, []byte(channelName))
	buf.Write(payload)
	hp.sendRawMsg(opcode_pub, buf.Bytes())
}

func (hp *Hpfeeds) Subscribe(channelName string, channel chan Message) {
	hp.channel[channelName] = channel
	hp.sendSub(channelName)
}

func (hp *Hpfeeds) Publish(channelName string, channel chan []byte) {
	go func() {
		for payload := range channel {
			if hp.conn == nil {
				return
			}
			hp.sendPub(channelName, payload)
		}
	}()
}

func (hp *Hpfeeds) log(format string, v ...interface{}) {
	if hp.Log {
		log.Printf(format, v...)
	}
}


func main() {
	if len(os.Args) != 6 {
		fmt.Printf("Usage: %s <ident> <authkey> <server> <port> <channel> (only one channel supported for now)\n", os.Args[0])
		os.Exit(0)
	}

	ident := os.Args[1]
	auth := os.Args[2]
	host := os.Args[3]
	port,err := strconv.Atoi(os.Args[4])
	channel := os.Args[5]
	if err != nil {
	  fmt.Println("Port must be an integer")
	  os.Exit(1)
	}
	hp := NewHpfeeds(ident, auth, host, port)
	hp.Log = true
	hp.Connect()

	firehose := make(chan Message)
	hp.Subscribe(channel, firehose)
	go func() {
		for foo := range firehose {
			// If you really want the HPFeeds honeypot id, uncomment. 
			// fmt.Println(foo.Name, string(foo.Payload))
			// I just want the json payload so we can do fun stuff with jq etc
			fmt.Println(string(foo.Payload))
		}
	}()

	// Wait for disconnect
	<-hp.Disconnected
}
