package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
)

type DnsHeader struct {
	ID      uint16
	Flags   uint16
	Qdcount uint16
	Ancount uint16
	Nscount uint16
	Arcount uint16
}

type DnsQuestion struct {
	Name  string
	Type  uint16
	Class uint16
}

type DnsRRF struct {
	Name  string
	Type  uint16
	Class uint16
	Tll   uint32
	RdLen uint16
	Rdata string
}

var typeNames = map[uint16]string{
	1:  "A",
	2:  "NS",
	5:  "CNAME",
	6:  "SOA",
	12: "PTR",
	15: "MX",
	16: "TXT",
	28: "AAAA",
	33: "SRV",
}

var classNames = map[uint16]string{
	1:   "IN",
	2:   "CS",
	3:   "CH",
	4:   "HS",
	254: "NONE",
}

func (q DnsQuestion) getType() string {
	if name, ok := typeNames[q.Type]; ok {
		return name
	}
	return fmt.Sprintf("Unknown Type %d", q.Type)
}

func (q DnsQuestion) getClass() string {
	if name, ok := classNames[q.Class]; ok {
		return name
	}
	return fmt.Sprintf("Unknown Class %d", q.Class)
}

func deserializeHeader(data []byte) (DnsHeader, error) {
	if len(data) < 12 {

	}

	var header DnsHeader

	header.ID = binary.BigEndian.Uint16(data[0:2])
	header.Flags = binary.BigEndian.Uint16(data[2:4])
	header.Qdcount = binary.BigEndian.Uint16(data[4:6])
	header.Ancount = binary.BigEndian.Uint16(data[6:8])
	header.Nscount = binary.BigEndian.Uint16(data[8:10])
	header.Arcount = binary.BigEndian.Uint16(data[10:12])
	return header, nil
}

func serializeHeader(header DnsHeader) ([]byte, error) {

	buffer := make([]byte, 12)

	binary.BigEndian.PutUint16(buffer[0:2], header.ID)
	binary.BigEndian.PutUint16(buffer[2:4], header.Flags)
	binary.BigEndian.PutUint16(buffer[4:6], header.Qdcount)
	binary.BigEndian.PutUint16(buffer[6:8], header.Ancount)
	binary.BigEndian.PutUint16(buffer[8:10], header.Nscount)
	binary.BigEndian.PutUint16(buffer[10:12], header.Arcount)
	return buffer, nil

}

func deserializeQuestion(data []byte) (DnsQuestion, error) {
	index := 1
	last := int(1 + data[0])

	var buff []byte

	for {

		buff = append(buff, data[index:last]...)

		if data[last] == 0x00 {
			break
		}
		buff = append(buff, '.')

		index = last + 1
		last = index + int(data[last])
	}

	var question DnsQuestion
	question.Name = string(buff)
	question.Class = binary.BigEndian.Uint16(data[last+1 : last+3])
	question.Type = binary.BigEndian.Uint16(data[last+3 : last+5])

	return question, nil
}

func serializeQuestion(question DnsQuestion) ([]byte, error) {

	buff := make([]byte, 0, 10)
	parts := strings.SplitSeq(question.Name, ".")

	for v := range parts {
		len_s := len(v)
		buff = append(buff, byte(len_s))
		buff = append(buff, []byte(v)...)
	}
	buff = append(buff, 0x00)

	var tmp = make([]byte, 2)

	binary.BigEndian.PutUint16(tmp, question.Type)
	buff = append(buff, tmp...)

	binary.BigEndian.PutUint16(tmp, question.Class)
	buff = append(buff, tmp...)

	return buff, nil

}

func deserializeAswer(data []byte, init_position int) (DnsRRF, error) {
	var rrf DnsRRF
	var last int
	var buff []byte

	if data[init_position] == 192 {
		text_pos := data[init_position+1]
		_, buff = extractLabel(data[text_pos:])
		last = init_position + 1

	} else {

		last, buff = extractLabel(data)
	}

	rrf.Name = string(buff)
	rrf.Type = binary.BigEndian.Uint16(data[last+1 : last+3])
	rrf.Class = binary.BigEndian.Uint16(data[last+3 : last+5])
	rrf.Tll = binary.BigEndian.Uint32(data[last+5 : last+9])
	rrf.RdLen = binary.BigEndian.Uint16(data[last+9 : last+11])
	var numbers []string

	for _, val := range data[last+11:] {
		numbers = append(numbers, fmt.Sprintf("%d", val))
	}

	rrf.Rdata = strings.Join(numbers, ".")

	return rrf, nil

}

func extractLabel(data []byte) (int, []byte) {
	index := 1
	last := int(1 + data[0])

	var buff []byte

	for {

		buff = append(buff, data[index:last]...)

		if data[last] == 0x00 {
			break
		}
		buff = append(buff, '.')

		index = last + 1
		last = index + int(data[last])
	}
	return last, buff
}

func deserializeMessage(data []byte) (DnsHeader, []DnsQuestion, []DnsRRF, error) {
	if len(data) < 12 {
		return DnsHeader{}, nil, nil, fmt.Errorf("data too short")
	}

	header, err := deserializeHeader(data[:12])
	if err != nil {
		return DnsHeader{}, nil, nil, err
	}

	res := 0b000000001111 & header.Flags
	if res != 0b000000000000 {
		return DnsHeader{}, nil, nil, fmt.Errorf("error in flags: %b", res)
	}

	offset := 12
	questions := make([]DnsQuestion, header.Qdcount)
	answers := make([]DnsRRF, header.Ancount)

	for i := 0; i < int(header.Qdcount); i++ {
		q, err := deserializeQuestion(data[offset:])
		if err != nil {
			return DnsHeader{}, nil, nil, err
		}
		questions[i] = q

		// mover offset sobre el nombre (labels + terminador 0)
		pos := offset
		for data[pos] != 0 {
			pos += int(data[pos]) + 1
		}
		// +1 por el 0x00, +2 por Type, +2 por Class
		offset = pos + 1 + 2 + 2
	}

	// leer múltiples respuestas
	for i := 0; i < int(header.Ancount); i++ {
		ans, err := deserializeAswer(data, offset)
		if err != nil {
			return DnsHeader{}, nil, nil, err
		}
		answers[i] = ans

		// avanzar offset tras este RRF
		pos := offset
		// nombre (puede ser puntero)
		if data[pos]&0xC0 == 0xC0 {
			pos += 2
		} else {
			for data[pos] != 0x00 {
				pos += int(data[pos]) + 1
			}
			pos++ // byte 0x00 final
		}
		// Type(2) + Class(2) + TTL(4) + RDLength(2)
		pos += 2 + 2 + 4
		rdlen := int(binary.BigEndian.Uint16(data[pos-2 : pos]))
		// RDATA
		pos += rdlen
		offset = pos
	}

	return header, questions, answers, nil
}

func randomId() (uint16, error) {
	var b [2]byte
	_, err := rand.Read(b[:])
	if err != nil {
		return 0, fmt.Errorf("error generating random ID: %w", err)
	}
	return binary.BigEndian.Uint16(b[:]), nil
}

func main() {

	if len(os.Args) < 2 {
		fmt.Println("Usage: ./main <domain>")
		return
	}

	name := os.Args[1]

	id, err := randomId()

	if err != nil {
		fmt.Println("Error generating random ID:", err)
		return
	}

	header, err := serializeHeader(DnsHeader{
		ID:      id,
		Flags:   0b0000000000000000,
		Qdcount: 1,
		Ancount: 0,
		Nscount: 0,
		Arcount: 0,
	})

	question, err := serializeQuestion(DnsQuestion{
		Name:  name,
		Type:  1,
		Class: 1,
	})

	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{
		IP:   net.ParseIP("8.8.8.8"),
		Port: 53,
	})

	if err != nil {
		fmt.Println("Error connecting:", err)
		return
	}
	defer conn.Close()
	fmt.Println("Connected to", conn.RemoteAddr())

	buff := append(header, question...)

	n, err := conn.Write(buff)
	if err != nil {
		fmt.Println("Error al enviar bytes:", err)
	}
	fmt.Println("escrito: ", n, " bytes")
	var resp [512]byte

	n, err = conn.Read(resp[:])
	if err != nil {
		fmt.Println("Error leyendo respuesta:", err)
		return
	}

	h, q, a, err := deserializeMessage(resp[:n])
	if err != nil {
		fmt.Println("Error deserializando mensaje:", err)
		return
	}
	fmt.Println("Header:", h)
	fmt.Println("Question:", q)
	fmt.Println("Answer:", a)
}
