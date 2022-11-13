package utils

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"sync/atomic"
	"time"

	"github.com/yezihack/colorlog"
	"google.golang.org/protobuf/encoding/protojson"
)

type dumpPacket struct {
	Index     int         `json:"index"`
	PacketId  int         `json:"packetId"`
	ProtoName string      `json:"protoName"`
	Source    string      `json:"source"`
	Time      float64     `json:"time"`
	Object    interface{} `json:"object"`
}

type recordPacket struct {
	idx    int
	cmd    int
	source int
	time   float64
	packet []byte
}

type Recorder struct {
	i       int32
	queue   *Queue[*recordPacket]
	handler *PacketHandler
	packets []*dumpPacket
	pjson   *protojson.MarshalOptions
}

const (
	SOURCE_CLIENT = 0
	SOURCE_SERVER = 1
)

func SourceDesc(source int) string {
	switch source {
	case SOURCE_CLIENT:
		return "Client"
	case SOURCE_SERVER:
		return "Server"
	}
	return ""
}

func (r *Recorder) Stop() {
	r.queue.Close()
}

func (r *Recorder) save() {
	content, err := json.MarshalIndent(r.packets, "", "  ")
	if err != nil {
		colorlog.Warn("marshaling records failed, err: %+v", err)
		return
	}
	fileName := fmt.Sprintf("log_%s_%d.json", time.Now().Format("2006_01_02_15_04_05"), rand.Int()%10000)
	os.WriteFile(fileName, content, 0644)
	colorlog.Info("log write to %s, with %d packet(s)", fileName, len(r.packets))
}

func (r *Recorder) Record(packet []byte, source, cmd int) {
	data := make([]byte, len(packet))
	copy(data, packet)
	r.queue.Enqueue(&recordPacket{
		idx:    int(atomic.AddInt32(&r.i, 1)),
		cmd:    cmd,
		source: source,
		time:   float64(time.Now().UnixNano()) / float64(time.Second),
		packet: data,
	})
}

func (r *Recorder) Start() {
	go func() {
		parser := r.handler
		for {
			data := r.queue.Dequeue()
			if data == nil {
				break
			}
			// process data
			d, err := parser.Parse(data.packet)
			if err != nil {
				colorlog.Warn("parse packet data failed, err: %+v", err)
				continue
			}

			protoName := GetCMDDescription(data.cmd)

			body := map[string]interface{}{}
			if d.Body != nil {
				jsonBytes, err := r.pjson.Marshal(d.Body)
				if err != nil {
					colorlog.Warn("marshal packet failed, idx: %d, proto: %s, err: %+v", data.idx, protoName, err)
					continue
				}

				err = json.Unmarshal(jsonBytes, &body)
				if err != nil {
					colorlog.Warn("unmarshal json-packet failed, idx: %d, proto: %s, err: %+v", data.idx, protoName, err)
					continue
				}
			}

			pack := &dumpPacket{
				Index:     data.idx,
				PacketId:  data.cmd,
				ProtoName: protoName,
				Source:    SourceDesc(data.source),
				Time:      data.time,
				Object:    body,
			}
			colorlog.Info("Record %s -> %s %5d: %s", pack.Source, SourceDesc(data.source^1), data.cmd, pack.ProtoName)
			r.packets = append(r.packets, pack)
		}
		r.save()
		colorlog.Warn("recorder quit")
	}()
}

func NewRecorder(cap int, handler *PacketHandler) *Recorder {
	return &Recorder{
		i:       -1,
		queue:   NewQueue[*recordPacket](cap),
		handler: handler,
		pjson:   &protojson.MarshalOptions{},
	}
}
