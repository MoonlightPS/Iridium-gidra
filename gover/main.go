package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"

	"github.com/MoonlightPS/Iridium-gidra/gover/ec2b"
	"github.com/MoonlightPS/Iridium-gidra/gover/gen"
	"github.com/MoonlightPS/Iridium-gidra/gover/proxy"
	"github.com/MoonlightPS/Iridium-gidra/gover/proxy/bypass"
	"github.com/MoonlightPS/Iridium-gidra/gover/utils"
	"github.com/yezihack/colorlog"
	"google.golang.org/protobuf/proto"
)

const HTTP_LST = ":8081"

type serverDesc struct {
	addr *net.UDPAddr
	sock proxy.ProxyInterface
}

type regionRsp struct {
	Content string `json:"content"`
	Sign    string `json:"sign"`
}

var gameServers = map[string]*serverDesc{}
var bypassMode = false

func WaitExit() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
	colorlog.Info("quit")
}

func newUDPBind() (*net.UDPConn, *net.UDPAddr, error) {
	retry := 10
	for retry > 0 {
		retry--
		port := rand.Int()%40000 + 10000
		addr := &net.UDPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: port,
		}
		conn, err := net.ListenUDP("udp", addr)
		if err != nil {
			continue
		}
		conn.LocalAddr()
		return conn, addr, nil
	}
	return nil, nil, errors.New("retry bind local udp exceed max times")
}

func httpGetAll(uri string) ([]byte, error) {
	resp, err := http.Get(uri)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	region := r.Header.Get("url")
	if region == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("error request"))
		return
	}

	colorlog.Info("incoming request to %s", region)
	dispatch := fmt.Sprintf("https://%s/query_cur_region?%s", region, r.URL.RawQuery)
	colorlog.Info("requesting %s", dispatch)
	result, err := httpGetAll(dispatch)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		colorlog.Error("failed request dispatch, err: %+v", err)
		return
	}
	originResp := append(make([]byte, 0, len(result)), result...)

	ver := r.URL.Query().Get("version")
	v2 := strings.Contains(ver, "2.7.5") || strings.Contains(ver, "2.8.") || strings.Contains(ver, "3.")
	keyID := utils.CN_KEY
	if v2 {
		keyID, err = strconv.Atoi(r.URL.Query().Get("key_id"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
			colorlog.Error("failed parse key_id, err: %+v", err)
			return
		}
		resp := &regionRsp{}
		err := json.Unmarshal(result, resp)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
			colorlog.Error("failed unmarshal region, err: %+v", err)
			return
		}
		result, err = base64.StdEncoding.DecodeString(resp.Content)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
			colorlog.Error("failed unmarshal region, err: %+v", err)
			return
		}
		result, err = utils.Decrypt(result, keyID)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
			colorlog.Error("failed decrypt region, err: %+v", err)
			return
		}
	}

	regionInfo := &gen.QueryCurrRegionHttpRsp{}
	err = proto.Unmarshal(result, regionInfo)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		colorlog.Error("failed parse region, err: %+v", err)
		return
	}

	if regionInfo.GetRetcode() == 0 {
		target := &net.UDPAddr{
			IP:   net.ParseIP(regionInfo.GetRegionInfo().GetGateserverIp()),
			Port: int(regionInfo.GetRegionInfo().GetGateserverPort()),
		}
		if bypassMode {
			keyBytes, err := ec2b.Derive(regionInfo.GetClientSecretKey())
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(err.Error()))
				colorlog.Error("generate key error, err: %+v", err)
				return
			}

			key := utils.NewPacketKey()
			key.SetKey(keyBytes)
			sock := proxy.NewBypassSocket(target, key, keyID)
			sock.Start()
			gameServers[target.String()] = &serverDesc{addr: nil, sock: sock}
			colorlog.Info("starting new bypass sniffer on %+v", target)
		} else if s, ok := gameServers[target.String()]; ok {
			regionInfo.GetRegionInfo().GateserverIp = s.addr.IP.String()
			regionInfo.GetRegionInfo().GateserverPort = uint32(s.addr.Port)
		} else {
			conn, addr, err := newUDPBind()
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(err.Error()))
				colorlog.Error("bind udp error, err: %+v", err)
				return
			}

			keyBytes, err := ec2b.Derive(regionInfo.GetClientSecretKey())
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(err.Error()))
				colorlog.Error("generate key error, err: %+v", err)
				return
			}

			key := utils.NewPacketKey()
			key.SetKey(keyBytes)
			sock := proxy.NewKCPSocket(conn, target, key, keyID)
			sock.Start()
			gameServers[target.String()] = &serverDesc{addr: addr, sock: sock}

			regionInfo.GetRegionInfo().GateserverIp = addr.IP.String()
			regionInfo.GetRegionInfo().GateserverPort = uint32(addr.Port)

			colorlog.Info("starting new proxy gate_server on %+v to %+v", addr, target)
		}
	}

	if bypassMode {
		result = originResp
	} else {
		result, err = proto.Marshal(regionInfo)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
			colorlog.Error("failed marshal region, err: %+v", err)
			return
		}
	}
	if v2 {
		if !bypassMode {
			var sign []byte
			result, sign, err = utils.EncryptWithSign(result, keyID)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(err.Error()))
				colorlog.Error("failed enc region, err: %+v", err)
				return
			}
			resp := &regionRsp{
				Content: base64.StdEncoding.EncodeToString(result),
				Sign:    base64.StdEncoding.EncodeToString(sign),
			}
			result, err = json.Marshal(resp)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(err.Error()))
				colorlog.Error("failed marshal region json, err: %+v", err)
				return
			}
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(result)))
		w.Header().Set("Content-Type", "application/json")
		w.Write(result)
	} else {
		w.Write([]byte(base64.StdEncoding.EncodeToString(result)))
	}
}

func main() {
	err := utils.InitKey("../keys")
	if err != nil {
		panic(err)
	}
	for _, arg := range os.Args {
		if arg == "--bypass" {
			bypassMode = true
			colorlog.Warn("service is running at bypass mode")
		}
	}
	if bypassMode {
		err = bypass.StartBypassService()
		if err != nil {
			panic(err)
		}
	}
	http.HandleFunc("/query_cur_region", indexHandler)
	go http.ListenAndServe(HTTP_LST, nil)
	colorlog.Info("running...")
	WaitExit()
	for _, v := range gameServers {
		v.sock.Stop()
	}
	bypass.StopBypassService()
}
