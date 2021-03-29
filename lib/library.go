package lib

import (
	"encoding/json"
	"fmt"
	"github.com/RumbleDiscovery/jarm-go"
	"golang.org/x/net/proxy"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"
)

type RelayInfo struct {
	Version          string        `json:"version"`
	BuildRevision    string        `json:"build_revision"`
	RelaysPublished  string        `json:"relays_published"`
	Relays           []Relays      `json:"relays"`
	BridgesPublished string        `json:"bridges_published"`
	Bridges          []interface{} `json:"bridges"`
}
type Relays struct {
	OrAddresses []string `json:"or_addresses"`
}
type Target struct {
	Host string
	Port int
}
type Result struct {
	Target Target
	Hash   string
	Error  error
}

func GetRelays() (*RelayInfo, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", "https://onionoo.torproject.org/details?type=relay&fields=or_addresses", nil)

	if err != nil {
		return nil, err
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)

	if err != nil {
		return nil, err
	}

	var info RelayInfo

	err = json.Unmarshal(body, &info)

	if err != nil {
		return nil, err
	}

	return &info, nil
}

func Fingerprint(t Target, och chan Result) {

	results := []string{}
	for _, probe := range jarm.GetProbes(t.Host, t.Port) {
		dialer := proxy.FromEnvironmentUsing(&net.Dialer{Timeout: time.Second * 30})
		c, err := dialer.Dial("tcp", net.JoinHostPort(t.Host, fmt.Sprintf("%d", t.Port)))
		if err != nil {
			och <- Result{Target: t, Error: err}
			continue
		}

		data := jarm.BuildProbe(probe)
		c.SetWriteDeadline(time.Now().Add(time.Second * 30))
		_, err = c.Write(data)
		if err != nil {
			results = append(results, "")
			c.Close()
			continue
		}

		c.SetReadDeadline(time.Now().Add(time.Second * 30))
		buff := make([]byte, 1484)
		c.Read(buff)
		c.Close()

		ans, err := jarm.ParseServerHello(buff, probe)
		if err != nil {
			results = append(results, "")
			continue
		}

		results = append(results, ans)
	}

	och <- Result{
		Target: t,
		Hash:   jarm.RawHashToFuzzyHash(strings.Join(results, ",")),
	}
}
