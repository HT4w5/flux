package dto

import (
	"net/netip"
	"strconv"
	"time"

	"github.com/docker/go-units"
)

// Request entry
type Request struct {
	Time     int64
	Client   netip.Addr
	Server   netip.Addr
	Method   string
	URL      string
	Host     string
	Agent    string
	Status   int
	Sent     int64
	Duration time.Duration
}

func (r *Request) String() string {
	return "Request{" +
		"time: " + time.Unix(r.Time, 0).Format(time.RFC3339) +
		", client: " + r.Client.String() +
		", server: " + r.Server.String() +
		", method: " + r.Method +
		", url: " + r.URL +
		", host: " + r.Host +
		", agent: " + r.Agent +
		", status: " + strconv.Itoa(r.Status) +
		", sent: " + units.HumanSize(float64(r.Sent)) +
		", duration: " + r.Duration.String() +
		"}"
}
