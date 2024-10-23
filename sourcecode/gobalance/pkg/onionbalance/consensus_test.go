package onionbalance

import "testing"

func TestParseIPv6AddressAndPort(t *testing.T) {
	_, getStatus, err := ParseRawStatus(`r Karlstad0 m5TNC3uAV+ryG6fwI7ehyMqc5kU f1g9KQhgS0r6+H/7dzAJOpi6lG8 2014-12-08 06:57:54 193.11.166.194 9000 80
a [2002:470:6e:80d::2]:22
s Fast Guard HSDir Running Stable V2Dir Valid
v Tor 0.2.4.23
w Bandwidth=2670
p reject 1-65535`)
	if err != nil {
		t.Error(err)
	}

	if getStatus().Address.IPv6Address.String() != "2002:470:6e:80d::2" {
		t.Error("Failes to Parse IPv6 Address correctly.")
	}

	if getStatus().Address.IPv6ORPort != StringToPort("22") {
		t.Error("Failes to Parse IPv6 Port correctly.")
	}
}
