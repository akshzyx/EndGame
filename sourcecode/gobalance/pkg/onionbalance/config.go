package onionbalance

import "encoding/json"

type InstanceConfig struct {
	Address string
}

type ServiceConfig struct {
	Key       string
	Instances []InstanceConfig
}

type ConfigData struct {
	Services []ServiceConfig
}

func (c ConfigData) String() string {
	by, _ := json.Marshal(c)
	return string(by)
}
