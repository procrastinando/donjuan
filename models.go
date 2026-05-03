package main

type AppData struct {
	Settings struct {
		IPv6          bool   `json:"ipv6"`
		FakeIP        bool   `json:"fakeIP"`
		DNSLeaks      bool   `json:"dnsLeaks"`
		RouteOnly     bool   `json:"routeOnly"`
		AllowInsecure bool   `json:"allowInsecure"`
		TUN           bool   `json:"tun"`
		Sniffing      bool   `json:"sniffing"`
		LocalNetwork  bool   `json:"localNetwork"`
		SaveLogs      bool   `json:"saveLogs"`
		Language      string `json:"language"`
	} `json:"settings"`
	Port    int `json:"port"`
	Routing struct {
		DirectCN     bool                      `json:"directCN"`
		DirectRU     bool                      `json:"directRU"`
		DirectIR     bool                      `json:"directIR"`
		DirectCU     bool                      `json:"directCU"`
		DirectVN     bool                      `json:"directVN"`
		DirectBR     bool                      `json:"directBR"`
		DirectUS     bool                      `json:"directUS"`
		CustomRules  []CustomRule              `json:"customRules"`
		GeositeRules map[string]string         `json:"geositeRules"` // category -> "proxy"|"direct"|"block"
	} `json:"routing"`
	Nodes        []Node `json:"nodes"`
	SelectedNode string `json:"selectedNode"`
}

type CustomRule struct {
	ID     string `json:"id"`
	Type   string `json:"type"`   // Domain, IP, Keyword
	Value  string `json:"value"`
	Action string `json:"action"` // Proxy, Direct, Block
	Source string `json:"source"` // optional source IP
}

type Node struct {
	ID      string `json:"id"`
	Remarks string `json:"remarks"`
	Type    string `json:"type"` // vless, hy2
	URL     string `json:"url"`  // Original share link
	Domain  string `json:"domain"`
	Latency int    `json:"latency"` // ms
}
