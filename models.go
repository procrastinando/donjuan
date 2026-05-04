package main

type AppData struct {
	Settings struct {
		IPv6          bool   `json:"ipv6"`
		FakeIP        bool   `json:"fakeIP"`
		DNSLeaks      bool   `json:"dnsLeaks"`
		RouteOnly     bool   `json:"routeOnly"`
		AllowInsecure bool   `json:"allowInsecure"`
		TUN           bool   `json:"tun"`
		AutoRedirect  bool   `json:"autoRedirect"`
		Sniffing      bool   `json:"sniffing"`
		LocalNetwork  bool   `json:"localNetwork"`
		SaveLogs      bool   `json:"saveLogs"`
		Language      string `json:"language"`
	} `json:"settings"`
	Port    int `json:"port"`
	Routing struct {
		CustomRules  []CustomRule              `json:"customRules"`
		GeositeRules map[string]string         `json:"geositeRules"` // category -> "proxy"|"direct"|"block"
	} `json:"routing"`
	Nodes         []Node         `json:"nodes"`
	Subscriptions []Subscription `json:"subscriptions"`
	SelectedNode  string         `json:"selectedNode"`
	ProxyRunning  bool           `json:"proxyRunning"`
}

type Subscription struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	URL     string `json:"url"`
	Details string `json:"details"`
	Nodes   []Node `json:"nodes"`
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
