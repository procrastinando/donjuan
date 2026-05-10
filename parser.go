package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
)

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func generateSingboxConfig(data AppData, selectedNodeID string) ([]byte, error) {
	config := make(map[string]interface{})

	// Log
	config["log"] = map[string]interface{}{
		"level":     "info",
		"timestamp": true,
	}

	remoteDNS := map[string]interface{}{
		"tag":    "remote-dns",
		"type":   "tls",
		"server": "8.8.8.8",
	}
	directDNS := map[string]interface{}{
		"tag":    "direct-dns",
		"type":   "https",
		"server": "223.5.5.5",
	}
	
	servers := []interface{}{remoteDNS, directDNS}

	dns := map[string]interface{}{
		"servers":           servers,
		"independent_cache": true,
		"strategy":          "ipv4_only",
	}
	if data.Settings.IPv6 {
		dns["strategy"] = "prefer_ipv4"
	}
	if data.Settings.FakeIP {
		dns["servers"] = append(dns["servers"].([]interface{}), map[string]interface{}{
			"tag":         "fakeip-dns",
			"type":        "fakeip",
			"inet4_range": "198.18.0.0/15",
			"inet6_range": "fc00::/18",
		})
		dns["rules"] = []interface{}{
			map[string]interface{}{
				"query_type": []string{"A", "AAAA"},
				"server":     "fakeip-dns",
			},
		}
	}

	// Collect domain names from proxy servers for DNS rules
	var proxyServerDomains []string
	for _, node := range allNodes(data) {
		u, err := url.Parse(node.URL)
		if err == nil && u.Hostname() != "" && net.ParseIP(u.Hostname()) == nil {
			proxyServerDomains = append(proxyServerDomains, u.Hostname())
		}
	}
	// Add proxy server IPs/hostnames to direct routing (prevents TUN routing loop)
	var dnsRules []interface{}
	if len(proxyServerDomains) > 0 {
		dnsRules = append(dnsRules, map[string]interface{}{
			"domain_suffix": proxyServerDomains,
			"server":        "direct-dns",
		})
	}

	subnet := data.Settings.ClientSubnet
	if subnet == "" {
		subnet = "114.114.114.114/24"
	}

	hasCNRules := fileExists("/etc/donjuan/geosite-geolocation-cn.srs") && fileExists("/etc/donjuan/geosite-geolocation-!cn.srs") && fileExists("/etc/donjuan/geoip-cn.srs")

	if hasCNRules {
		// Documentation standard rules for DNS
		dnsRules = append(dnsRules, map[string]interface{}{
			"rule_set": "geosite-geolocation-cn",
			"server":   "direct-dns",
		})

		leakRule := map[string]interface{}{
			"type": "logical",
			"mode": "and",
			"rules": []interface{}{
				map[string]interface{}{"rule_set": "geosite-geolocation-!cn", "invert": true},
				map[string]interface{}{"rule_set": "geoip-cn"},
			},
		}
		if data.Settings.DNSLeaks {
			// Slower, secure
			leakRule["server"] = "remote-dns"
			leakRule["client_subnet"] = subnet
		} else {
			// Faster, leaks
			leakRule["server"] = "direct-dns"
		}
		dnsRules = append(dnsRules, leakRule)
	} else {
		// Fallback if rule sets are not downloaded
		fallbackRule := map[string]interface{}{}
		if data.Settings.DNSLeaks {
			fallbackRule["server"] = "remote-dns"
			fallbackRule["client_subnet"] = subnet
		} else {
			fallbackRule["server"] = "direct-dns"
		}
		dnsRules = append(dnsRules, fallbackRule)
	}

	if dns["rules"] != nil {
		dns["rules"] = append(dns["rules"].([]interface{}), dnsRules...)
	} else {
		dns["rules"] = dnsRules
	}

	config["dns"] = dns

	// Inbounds
	inbounds := []interface{}{}
	if !data.Settings.RouteOnly {
		if data.Settings.TUN {
			tunInbound := map[string]interface{}{
				"type":         "tun",
				"tag":          "tun-in",
				"address":      []string{"172.19.0.1/30"},
				"auto_route":   true,
				"strict_route": true,
			}
			if data.Settings.AutoRedirect {
				tunInbound["auto_redirect"] = true
			}
			if data.Settings.IPv6 {
				tunInbound["address"] = []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"}
			}
			inbounds = append(inbounds, tunInbound)
		}
	}
	config["inbounds"] = inbounds

	// Outbounds
	var outbounds []interface{}
	var proxyTags []string

	for _, node := range allNodes(data) {
		outbound, err := parseNodeURL(node.URL, data.Settings.AllowInsecure)
		if err != nil {
			addLog(fmt.Sprintf("WARN: Skipping node %s (%s): %v", node.ID, node.Type, err))
			continue
		}
		if outbound != nil {
			tag := fmt.Sprintf("proxy-%s", node.ID)
			outbound["tag"] = tag
			outbounds = append(outbounds, outbound)
			proxyTags = append(proxyTags, tag)
		}
	}

	proxyTagsWithDirect := append([]string{}, proxyTags...)
	proxyTagsWithDirect = append(proxyTagsWithDirect, "direct")

	if len(proxyTags) > 0 {
		outbounds = append([]interface{}{
			map[string]interface{}{
				"type":      "selector",
				"tag":       "proxy",
				"outbounds": proxyTagsWithDirect,
			},
			map[string]interface{}{
				"type":                        "urltest",
				"tag":                         "auto",
				"outbounds":                   proxyTagsWithDirect,
				"url":                         "https://www.gstatic.com/generate_204",
				"interval":                    "1m",
				"tolerance":                   50,
				"interrupt_exist_connections": true,
			},
		}, outbounds...)
	} else {
		outbounds = append(outbounds, map[string]interface{}{
			"type":      "selector",
			"tag":       "proxy",
			"outbounds": []string{"direct"},
		})
	}

	outbounds = append(outbounds, map[string]interface{}{
		"type": "direct",
		"tag":  "direct",
	})
	outbounds = append(outbounds, map[string]interface{}{
		"type": "block",
		"tag":  "block",
	})

	config["outbounds"] = outbounds

	config["experimental"] = map[string]interface{}{
		"clash_api": map[string]interface{}{
			"external_controller": "127.0.0.1:9090",
			"secret":              "",
		},
	}

	// Route
	route := map[string]interface{}{
		"default_domain_resolver": "direct-dns",
		"auto_detect_interface":   true,
	}
	var rules []interface{}
	if data.Settings.Sniffing {
		rules = append(rules, map[string]interface{}{
			"action": "sniff",
		})
	}
	rules = append(rules, map[string]interface{}{
		"protocol": "dns",
		"action":   "hijack-dns",
	})
	rules = append(rules, map[string]interface{}{
		"ip_cidr":  []string{"223.5.5.5/32"},
		"outbound": "direct",
	})
	if data.Settings.LocalNetwork {
		rules = append(rules, map[string]interface{}{
			"ip_is_private": true,
			"outbound":      "direct",
		})
	}

// Add proxy server IPs/hostnames to direct routing (prevents TUN routing loop)
	seenHosts := make(map[string]bool)
	for _, node := range allNodes(data) {
		u, err := url.Parse(node.URL)
		if err != nil || u.Hostname() == "" {
			continue
		}
		host := u.Hostname()
		if seenHosts[host] {
			continue
		}
		seenHosts[host] = true
		if net.ParseIP(host) != nil {
			rules = append(rules, map[string]interface{}{
				"ip_cidr":  []string{host + "/32"},
				"outbound": "direct",
			})
		} else {
			rules = append(rules, map[string]interface{}{
				"domain_suffix": []string{host},
				"outbound":      "direct",
			})
		}
	}

	// Custom rules
	for _, cr := range data.Routing.CustomRules {
		rule := map[string]interface{}{
			"outbound": strings.ToLower(cr.Action),
		}
		switch cr.Type {
		case "Domain":
			rule["domain_suffix"] = []string{cr.Value}
		case "IP":
			rule["ip_cidr"] = []string{cr.Value}
		case "Keyword":
			rule["domain_keyword"] = []string{cr.Value}
		}
		if cr.Source != "" {
			rule["source_ip_cidr"] = []string{cr.Source}
		}
		rules = append(rules, rule)
	}

	// Geosite/GeoIP direct routing rules
	var ruleSets []interface{}
	
	if hasCNRules {
		ruleSets = append(ruleSets, map[string]interface{}{
			"type":   "local",
			"tag":    "geosite-geolocation-cn",
			"format": "binary",
			"path":   "/etc/donjuan/geosite-geolocation-cn.srs",
		}, map[string]interface{}{
			"type":   "local",
			"tag":    "geosite-geolocation-!cn",
			"format": "binary",
			"path":   "/etc/donjuan/geosite-geolocation-!cn.srs",
		}, map[string]interface{}{
			"type":   "local",
			"tag":    "geoip-cn",
			"format": "binary",
			"path":   "/etc/donjuan/geoip-cn.srs",
		})
	}

	for key, action := range data.Routing.GeositeRules {
		action = strings.ToLower(action)
		if action == "direct" || action == "block" {
			geositeFile := fmt.Sprintf("/etc/donjuan/geosite-%s.srs", key)
			if fileExists(geositeFile) {
				tag := "geosite-" + key
				rules = append(rules, map[string]interface{}{
					"rule_set": tag,
					"outbound": action,
				})
				ruleSets = append(ruleSets, map[string]interface{}{
					"type":   "local",
					"tag":    tag,
					"format": "binary",
					"path":   geositeFile,
				})
			}
		}
	}

	if len(ruleSets) > 0 {
		route["rule_set"] = ruleSets
	}

	// Default catch-all outbound (must be LAST)
	if selectedNodeID == "auto" {
		rules = append(rules, map[string]interface{}{
			"outbound": "auto",
		})
	} else if selectedNodeID != "" {
		rules = append(rules, map[string]interface{}{
			"outbound": fmt.Sprintf("proxy-%s", selectedNodeID),
		})
	} else {
		rules = append(rules, map[string]interface{}{
			"outbound": "proxy",
		})
	}

	route["rules"] = rules
	config["route"] = route

	return json.MarshalIndent(config, "", "  ")
}

func parseNodeURL(rawURL string, allowInsecure bool) (map[string]interface{}, error) {
	if strings.HasPrefix(rawURL, "vless://") {
		return parseVLESS(rawURL, allowInsecure)
	} else if strings.HasPrefix(rawURL, "hy2://") || strings.HasPrefix(rawURL, "hysteria2://") {
		return parseHY2(rawURL, allowInsecure)
	} else if strings.HasPrefix(rawURL, "trojan://") {
		return parseTrojan(rawURL, allowInsecure)
	}
	return nil, fmt.Errorf("unsupported protocol")
}

func parseTLS(query url.Values, allowInsecure bool) map[string]interface{} {
	security := query.Get("security")
	if security != "tls" && security != "reality" {
		return nil
	}
	tls := map[string]interface{}{
		"enabled":  true,
		"insecure": allowInsecure,
	}
	if sni := query.Get("sni"); sni != "" {
		tls["server_name"] = sni
	}
	if alpn := query.Get("alpn"); alpn != "" {
		tls["alpn"] = strings.Split(alpn, ",")
	}
	if fp := query.Get("fp"); fp != "" {
		tls["utls"] = map[string]interface{}{
			"enabled":     true,
			"fingerprint": fp,
		}
	}
	if security == "reality" {
		tls["reality"] = map[string]interface{}{
			"enabled":    true,
			"public_key": query.Get("pbk"),
			"short_id":   query.Get("sid"),
		}
	}
	return tls
}

func parseTransport(query url.Values) (map[string]interface{}, error) {
	tType := query.Get("type")
	path := query.Get("path")
	host := query.Get("host")

	if tType == "" || tType == "tcp" {
		if query.Get("headerType") == "http" {
			return nil, fmt.Errorf("unsupported transport: tcp with http header (only none, tcp, grpc, httpupgrade are supported)")
		}
		return nil, nil
	} else if tType == "grpc" {
		return map[string]interface{}{
			"type":        "grpc",
			"service_name": query.Get("serviceName"),
		}, nil
	} else if tType == "httpupgrade" {
		return map[string]interface{}{
			"type": "httpupgrade",
			"path": path,
			"host": host,
		}, nil
	}
	return nil, fmt.Errorf("unsupported transport type: %s (only none, tcp, grpc, httpupgrade are supported)", tType)
}

func parseVLESS(raw string, allowInsecure bool) (map[string]interface{}, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	outbound := map[string]interface{}{
		"type":   "vless",
		"server": u.Hostname(),
		"uuid":   u.User.Username(),
	}
	if portInt, err := strconv.Atoi(u.Port()); err == nil {
		outbound["server_port"] = portInt
	}
	query := u.Query()
	if flow := query.Get("flow"); flow != "" {
		outbound["flow"] = flow
	}
	if tls := parseTLS(query, allowInsecure); tls != nil {
		outbound["tls"] = tls
	}
	transport, err := parseTransport(query)
	if err != nil {
		return nil, err
	}
	if transport != nil {
		outbound["transport"] = transport
	}
	return outbound, nil
}

func parseTrojan(raw string, allowInsecure bool) (map[string]interface{}, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	outbound := map[string]interface{}{
		"type":     "trojan",
		"server":   u.Hostname(),
		"password": u.User.Username(),
	}
	if portInt, err := strconv.Atoi(u.Port()); err == nil {
		outbound["server_port"] = portInt
	}
	query := u.Query()
	if tls := parseTLS(query, allowInsecure); tls != nil {
		outbound["tls"] = tls
	}
	transport, err := parseTransport(query)
	if err != nil {
		return nil, err
	}
	if transport != nil {
		outbound["transport"] = transport
	}
	return outbound, nil
}

func parseHY2(raw string, allowInsecure bool) (map[string]interface{}, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	outbound := map[string]interface{}{
		"type":     "hysteria2",
		"server":   u.Hostname(),
		"password": u.User.Username(),
		"tls": map[string]interface{}{
			"enabled":  true,
			"insecure": allowInsecure,
		},
	}
	if portInt, err := strconv.Atoi(u.Port()); err == nil {
		outbound["server_port"] = portInt
	}
	if sni := u.Query().Get("sni"); sni != "" {
		outbound["tls"].(map[string]interface{})["server_name"] = sni
	}
	return outbound, nil
}
