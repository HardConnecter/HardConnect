package configs

type (
	Config struct {
		ServerAddress       string
		ServerPort          int
		Username            string
		Password            string
		DisableServerConfig bool
		DisableFDUConfig    bool
		DisableFDUDNS       bool
		DisableMultiLine    bool
		ProxyAll            bool
		SocksBind           string
		SocksUser           string
		SocksPasswd         string
		HTTPBind            string
		ShadowsocksURL      string
		DialDirectProxy     string
		TUNMode             bool
		AddRoute            bool
		DNSTTL              uint64
		DisableKeepAlive    bool
		FDUDNSServer        string
		SecondaryDNSServer  string
		DNSServerBind       string
		DNSHijack           bool
		DebugDump           bool
		PortForwardingList  []SinglePortForwarding
		CustomDNSList       []SingleCustomDNS
		CustomProxyDomain   []string
		TwfID               string
	}

	SinglePortForwarding struct {
		NetworkType   string
		BindAddress   string
		RemoteAddress string
	}

	SingleCustomDNS struct {
		HostName string `toml:"host_name"`
		IP       string `toml:"ip"`
	}
)

type (
	ConfigTOML struct {
		ServerAddress       *string                    `toml:"server_address"`
		ServerPort          *int                       `toml:"server_port"`
		Username            *string                    `toml:"username"`
		Password            *string                    `toml:"password"`
		DisableServerConfig *bool                      `toml:"disable_server_config"`
		DisableFDUConfig    *bool                      `toml:"disable_fdu_config"`
		DisableFDUDNS       *bool                      `toml:"disable_fdu_dns"`
		DisableMultiLine    *bool                      `toml:"disable_multi_line"`
		ProxyAll            *bool                      `toml:"proxy_all"`
		SocksBind           *string                    `toml:"socks_bind"`
		SocksUser           *string                    `toml:"socks_user"`
		SocksPasswd         *string                    `toml:"socks_passwd"`
		HTTPBind            *string                    `toml:"http_bind"`
		ShadowsocksURL      *string                    `toml:"shadowsocks_url"`
		DialDirectProxy     *string                    `toml:"dial_direct_proxy"`
		TUNMode             *bool                      `toml:"tun_mode"`
		AddRoute            *bool                      `toml:"add_route"`
		DNSTTL              *uint64                    `toml:"dns_ttl"`
		DisableKeepAlive    *bool                      `toml:"disable_keep_alive"`
		FDUDNSServer        *string                    `toml:"fdu_dns_server"`
		SecondaryDNSServer  *string                    `toml:"secondary_dns_server"`
		DNSServerBind       *string                    `toml:"dns_server_bind"`
		DNSHijack           *bool                      `toml:"dns_hijack"`
		DebugDump           *bool                      `toml:"debug_dump"`
		PortForwarding      []SinglePortForwardingTOML `toml:"port_forwarding"`
		CustomDNS           []SingleCustomDNSTOML      `toml:"custom_dns"`
		CustomProxyDomain   []string                   `toml:"custom_proxy_domain"`
	}

	SinglePortForwardingTOML struct {
		NetworkType   *string `toml:"network_type"`
		BindAddress   *string `toml:"bind_address"`
		RemoteAddress *string `toml:"remote_address"`
	}

	SingleCustomDNSTOML struct {
		HostName *string `toml:"host_name"`
		IP       *string `toml:"ip"`
	}
)
