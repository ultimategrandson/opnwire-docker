using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Security.Cryptography.X509Certificates;
using NSec.Cryptography;
using System.Net.Http.Json;
using System.Text.Json.Serialization;

var config = new Configuration
{
    PiaUsername = Environment.GetEnvironmentVariable("PIA_USERNAME"),
    PiaPassword = Environment.GetEnvironmentVariable("PIA_PASSWORD"),
    QBittorrentUrl = Environment.GetEnvironmentVariable("QBITTORRENT_URL"),
    QBittorrentUsername = Environment.GetEnvironmentVariable("QBITTORRENT_USERNAME"),
    QBittorrentPassword = Environment.GetEnvironmentVariable("QBITTORRENT_PASSWORD"),
    OpnsenseUrl = Environment.GetEnvironmentVariable("OPNSENSE_URL"),
    OpnsenseApiKey = Environment.GetEnvironmentVariable("OPNSENSE_API_KEY"),
    OpnsenseApiSecret = Environment.GetEnvironmentVariable("OPNSENSE_API_SECRET"),
    PortForwardSettingsPath = "/App/data/port_forward.json",
    TokenLifetime = TimeSpan.FromHours(23)
};

var manager = new PiaWireguardManager(config);
await manager.RunAsync();

public class PiaWireguardManager(Configuration config)
{
    private readonly Configuration _config = config;

    public async Task RunAsync()
    {
        // Load existing
        PiaPortForwarding portForwardSettings;

        if (File.Exists(_config.PortForwardSettingsPath))
        {
            using var file = File.OpenRead(_config.PortForwardSettingsPath);
            portForwardSettings = await JsonSerializer.DeserializeAsync<PiaPortForwarding>(file) ?? new PiaPortForwarding();
        }
        else
            portForwardSettings = new PiaPortForwarding();

        while (true)
        {
            try
            {
                bool newServer = false;
                int originalPortNumber = portForwardSettings.Port;

                // Get best PIA server
                if (portForwardSettings.Server == null)
                {
                    Console.WriteLine("Finding best PIA WireGuard server...");
                    portForwardSettings.Server = await GetBestPiaServerAsync();
                    Console.WriteLine($" Selected server: {portForwardSettings.Server.Name} ({portForwardSettings.Server.Region})");
                    Console.WriteLine($" Server: {portForwardSettings.Server.ServerIp}, CN={portForwardSettings.Server.CommonName}\n");
                    newServer = true;
                }

                if (newServer)
                {
                    // Generate WireGuard keys
                    Console.WriteLine("Generating WireGuard key pair...");
                    var (privateKey, publicKey) = GenerateWireGuardKeys();

                    // Add public key to PIA and get configuration
                    Console.WriteLine("Registering with PIA and getting tunnel IP...");
                    await RegisterKeyWithPiaAsync(publicKey, await GetOrAddToken(portForwardSettings), portForwardSettings.Server);
                    Console.WriteLine($" Tunnel IP: {portForwardSettings.Server.TunnelIp}");
                    Console.WriteLine($" Peer Server IP: {portForwardSettings.Server.ServerIp}:{portForwardSettings.Server.ServerPort}");
                    Console.WriteLine($" Peer Public Key: {portForwardSettings.Server.ServerPublicKey}\n");

                    // Configure WireGuard on OPNsense
                    Console.WriteLine("Configuring WireGuard on OPNsense...");
                    await ConfigureOpnsenseWireguardAsync(privateKey, publicKey, portForwardSettings.Server);

                    Console.WriteLine("Configuring Gateway on OPNsense...");
                    await UpdateOpnSenseGatewayAsync(portForwardSettings.Server);
                }

                if (portForwardSettings.IsSignatureExpired)
                {
                    // Request port forward from PIA
                    Console.WriteLine("Requesting port forward from PIA...");
                    await RequestPiaPortForwardAsync(portForwardSettings);
                    Console.WriteLine($" Forwarded port: {portForwardSettings.Port} (Expires: {portForwardSettings.SignatureExpiry})\n");
                }

                if (originalPortNumber != portForwardSettings.Port)
                {
                    // Update qBittorrent
                    Console.WriteLine("Updating qBittorrent listening port...");
                    await UpdateQBittorrentPortAsync(portForwardSettings.Port);

                    Console.WriteLine("Updating OpnSense port forward...");
                    await UpdateOpnsenseNatPortAsync(portForwardSettings.Port);
                }

                // Save settings
                using (var file = File.OpenWrite(_config.PortForwardSettingsPath))
                    await JsonSerializer.SerializeAsync(file, portForwardSettings);

                // Bind port, maintain port
                await BindAndKeepAlivePort(portForwardSettings);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\nError: {ex}");
                portForwardSettings.Server = null;
            }

            await Task.Delay(TimeSpan.FromMinutes(1));
        }
    }

    private async Task<PiaServer> GetBestPiaServerAsync()
    {
        // Get PIA server list
        using var client = new HttpClient();
        var serversUrl = "https://serverlist.piaservers.net/vpninfo/servers/v6";
        var response = await client.GetAsync(serversUrl);
        response.EnsureSuccessStatusCode();

        var content = await response.Content.ReadAsStringAsync();

        // PIA returns data with signature, parse the JSON part
        var jsonStart = content.IndexOf('{');
        var jsonEnd = content.LastIndexOf('}');
        var jsonContent = content.Substring(jsonStart, jsonEnd + 1);

        var serverData = JsonSerializer.Deserialize<JsonElement>(jsonContent);
        var regions = serverData.GetProperty("regions").EnumerateArray();

        var wireguardServers = new List<PiaServer>();

        foreach (var region in regions)
        {
            var regionId = region.GetProperty("id").GetString();
            var regionName = region.GetProperty("name").GetString();

            if (regionId == null || regionName == null)
                continue;

            // Check if port forwarding is supported
            if (!region.GetProperty("port_forward").GetBoolean())
                continue;

            // Get WireGuard servers
            if (region.TryGetProperty("servers", out var servers) && servers.TryGetProperty("wg", out var wgServersProp))
                foreach (var server in wgServersProp.EnumerateArray())
                {
                    var ip = server.GetProperty("ip").GetString();
                    var cn = server.GetProperty("cn").GetString();

                    if (ip == null || cn == null)
                        continue;

                    wireguardServers.Add(new PiaServer
                    {
                        Region = regionId,
                        Name = regionName,
                        ServerIp = ip,
                        CommonName = cn,
                        ServerPort = 1337
                    });
                }
        }

        // Otherwise return first available
        return wireguardServers.FirstOrDefault()
            ?? throw new Exception("No PIA servers with port forwarding found");
    }

    private (string privateKey, string publicKey) GenerateWireGuardKeys()
    {
        using var key = Key.Create(KeyAgreementAlgorithm.X25519, new KeyCreationParameters()
        {
            ExportPolicy = KeyExportPolicies.AllowPlaintextExport
        });

        var privateKeyBytes = key.Export(KeyBlobFormat.RawPrivateKey);
        var publicKeyBytes = key.Export(KeyBlobFormat.RawPublicKey);

        var privateKey = Convert.ToBase64String(privateKeyBytes);
        var publicKey = Convert.ToBase64String(publicKeyBytes);

        return (privateKey, publicKey);
    }

    private async Task<PiaToken> GetOrAddToken(PiaPortForwarding portForward)
    {
        if (_config.PiaUsername == null || _config.PiaPassword == null)
            throw new Exception("PIA Username/Password required");

        if (portForward.Token != null && !portForward.Token.IsTokenExpired)
            return portForward.Token;

        // Get PIA token
        using var tokenClient = new HttpClient();
        var tokenResponse = await tokenClient.PostAsync("https://www.privateinternetaccess.com/api/client/v2/token", new FormUrlEncodedContent(
        [
            new("username", _config.PiaUsername),
            new("password", _config.PiaPassword)
        ]));

        tokenResponse.EnsureSuccessStatusCode();

        var tokenData = await tokenResponse.Content.ReadFromJsonAsync<JsonElement>();
        portForward.Token = new()
        {
            Token = tokenData.GetProperty("token").GetString() ?? throw new Exception("Unable to get token"),
            Expiry = DateTime.UtcNow.Add(_config.TokenLifetime)
        };

        return portForward.Token;
    }

    private HttpClient CreatePortForwardingHttpClient(PiaServer piaServer, int port)
    {
        var piaCa = X509CertificateLoader.LoadCertificateFromFile("wg.crt");

        var clientHandler = new SocketsHttpHandler()
        {
            SslOptions =
            {
                ClientCertificates = [piaCa],
                TargetHost = piaServer.CommonName,
                RemoteCertificateValidationCallback = (handler, cert, chain, errors) =>
                {
                    var chain2 = new X509Chain
                    {
                        ChainPolicy =
                        {
                            RevocationMode = X509RevocationMode.NoCheck,
                            RevocationFlag = X509RevocationFlag.ExcludeRoot,
                            ExtraStore = { piaCa },
                            VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority
                        }
                    };

                    bool valid = chain2.Build(new X509Certificate2(cert ?? throw new Exception("Certificate is null")));

                    var root = chain2.ChainElements[^1].Certificate;

                    if (!root.RawData.SequenceEqual(piaCa.RawData))
                        return false;

                    return valid;
                }
            },
        };

        var piaUriBuilder = new UriBuilder
        {
            Host = piaServer.ServerIp,
            Port = port,
            Scheme = Uri.UriSchemeHttps
        };

        var pfHttpClient = new HttpClient(clientHandler);
        pfHttpClient.BaseAddress = piaUriBuilder.Uri;

        return pfHttpClient;
    }

    private async Task RegisterKeyWithPiaAsync(string publicKey, PiaToken token, PiaServer server)
    {
        using var addKeyClient = CreatePortForwardingHttpClient(server, server.ServerPort);
        var addKeyResponse = await addKeyClient.GetAsync($"/addKey?pubkey={Uri.EscapeDataString(publicKey)}&pt={Uri.EscapeDataString(token.Token)}");

        addKeyResponse.EnsureSuccessStatusCode();

        var configJson = await addKeyResponse.Content.ReadAsStringAsync();
        var configData = JsonSerializer.Deserialize<JsonElement>(configJson);

        server.TunnelIp = configData.GetProperty("peer_ip").GetString();
        server.ServerPublicKey = configData.GetProperty("server_key").GetString();

        if (configData.TryGetProperty("server_ip", out var serverIpProp))
        {
            var newServerIp = serverIpProp.GetString();

            if (newServerIp != null)
                server.ServerIp = newServerIp;
        }

        server.ServerPort = configData.GetProperty("server_port").GetInt32();
    }

    private async Task RequestPiaPortForwardAsync(PiaPortForwarding portForwardSettings)
    {
        if (portForwardSettings.Server == null)
            throw new Exception("Server required");

        // Add key to PIA and get tunnel configuration
        using var portClient = CreatePortForwardingHttpClient(portForwardSettings.Server, 19999);
        var token = await GetOrAddToken(portForwardSettings);

        // Request port forward using the tunnel IP as gateway
        var portResponse = await portClient.GetAsync($"/getSignature?token={Uri.EscapeDataString(token.Token)}");
        portResponse.EnsureSuccessStatusCode();

        var sigJson = await portResponse.Content.ReadAsStringAsync();
        var portData = JsonSerializer.Deserialize<JsonElement>(sigJson);

        if (portData.GetProperty("status").GetString() != "OK")
            throw new Exception("Status failed on getSignature");

        var payload = portData.GetProperty("payload").GetString()!;
        var payloadElement = JsonSerializer.Deserialize<JsonElement>(Convert.FromBase64String(payload));
        var signature = portData.GetProperty("signature").GetString()!;
        var port = payloadElement.GetProperty("port").GetInt32();
        var expiry = payloadElement.GetProperty("expires_at").GetString()!;

        var newToken = payloadElement.GetProperty("token").GetString()!;

        if (newToken != token.Token) // Is most likely always the same 
        {
            token.Token = newToken;
            token.Expiry = DateTime.UtcNow.Add(_config.TokenLifetime);
        }

        portForwardSettings.Payload = payload;
        portForwardSettings.Signature = signature;
        portForwardSettings.Port = port;
        portForwardSettings.SignatureExpiry = DateTime.Parse(expiry);
    }

    private async Task BindAndKeepAlivePort(PiaPortForwarding portForwarding)
    {
        if (portForwarding.Server == null || portForwarding.Payload == null || portForwarding.Signature == null)
            throw new Exception("Server, Payload and Signature required");

        using var portClient = CreatePortForwardingHttpClient(portForwarding.Server, 19999);
        var url = $"/bindPort?payload={Uri.EscapeDataString(portForwarding.Payload)}&signature={Uri.EscapeDataString(portForwarding.Signature)}";

        // Request port forward using the tunnel IP as gateway
        while (true)
        {
            Console.WriteLine($"Binding port {portForwarding.Port}...");

            var portResponse = await portClient.GetAsync(url);
            portResponse.EnsureSuccessStatusCode();

            var response = await portResponse.Content.ReadFromJsonAsync<JsonElement>();
            var status = response.GetProperty("status").GetString();
            var message = response.GetProperty("message").GetString();

            Console.WriteLine($" {status}: {message}");

            if (response.GetProperty("status").GetString() != "OK")
                break;

            await Task.Delay(TimeSpan.FromMinutes(15));
        }
    }

    private async Task UpdateQBittorrentPortAsync(int port)
    {
        if (_config.QBittorrentUsername == null || _config.QBittorrentPassword == null || _config.QBittorrentUrl == null)
            throw new Exception("QBittorrent Username/Password/Url required");

        using var qbtClient = new HttpClient();
        qbtClient.BaseAddress = new Uri(_config.QBittorrentUrl);

        // Login
        var loginData = new FormUrlEncodedContent(
        [
            new KeyValuePair<string, string>("username", _config.QBittorrentUsername),
            new KeyValuePair<string, string>("password", _config.QBittorrentPassword)
        ]);

        var loginResponse = await qbtClient.PostAsync($"/api/v2/auth/login", loginData);
        loginResponse.EnsureSuccessStatusCode();

        // Set port
        var preferences = new { listen_port = port };
        var prefJson = JsonSerializer.Serialize(preferences);

        var setPortData = new FormUrlEncodedContent(
        [
            new KeyValuePair<string, string>("json", prefJson)
        ]);

        var cookies = loginResponse.Headers.GetValues("Set-Cookie");
        qbtClient.DefaultRequestHeaders.Add("Cookie", string.Join("; ", cookies));

        await qbtClient.PostAsync($"/api/v2/app/setPreferences", setPortData);
    }

    private async Task UpdateOpnsenseNatPortAsync(int newPort)
    {
        using var natClient = GetOpnSenseClient();

        // Search for existing PIA port forward rule by description
        var searchResponse = await natClient.GetAsync("/api/firewall/alias/search_item?searchPhrase=PIAPortForward&current=1&rowCount=5");
        searchResponse.EnsureSuccessStatusCode();

        var searchResult = await searchResponse.Content.ReadFromJsonAsync<JsonElement>();

        var aliasUuid = searchResult
            .GetProperty("rows")
            .EnumerateArray()
            .FirstOrDefault(a => a.GetProperty("name").GetString() == _config.AliasConfigName)
            .GetProperty("uuid")
            .GetString() ?? throw new Exception("No existing PIA Alias found. Please create it manually first.");

        // Update existing alias with new port
        var natAlias = new
        {
            alias = new
            {
                content = newPort.ToString()
            }
        };

        var updateResponse = await natClient.PostAsync($"/api/firewall/alias/set_item/{aliasUuid}", JsonContent.Create(natAlias));
        updateResponse.EnsureSuccessStatusCode();

        await natClient.PostAsync($"/api/firewall/alias/reconfigure", null);
        updateResponse.EnsureSuccessStatusCode();
    }

    private HttpClient GetOpnSenseClient()
    {
        if (_config.OpnsenseUrl == null)
            throw new Exception("Opnsense URL required");

        var opnSenseClient = new HttpClient
        {
            BaseAddress = new Uri(_config.OpnsenseUrl)
        };

        opnSenseClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{_config.OpnsenseApiKey}:{_config.OpnsenseApiSecret}")));
        return opnSenseClient;
    }

    private async Task UpdateOpnSenseGatewayAsync(PiaServer serverConfig)
    {
        using var opnSenseClient = GetOpnSenseClient();

        // Find existing gateway
        var serverResponse = await opnSenseClient.GetAsync($"/api/routing/settings/search_gateway");
        serverResponse.EnsureSuccessStatusCode();

        var serverResult = await serverResponse.Content.ReadFromJsonAsync<JsonElement>();
        string? gatewayUuid = null;

        foreach (var row in serverResult.GetProperty("rows").EnumerateArray())
        {
            if (row.GetProperty("name").ToString() != _config.GatewayConfigName)
                continue;

            gatewayUuid = row.GetProperty("uuid").ToString();
            break;
        }

        Console.WriteLine($" Gateway UUID: {gatewayUuid}");

        var gatewayConfig = new
        {
            gateway_item = new
            {
                gateway = serverConfig.GatewayIp,
                monitor = serverConfig.ServerIp
            }
        };

        serverResponse = await opnSenseClient.PostAsync($"/api/routing/settings/set_gateway/{gatewayUuid}", JsonContent.Create(gatewayConfig));
        serverResponse.EnsureSuccessStatusCode();

        serverResponse = await opnSenseClient.PostAsync($"/api/routing/settings/reconfigure", null);
        serverResponse.EnsureSuccessStatusCode();
    }

    private async Task ConfigureOpnsenseWireguardAsync(string privateKey, string publicKey, PiaServer piaConfig)
    {
        if (piaConfig.TunnelIp == null)
            throw new Exception("Need tunnel IP.");

        using var opnSenseClient = GetOpnSenseClient();

        // Find existing server
        var serverResponse = await opnSenseClient.GetAsync($"/api/wireguard/server/search_server?current=1&rowCount=50");
        serverResponse.EnsureSuccessStatusCode();

        var serverResult = await serverResponse.Content.ReadFromJsonAsync<JsonElement>();
        string? serverUuid = null;
        string? peerUuid = null;

        foreach (var row in serverResult.GetProperty("rows").EnumerateArray())
        {
            if (row.GetProperty("name").ToString() != _config.WireguardConfigName)
                continue;

            serverUuid = row.GetProperty("uuid").ToString();
            peerUuid = row.GetProperty("peers").ToString();
            break;
        }

        // Update WireGuard server (local instance)
        piaConfig.GatewayIp = $"{piaConfig.TunnelIp[..piaConfig.TunnelIp.LastIndexOf('.')]}.{Convert.ToInt32(piaConfig.TunnelIp.Split('.')[3]) - 1}";
        var serverConfig = new
        {
            server = new
            {
                pubkey = publicKey,
                privkey = privateKey,
                tunneladdress = $"{piaConfig.TunnelIp}/24",
                disableroutes = "1",
                gateway = piaConfig.GatewayIp
            }
        };

        serverResponse = await opnSenseClient.PostAsync($"/api/wireguard/server/set_server/{serverUuid}", JsonContent.Create(serverConfig));
        serverResponse.EnsureSuccessStatusCode();

        // Update peer (PIA endpoint)
        var peerConfig = new
        {
            client = new
            {
                pubkey = piaConfig.ServerPublicKey,
                tunneladdress = "0.0.0.0/0",
                serveraddress = piaConfig.ServerIp,
                serverport = piaConfig.ServerPort.ToString(),
                keepalive = "25",
                servers = serverUuid
            }
        };

        var peerJson = JsonSerializer.Serialize(peerConfig);
        var peerContent = new StringContent(peerJson, Encoding.UTF8, "application/json");

        var addPeerUrl = $"/api/wireguard/client/set_client/{peerUuid}";
        serverResponse = await opnSenseClient.PostAsync(addPeerUrl, peerContent);
        serverResponse.EnsureSuccessStatusCode();

        // Reconfigure and start service
        serverResponse = await opnSenseClient.PostAsync($"/api/wireguard/service/reconfigure", null);
        serverResponse.EnsureSuccessStatusCode();
        serverResponse = await opnSenseClient.PostAsync($"/api/wireguard/service/start", null);
        serverResponse.EnsureSuccessStatusCode();

        await Task.Delay(5000);
    }
}

public class PiaPortForwarding
{
    public PiaToken? Token { get; set; }

    public int Port { get; set; }

    public string? Payload { get; set; }

    public string? Signature { get; set; }

    public DateTime SignatureExpiry { get; set; } = DateTime.MinValue;

    [JsonIgnore]
    public bool IsSignatureExpired => DateTime.UtcNow > SignatureExpiry;

    public PiaServer? Server { get; set; }
}

public class PiaToken
{
    public required string Token { get; set; }

    public required DateTime Expiry { get; set; }

    [JsonIgnore]
    public bool IsTokenExpired => DateTime.UtcNow > Expiry;
}

public class PiaServer
{
    public required string Region { get; set; }
    public required string Name { get; set; }
    public required string CommonName { get; set; }
    public required string ServerIp { get; set; }
    public required int ServerPort { get; set; }
    public string? ServerPublicKey { get; set; }
    public string? TunnelIp { get; set; }
    public string? GatewayIp { get; set; }
}

public class Configuration
{
    public required string? PiaUsername { get; set; }
    public required string? PiaPassword { get; set; }
    public required string? QBittorrentUrl { get; set; }
    public required string? QBittorrentUsername { get; set; }
    public required string? QBittorrentPassword { get; set; }
    public required string? OpnsenseUrl { get; set; }
    public required string? OpnsenseApiKey { get; set; }
    public required string? OpnsenseApiSecret { get; set; }
    public required string PortForwardSettingsPath { get; set; }
    public string GatewayConfigName { get; set; } = "PIA_VPN_IP4";
    public string WireguardConfigName { get; set; } = "PIA_WireGuard";
    public string AliasConfigName { get; set; } = "PIAPortForward";
    public required TimeSpan TokenLifetime { get; set; }
}