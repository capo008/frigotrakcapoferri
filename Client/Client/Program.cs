using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

var url = "http://localhost:5000";
var http = new HttpClient();

// ---------- Handshake Diffie-Hellman (stesso gruppo del server) ----------
var P = Hex(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74" +
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437" +
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05" +
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB" +
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718" +
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF");
var G = new BigInteger(2);

var a = new BigInteger(RandomNumberGenerator.GetBytes(32), isUnsigned: true);
var A = BigInteger.ModPow(G, a, P);

var richiesta = new JsonObject { ["p"] = P.ToString("X"), ["g"] = "2", ["A"] = A.ToString("X") };
var res = await http.PostAsync(url + "/api/handshake", Contenuto(richiesta));
var testo = await res.Content.ReadAsStringAsync();
Console.WriteLine($"handshake -> {(int)res.StatusCode}");
if (!res.IsSuccessStatusCode) { Console.WriteLine(testo); return; }

var h = JsonNode.Parse(testo)!;
var sid = (string)h["session_id"]!;
var B = Hex((string)h["B"]!);
var K = BigInteger.ModPow(B, a, P);
var chiave = SHA256.HashData(K.ToByteArray(isUnsigned: true, isBigEndian: true));
Console.WriteLine("session_id = " + sid);

var ora = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");

// ---------- 1. Tre sensori, misure valide ----------
await Invia("/api/telemetry", new JsonObject { ["sensor_id"] = "CELLA-BG-001", ["timestamp"] = ora, ["cargo_type"] = "pharma", ["temperature_c"] = 4.6, ["humidity"] = 55, ["battery"] = 87 });
await Invia("/api/telemetry", new JsonObject { ["sensor_id"] = "CAMION-MI-002", ["timestamp"] = ora, ["cargo_type"] = "food", ["temperature_c"] = 3.2 });
await Invia("/api/telemetry", new JsonObject { ["sensor_id"] = "CELLA-BS-003", ["timestamp"] = ora, ["cargo_type"] = "frozen", ["temperature_c"] = -10 });   // allarme

// ---------- 2. Misura non valida (400 con campo sbagliato) ----------
await Invia("/api/telemetry", new JsonObject { ["sensor_id"] = "sbagliato", ["timestamp"] = ora, ["cargo_type"] = "pharma", ["temperature_c"] = 99 });

// ---------- 3. Elenco misure ----------
await Invia("/api/readings", new JsonObject { ["sensor_id"] = "CELLA-BG-001" });

// ---------- 4. Busta manomessa (tag sbagliato) -> 400 ----------
var manomessa = Sigilla(chiave, sid, new JsonObject { ["sensor_id"] = "CELLA-BG-001" });
manomessa["tag"] = Convert.ToBase64String(new byte[16]);
await InviaBusta("/api/telemetry", manomessa);

// ---------- 5. Sessione inesistente -> 404 ----------
var falsa = Sigilla(chiave, "00000000", new JsonObject { ["x"] = 1 });
await InviaBusta("/api/telemetry", falsa);

// ---------- 6. Chiusura sessione ----------
await Invia("/api/close", new JsonObject { ["bye"] = true });
// dopo la chiusura la sessione non esiste più -> 404
await Invia("/api/telemetry", new JsonObject { ["sensor_id"] = "CELLA-BG-001", ["timestamp"] = ora, ["cargo_type"] = "pharma", ["temperature_c"] = 5 });

// ====================== FUNZIONI ======================

async Task Invia(string endpoint, JsonObject msg) => await InviaBusta(endpoint, Sigilla(chiave, sid, msg));

async Task InviaBusta(string endpoint, JsonObject busta)
{
    var r = await http.PostAsync(url + endpoint, Contenuto(busta));
    var t = await r.Content.ReadAsStringAsync();
    Console.WriteLine($"{endpoint} -> {(int)r.StatusCode}");
    try { Console.WriteLine("   " + Apri(chiave, JsonNode.Parse(t)!)); }
    catch { Console.WriteLine("   (in chiaro) " + t); }
}

static BigInteger Hex(string s) => BigInteger.Parse("0" + s, NumberStyles.HexNumber);

static StringContent Contenuto(JsonNode n) => new(n.ToJsonString(), Encoding.UTF8, "application/json");

// ciphertext = nonce (12 byte) + dati cifrati
static JsonObject Sigilla(byte[] chiave, string sid, JsonNode msg)
{
    var chiaro = Encoding.UTF8.GetBytes(msg.ToJsonString());
    var nonce = RandomNumberGenerator.GetBytes(12);
    var cifrato = new byte[chiaro.Length];
    var tag = new byte[16];
    using var aes = new AesGcm(chiave, 16);
    aes.Encrypt(nonce, chiaro, cifrato, tag);
    return new JsonObject
    {
        ["session_id"] = sid,
        ["ciphertext"] = Convert.ToBase64String(nonce.Concat(cifrato).ToArray()),
        ["tag"] = Convert.ToBase64String(tag)
    };
}

static string Apri(byte[] chiave, JsonNode busta)
{
    var dati = Convert.FromBase64String((string)busta["ciphertext"]!);
    var tag = Convert.FromBase64String((string)busta["tag"]!);
    var nonce = dati[..12];
    var cifrato = dati[12..];
    var chiaro = new byte[cifrato.Length];
    using var aes = new AesGcm(chiave, 16);
    aes.Decrypt(nonce, cifrato, tag, chiaro);
    return Encoding.UTF8.GetString(chiaro);
}