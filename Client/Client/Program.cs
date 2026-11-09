using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Json.Schema;

var url = "http://localhost:5000";
var http = new HttpClient();

// ---------- Schemi (stessi file del server) ----------
var schHandshake = Carica("handshake_request.json");
var schTelemetry = Carica("telemetry.json");
var schReadingsReq = Carica("readings_request.json");
var schReadingsRes = Carica("readings_response.json");
var schError = Carica("error.json");

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
var problemaHs = Valida(schHandshake, richiesta);          // validazione prima dell'invio
if (problemaHs != null) { Console.WriteLine("handshake non valido: " + problemaHs); return; }

var res = await http.PostAsync(url + "/api/handshake", Contenuto(richiesta));
var testo = await res.Content.ReadAsStringAsync();
Console.WriteLine($"handshake -> {(int)res.StatusCode}");
if (!res.IsSuccessStatusCode) { Console.WriteLine(testo); return; }

var h = JsonNode.Parse(testo)!;
if (h["session_id"] == null || h["B"] == null) { Console.WriteLine("risposta handshake non valida: " + testo); return; }
var sid = (string)h["session_id"]!;
var B = Hex((string)h["B"]!);
var K = BigInteger.ModPow(B, a, P);
var chiave = SHA256.HashData(K.ToByteArray(isUnsigned: true, isBigEndian: true));
Console.WriteLine("session_id = " + sid);

// ---------- 1. Tre sensori che inviano a intervalli regolari ----------
var sensori = new[]
{
    (id: "CELLA-BG-001",  tipo: "pharma", t0: 5.0),
    (id: "CAMION-MI-002", tipo: "food",   t0: 3.0),
    (id: "CELLA-BS-003",  tipo: "frozen", t0: -20.0)
};
var rnd = new Random();

for (var giro = 1; giro <= 3; giro++)
{
    Console.WriteLine($"--- giro {giro} ---");
    foreach (var s in sensori)
    {
        var misura = new JsonObject
        {
            ["sensor_id"] = s.id,
            ["timestamp"] = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            ["cargo_type"] = s.tipo,
            ["temperature_c"] = Math.Round(s.t0 + rnd.NextDouble() * 6 - 3, 1),
            ["humidity"] = rnd.Next(40, 70),
            ["battery"] = 100 - giro * 3
        };
        await Invia("/api/telemetry", misura, schTelemetry, null);
    }
    if (giro < 3) await Task.Delay(2000);   // intervallo regolare: 2 secondi
}

// ---------- 2. Misura non valida ----------
var cattiva = new JsonObject
{
    ["sensor_id"] = "sbagliato",
    ["timestamp"] = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
    ["cargo_type"] = "pharma",
    ["temperature_c"] = 99
};
Console.WriteLine("--- misura non valida: bloccata dal client ---");
await Invia("/api/telemetry", cattiva, schTelemetry, null);
Console.WriteLine("--- stessa misura inviata senza validazione client: la rifiuta il server ---");
await Invia("/api/telemetry", cattiva, schTelemetry, null, salta: true);

// ---------- 3. Elenco misure ----------
Console.WriteLine("--- readings ---");
await Invia("/api/readings", new JsonObject { ["sensor_id"] = "CELLA-BG-001" }, schReadingsReq, schReadingsRes);

// ---------- 4. Busta manomessa (tag sbagliato) -> 400 ----------
Console.WriteLine("--- busta manomessa ---");
var manomessa = Sigilla(chiave, sid, new JsonObject { ["sensor_id"] = "CELLA-BG-001" });
manomessa["tag"] = Convert.ToBase64String(new byte[16]);
await InviaBusta("/api/telemetry", manomessa, null);

// ---------- 5. Sessione inesistente -> 404 ----------
Console.WriteLine("--- sessione inesistente ---");
await InviaBusta("/api/telemetry", Sigilla(chiave, "00000000", new JsonObject { ["x"] = 1 }), null);

// ---------- 6. Chiusura sessione, poi nuovo invio -> 404 ----------
Console.WriteLine("--- close ---");
await Invia("/api/close", new JsonObject { ["bye"] = true }, null, null);
await Invia("/api/telemetry", new JsonObject
{
    ["sensor_id"] = "CELLA-BG-001",
    ["timestamp"] = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
    ["cargo_type"] = "pharma",
    ["temperature_c"] = 5
}, schTelemetry, null);

// ====================== FUNZIONI ======================

// Valida con lo schema PRIMA di cifrare; se non è valido non invia nulla.
async Task Invia(string endpoint, JsonObject msg, JsonSchema? schemaRichiesta, JsonSchema? schemaRisposta, bool salta = false)
{
    if (!salta && schemaRichiesta != null)
    {
        var problema = Valida(schemaRichiesta, msg);
        if (problema != null)
        {
            Console.WriteLine($"{endpoint} -> NON INVIATO, messaggio non valido: {problema}");
            return;
        }
    }
    await InviaBusta(endpoint, Sigilla(chiave, sid, msg), schemaRisposta);
}

// Invia la busta, decifra la risposta e la valida con lo schema (se è una risposta con schema)
async Task InviaBusta(string endpoint, JsonObject busta, JsonSchema? schemaRisposta)
{
    var r = await http.PostAsync(url + endpoint, Contenuto(busta));
    var t = await r.Content.ReadAsStringAsync();
    Console.WriteLine($"{endpoint} -> {(int)r.StatusCode}");
    try
    {
        var chiaro = Apri(chiave, JsonNode.Parse(t)!);
        Console.WriteLine("   " + chiaro);

        var schema = r.IsSuccessStatusCode ? schemaRisposta : schError;
        if (schema != null)
        {
            var problema = Valida(schema, JsonNode.Parse(chiaro)!);
            if (problema != null) Console.WriteLine("   ATTENZIONE: risposta non conforme allo schema: " + problema);
        }
    }
    catch { Console.WriteLine("   (in chiaro) " + t); }
}

static JsonSchema Carica(string nome) =>
    JsonSchema.FromFile(Path.Combine(AppContext.BaseDirectory, "schemas", nome));

// null = valido, altrimenti il testo dell'errore
static string? Valida(JsonSchema schema, JsonNode nodo)
{
    var elemento = JsonDocument.Parse(nodo.ToJsonString()).RootElement;
    var r = schema.Evaluate(elemento, new EvaluationOptions
    {
        OutputFormat = OutputFormat.List,
        RequireFormatValidation = true
    });
    return r.IsValid ? null : JsonSerializer.Serialize(r);
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