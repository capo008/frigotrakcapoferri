using System.Collections.Concurrent;
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Json.Schema;

// ---------- Diffie-Hellman: gruppo 14 di RFC 3526 (2048 bit), g = 2 ----------
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

// ---------- Stato in memoria ----------
var sessioni = new ConcurrentDictionary<string, byte[]>();   // session_id -> chiave
var misure = new List<string>();                              // misure salvate
var lockMisure = new object();

// ---------- Schemi ----------
var schHandshake = Carica("handshake_request.json");
var schTelemetry = Carica("telemetry.json");
var schReadings = Carica("readings_request.json");

// Intervalli di sicurezza per tipo di merce
var range = new Dictionary<string, (double min, double max)>
{
    ["pharma"] = (3, 8),
    ["food"] = (0, 6),
    ["frozen"] = (-25, -15)
};

var app = WebApplication.CreateBuilder(args).Build();

// ================= /api/handshake =================
app.MapPost("/api/handshake", async (HttpRequest req) =>
{
    var body = await LeggiBody(req);
    if (body == null) return Errore(400, "JSON non valido");

    var problema = Valida(schHandshake, body);
    if (problema != null) return Errore(400, problema);

    var p = Hex((string)body["p"]!);
    var g = Hex((string)body["g"]!);
    var A = Hex((string)body["A"]!);

    if (p != P || g != G) return Errore(400, "gruppo DH non supportato");
    if (A <= 1 || A >= P - 1) return Errore(400, "chiave pubblica non valida");

    var b = new BigInteger(RandomNumberGenerator.GetBytes(32), isUnsigned: true);
    var B = BigInteger.ModPow(G, b, P);
    var K = BigInteger.ModPow(A, b, P);

    // chiave AES = SHA-256 del segreto K (big endian)
    var chiave = SHA256.HashData(K.ToByteArray(isUnsigned: true, isBigEndian: true));

    var sid = Convert.ToHexString(RandomNumberGenerator.GetBytes(4)).ToLower();
    sessioni[sid] = chiave;

    return Results.Json(new JsonObject { ["session_id"] = sid, ["B"] = B.ToString("X") });
});

// ================= /api/telemetry =================
app.MapPost("/api/telemetry", async (HttpRequest req) =>
{
    var err = Apri(await LeggiBody(req), out var sid, out var chiave, out var msg);
    if (err != null) return err;

    var problema = Valida(schTelemetry, msg!);
    if (problema != null) return Sigilla(sid, chiave, new JsonObject { ["error"] = problema }, 400);

    lock (lockMisure)
    {
        misure.Add(msg!.ToJsonString());
        File.AppendAllText("readings.jsonl", msg.ToJsonString() + "\n");
    }

    var tipo = (string)msg["cargo_type"]!;
    var t = (double)msg["temperature_c"]!;
    var limiti = range[tipo];
    var allarme = t < limiti.min || t > limiti.max;

    var ack = new JsonObject { ["status"] = "ok", ["alarm"] = allarme };
    if (allarme) ack["message"] = $"temperatura {t} fuori dall'intervallo {limiti.min}..{limiti.max} per {tipo}";
    return Sigilla(sid, chiave, ack);
});

// ================= /api/readings =================
app.MapPost("/api/readings", async (HttpRequest req) =>
{
    var err = Apri(await LeggiBody(req), out var sid, out var chiave, out var msg);
    if (err != null) return err;

    var problema = Valida(schReadings, msg!);
    if (problema != null) return Sigilla(sid, chiave, new JsonObject { ["error"] = problema }, 400);

    var sensore = (string)msg!["sensor_id"]!;
    DateTimeOffset? da = msg["from"] != null ? DateTimeOffset.Parse((string)msg["from"]!) : null;
    DateTimeOffset? a = msg["to"] != null ? DateTimeOffset.Parse((string)msg["to"]!) : null;

    var risultato = new JsonArray();
    lock (lockMisure)
    {
        foreach (var s in misure)
        {
            var m = JsonNode.Parse(s)!;
            if ((string)m["sensor_id"]! != sensore) continue;
            var ts = DateTimeOffset.Parse((string)m["timestamp"]!);
            if (da != null && ts < da) continue;
            if (a != null && ts > a) continue;
            risultato.Add(m);
        }
    }
    return Sigilla(sid, chiave, new JsonObject { ["count"] = risultato.Count, ["readings"] = risultato });
});

// ================= /api/close =================
app.MapPost("/api/close", async (HttpRequest req) =>
{
    var err = Apri(await LeggiBody(req), out var sid, out var chiave, out var msg);
    if (err != null) return err;

    var risposta = Sigilla(sid, chiave, new JsonObject { ["status"] = "closed" });
    sessioni.TryRemove(sid, out _);   // cancella la chiave
    return risposta;
});

app.Run("http://localhost:5000");

// ====================== FUNZIONI ======================

static BigInteger Hex(string s) => BigInteger.Parse("0" + s, NumberStyles.HexNumber);

static JsonSchema Carica(string nome) =>
    JsonSchema.FromFile(Path.Combine(AppContext.BaseDirectory, "schemas", nome));

static IResult Errore(int codice, string testo) =>
    Results.Json(new { error = testo }, statusCode: codice);

static async Task<JsonNode?> LeggiBody(HttpRequest req)
{
    try { return JsonNode.Parse(await new StreamReader(req.Body).ReadToEndAsync()); }
    catch { return null; }
}

// null = valido, altrimenti il testo dell'errore (contiene il campo sbagliato)
static string? Valida(JsonSchema schema, JsonNode nodo)
{
    var elemento = JsonDocument.Parse(nodo.ToJsonString()).RootElement;
    var r = schema.Evaluate(elemento, new EvaluationOptions { RequireFormatValidation = true });
    return r.IsValid ? null : JsonSerializer.Serialize(r);
}

// Controlla sessione e decifra la busta. Ritorna null se va tutto bene, altrimenti la risposta d'errore.
IResult? Apri(JsonNode? busta, out string sid, out byte[] chiave, out JsonNode? msg)
{
    sid = "";
    chiave = Array.Empty<byte>();
    msg = null;
    try
    {
        sid = (string?)busta?["session_id"] ?? "";
        if (sid == "") return Errore(401, "session_id mancante");
        if (!sessioni.TryGetValue(sid, out var k)) return Errore(404, "sessione inesistente");
        chiave = k;

        var dati = Convert.FromBase64String((string)busta!["ciphertext"]!);
        var tag = Convert.FromBase64String((string)busta["tag"]!);
        var nonce = dati[..12];
        var cifrato = dati[12..];
        var chiaro = new byte[cifrato.Length];

        using var aes = new AesGcm(chiave, 16);
        aes.Decrypt(nonce, cifrato, tag, chiaro);   // eccezione se il tag non torna

        msg = JsonNode.Parse(Encoding.UTF8.GetString(chiaro));
        return null;
    }
    catch
    {
        return Errore(400, "busta non valida o manomessa");
    }
}

// Cifra un JSON e lo mette in una busta. ciphertext = nonce (12 byte) + dati cifrati
static IResult Sigilla(string sid, byte[] chiave, JsonNode msg, int codice = 200)
{
    var chiaro = Encoding.UTF8.GetBytes(msg.ToJsonString());
    var nonce = RandomNumberGenerator.GetBytes(12);
    var cifrato = new byte[chiaro.Length];
    var tag = new byte[16];

    using var aes = new AesGcm(chiave, 16);
    aes.Encrypt(nonce, chiaro, cifrato, tag);

    var busta = new JsonObject
    {
        ["session_id"] = sid,
        ["ciphertext"] = Convert.ToBase64String(nonce.Concat(cifrato).ToArray()),
        ["tag"] = Convert.ToBase64String(tag)
    };
    return Results.Json(busta, statusCode: codice);
}