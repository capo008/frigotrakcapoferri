# Relazione – FrigoTrack, telemetria sicura per la catena del freddo



## Obiettivo

Un server HTTP raccoglie le misure di temperatura dei sensori. Il canale resta HTTP, ma i dati viaggiano cifrati con una chiave concordata con Diffie-Hellman e ogni messaggio viene validato con JSON Schema, così un tecnico malintenzionato non può leggere né inserire valori falsi nel flusso.

## Scelte tecniche

- **C# / ASP.NET Core minimal API**: un solo file per il server e uno per il client, facili da leggere e da spiegare.
- **Diffie-Hellman implementato a mano** con `BigInteger.ModPow` (`A = g^a mod p`, `K = B^a mod p`). Uso il gruppo 14 di RFC 3526 (2048 bit) e il server accetta solo quel gruppo, altrimenti un client potrebbe imporre parametri deboli. Il server rifiuta anche chiavi pubbliche con valore 1 o p−1.
- **Chiave AES = SHA-256(K)**: il segreto condiviso è di 2048 bit, AES-256 vuole 32 byte, quindi lo riduco con un hash invece di usarlo direttamente.
- **AES-256-GCM**: cifra e autentica insieme. Il tag GCM rileva ogni manomissione, e il nonce casuale a 12 byte è anteposto al ciphertext perché la busta del protocollo non ha un campo apposito.
- **Prima decifra, poi valida**: se decifratura o tag falliscono il server risponde 400 senza elaborare nulla. Solo il messaggio decifrato passa allo schema.
- **JSON Schema (draft 2020-12)**: un file per tipo di messaggio, con `type`, `required`, `enum`, `minimum`/`maximum`, `pattern`, `format` e `additionalProperties: false`. Il client valida **prima** di cifrare e valida anche le risposte del server.
- **Sessioni** in un `ConcurrentDictionary`, ciascuna con la propria chiave, quindi più client contemporanei non interferiscono. La lista delle misure è protetta da un `lock`.
- **Errori**: la validazione fallita produce un errore cifrato con il campo sbagliato. Gli errori prima della decifratura (busta manomessa, sessione assente) sono in chiaro ma generici.

## Limiti noti

- **Nessuna autenticazione**: Diffie-Hellman senza firme è vulnerabile a un attaccante che si interpone attivamente (man-in-the-middle). Inoltre qualunque client con una sessione valida può dichiararsi un sensore qualsiasi.
- **Nessuna protezione dal replay**: una busta intercettata può essere reinviata e verrebbe accettata. Servirebbero un contatore o un controllo sul timestamp.
- **`session_id` di soli 32 bit** e risposte diverse per sessione inesistente (404) e busta non valida (400): permettono di indovinare le sessioni attive.
- **Nessuna scadenza delle sessioni**, e nessun limite di richieste.
- **Persistenza minima**: le misure sono in memoria e in `readings.jsonl`, non cifrato e senza database.

  

## Possibili miglioramenti

Firmare l'handshake (certificati o chiave pre-condivisa), aggiungere un contatore anti-replay, un `session_id` più lungo con scadenza, un database per le misure.
