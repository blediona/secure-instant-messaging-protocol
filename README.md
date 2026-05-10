# Secure Instant Messaging Protocol

Ky projekt zbaton nje protokoll te sigurt per mesazhe te castit me:

- enkriptim nga skaji ne skaj (end-to-end encryption);
- nenshkrime digjitale per autenticitet dhe integritet;
- fshehtesi perpara (forward secrecy) me celesa te perkohshem;
- server qe vetem percjell mesazhe dhe nuk mund t'i dekriptoje.

## Struktura

- `client/client.py` - klienti qe krijon perdorues, gjeneron celesa, dergon dhe hap mesazhe.
- `server/server.py` - serveri relay qe ruan vetem celesa publike dhe percjell ciphertext.
- `crypto/key_manager.py` - gjenerimi, ruajtja, nenshkrimi dhe verifikimi i celesave.
- `keys/` - folder lokal ku krijohen automatikisht celesat e perdoruesve kur klienti startohet.
- `crypto/secure_message.py` - krijimi dhe hapja e mesazheve te sigurta.
- `docs/protocol.md` - pershkrimi i protokollit dhe garancive te sigurise.

## Algoritmet

- `X25519` per marreveshje celesash.
- `Ed25519` per nenshkrime digjitale.
- `HKDF-SHA256` per nxjerrje te celesit simetrik.
- `AES-GCM` per enkriptim te autentikuar.

## Dokumentimi teknik

Pershkrimi i plote i protokollit gjendet ketu: [docs/protocol.md](docs/protocol.md).

## Si ekzekutohet

Instalo varesine kryesore:

```powershell
pip install -r requirements.txt
```

Nise serverin:

```powershell
python server\server.py
```

Pastaj hap dy terminale te tjera dhe nisi dy kliente:

```powershell
python client\client.py
```

Regjistro dy perdorues, p.sh. `alice` dhe `bob`, dhe dergo mesazh nga njeri te tjetri. Kur shkruan nje username te ri, klienti krijon automatikisht file si `keys/alice.json` me celesat e atij perdoruesi.

## Kufizime

Ky eshte implementim edukativ. Per perdorim real do te duheshin edhe:

- verifikim manual i fingerprint-it te celesave publike;
- ruajtje me e sigurt e celesave private;
- queue per mesazhe offline;
- mbrojtje me e gjere kunder replay attacks;
- protokoll i plote ratchet si Signal Double Ratchet.