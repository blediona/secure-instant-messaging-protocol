# Pershkrimi i Protokollit

## Qellimi

Protokolli ka per qellim komunikim te sigurt instant ndermjet dy klienteve. Serveri sherben vetem si ndermjetes per regjistrim te celesave publike dhe percjellje te mesazheve te enkriptuara.

## Celesat

Cdo perdorues ka:

- `identity_private_key` dhe `identity_public_key` me X25519;
- `signing_private_key` dhe `signing_public_key` me Ed25519;
- `signed_prekey_private_key` dhe `signed_prekey_public_key` me X25519;
- `signed_prekey_signature`, qe eshte nenshkrim Ed25519 mbi `signed_prekey_public_key`.

Celesat private ruhen lokalisht ne klient. Serveri pranon vetem celesat publike dhe nenshkrimin e pre-key.

## Regjistrimi

Klienti dergon ne server:

- emrin e perdoruesit;
- identity public key;
- signing public key;
- signed pre-key public key;
- nenshkrimin e signed pre-key.

Serveri i ruan keto te dhena publike dhe i kthen kur nje klient tjeter kerkon te dergoje mesazh.

## Dergimi i Mesazhit

Kur Alice dergon mesazh te Bob:

1. Alice merr celesat publike te Bob nga serveri.
2. Alice verifikon qe `signed_prekey_public_key` i Bob eshte nenshkruar nga `signing_public_key` i Bob.
3. Alice gjeneron nje celes te perkohshem X25519 vetem per kete mesazh.
4. Alice ben X25519 key exchange me signed pre-key te Bob.
5. Nga shared secret nxirret celes simetrik me HKDF-SHA256.
6. Mesazhi enkriptohet me AES-GCM.
7. Header-i dhe ciphertext nenshkruhen me Ed25519 signing key te Alice.
8. Serverit i dergohet vetem mesazhi i enkriptuar.

## Hapja e Mesazhit

Kur Bob pranon mesazh:

1. Bob merr celesat publike te Alice nga serveri.
2. Bob verifikon nenshkrimin e mesazhit me signing public key te Alice.
3. Bob kontrollon qe mesazhi eshte enkriptuar per identity key te tij.
4. Bob ben X25519 key exchange me signed pre-key private key dhe ephemeral public key te Alice.
5. Bob nxjerr celesin simetrik me HKDF-SHA256.
6. Bob dekripton ciphertext me AES-GCM.
7. Pas hapjes se mesazheve, Bob rrotullon signed pre-key dhe e publikon prape ne server.

## Pse Serveri Nuk Lexon Mesazhet

Serveri nuk ka asnje celes privat. Ai sheh:

- emrat e perdoruesve;
- celesat publike;
- ciphertext;
- nonce;
- header publik;
- nenshkrim.

Pa signed pre-key private key te marresit, serveri nuk mund te nxjerre celesin simetrik dhe nuk mund ta dekriptoje mesazhin.

## Forward Secrecy

Forward secrecy arrihet duke perdorur:

- ephemeral key te ri nga derguesi per cdo mesazh;
- signed pre-key te marresit qe rrotullohet pas hapjes se mesazheve.

Kjo do te thote se komprometimi i nje celesi te ardhshem nuk duhet te hape automatikisht mesazhet e vjetra qe jane krijuar me pre-key te meparshem.

## Nenshkrimet

Nenshkrimet perdoren ne dy vende:

- signed pre-key nenshkruhet nga identity signing key i perdoruesit;
- mesazhi i enkriptuar nenshkruhet nga derguesi.

Kjo mbron kunder ndryshimit te mesazhit dhe kunder zevendesimit te pre-key pa u vene re nga klienti.