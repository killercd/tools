#!/usr/bin/env python3
"""
ntlm_catcher.py

Semplice HTTP server che richiede NTLM e stampa il token NTLM ricevuto.
Uso:
    python3 ntlm_catcher.py [HOST] [PORT]

Esempio:
    python3 ntlm_catcher.py 0.0.0.0 8080
"""
import http.server
import socketserver
import base64
import sys
from http import HTTPStatus

HOST = "0.0.0.0"
PORT = 8080

if len(sys.argv) >= 2:
    HOST = sys.argv[1]
if len(sys.argv) >= 3:
    PORT = int(sys.argv[2])

class NTLMRequestHandler(http.server.BaseHTTPRequestHandler):
    server_version = "NTLM-Catcher/0.1"

    def _force_ntlm_challenge(self):
        # Risposta che richiede autenticazione NTLM
        self.send_response(HTTPStatus.UNAUTHORIZED)
        # 'WWW-Authenticate: NTLM' senza challenge iniziale provoca il trigger del flow NTLM
        self.send_header("WWW-Authenticate", "NTLM")
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"NTLM required\n")

    def do_GET(self):
        auth = self.headers.get("Authorization")
        if not auth:
            # nessuna Authorization -> invia 401 per richiedere NTLM
            print(f"[+] {self.client_address} -> nessuna Authorization header, forzo 401+NTLM")
            self._force_ntlm_challenge()
            return

        # Se presente header Authorization
        if auth.startswith("NTLM "):
            b64 = auth.split(" ", 1)[1].strip()
            try:
                raw = base64.b64decode(b64)
            except Exception as e:
                self.send_response(HTTPStatus.BAD_REQUEST)
                self.end_headers()
                self.wfile.write(b"Invalid base64 in NTLM header\n")
                print(f"[!] Errore decodifica base64: {e}")
                return

            # Mostra informazioni utili: base64, lunghezza, esadecimale, e una breve indicazione del tipo (se possibile)
            msg_type = None
            if len(raw) >= 12:
                try:
                    # tipo messaggio NTLM: 4 bytes little-endian a offset 8
                    msg_type = int.from_bytes(raw[8:12], "little")
                except Exception:
                    msg_type = None

            print("============================================")
            print(f"[+] Ricevuto NTLM Authorization da {self.client_address}")
            print(f"    Base64 ({len(b64)} chars):\n{b64}\n")
            print(f"    Bytes length: {len(raw)}")
            if msg_type is not None:
                print(f"    NTLM message type (parsed from bytes 8-11): {msg_type}")
            else:
                print("    NTLM message type: non disponibile (payload troppo corto o non conforme)")
            # stampa esadecimale (prima 256 bytes max per leggibilità)
            hex_snip = raw.hex()
            if len(hex_snip) > 512:
                hex_display = hex_snip[:512] + "...(troncato)"
            else:
                hex_display = hex_snip
            print(f"    Hex (snippet): {hex_display}")
            print("============================================")

            # Rispondi con 401+NTLM per continuare handshake (molti client invieranno il messaggio successivo)
            # Se preferisci terminare qui, puoi inviare 200 OK invece.
            self.send_response(HTTPStatus.UNAUTHORIZED)
            # per proseguire l'handshake sarebbe opportuno inviare un Type2 challenge base64 qui:
            #    self.send_header("WWW-Authenticate", "NTLM <base64-challenge>")
            # ma qui lasciamo il server semplice e rispondiamo con semplice 'NTLM' header.
            self.send_header("WWW-Authenticate", "NTLM")
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"NTLM token received and printed on server console\n")
            return
        else:
            # Authorization presente ma non NTLM
            print(f"[!] Authorization header presente ma non NTLM: {auth.split()[0]}")
            self.send_response(HTTPStatus.FORBIDDEN)
            self.end_headers()
            self.wfile.write(b"Only NTLM auth accepted\n")

    # supporta anche POST se necessario
    def do_POST(self):
        self.do_GET()

if __name__ == "__main__":
    with socketserver.TCPServer((HOST, PORT), NTLMRequestHandler) as httpd:
        print(f"[+] NTLM catcher running on http://{HOST}:{PORT}/")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[+] Shutting down.")
            httpd.server_close()
