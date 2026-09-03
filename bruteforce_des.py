#!/usr/bin/env python3
# bruteforce_des_live.py — DES ECB brute-force con progreso y Top-N
# Kali + Python 3 + pycryptodome

import argparse, itertools, string, time, heapq, sys
from typing import Iterable, Tuple, List, Optional
from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad

# ---------- Descifrado con una clave ----------
def try_key(ciphertext: bytes, key_str: str) -> Optional[bytes]:
    if len(key_str) != 8:
        return None
    try:
        cipher = DES.new(key_str.encode("utf-8", "ignore"), DES.MODE_ECB)
        pt = unpad(cipher.decrypt(ciphertext), 8)
        return pt
    except Exception:
        return None

# ---------- Heurística de puntuación ----------
COMMON_ES = " eaosnriltudcmphqbgfvjzyxwáéíóúñ.,¡!¿?;:-()\"'"

def score_plaintext(pt: bytes, contains: bytes) -> float:
    if not pt:
        return 0.0
    # 1) % de imprimibles
    printable = set(bytes(string.printable, "utf-8"))
    print_ratio = sum(b in printable for b in pt) / len(pt)

    # 2) bonus por palabra(s) clave
    bonus_kw = 0.0
    if contains:
        lower_pt = pt.lower()
        # suma 0.25 por cada match distinto (máx 1.0)
        hits = 0
        for token in contains.split():
            if token in lower_pt:
                hits += 1
        bonus_kw = min(1.0, 0.25 * hits)

    # 3) heurística simple de “parece español”
    allowed = set(COMMON_ES.encode("utf-8"))
    es_ratio = sum(b in allowed or chr(b).islower() or chr(b).isspace() for b in pt) / len(pt)

    # mezcla ponderada (ajustable)
    score = 0.55 * print_ratio + 0.35 * es_ratio + 0.10 * bonus_kw
    return score + (0.50 if contains and contains in pt.lower() else 0.0)  # boost fuerte si match exacto

# ---------- Generadores de claves ----------
def product_keys(charset: str, length: int) -> Iterable[str]:
    for tup in itertools.product(charset, repeat=length):
        yield "".join(tup)

def wordlist_keys(path: str) -> Iterable[str]:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            k = line.strip()
            if len(k) == 8:
                yield k

# ---------- Impresión de Top-N ----------
def print_top(top: List[Tuple[float, str, bytes]], start_time: float, tested: int):
    elapsed = max(1e-6, time.time() - start_time)
    speed = tested / elapsed
    print("\n=== PROGRESO ===")
    print(f"Probadas: {tested:,}  |  Tiempo: {elapsed:,.1f}s  |  Velocidad: {speed:,.0f} claves/s")
    print(f"Top {len(top)} candidatos:")
    for rank, (score, key, pt) in enumerate(sorted(top, reverse=True), 1):
        preview = pt[:100].decode(errors="replace").replace("\n", " ")
        print(f"#{rank:02d}  score={score:0.3f}  key='{key}'  :: {preview}")
    print("=" * 60, flush=True)

def main():
    ap = argparse.ArgumentParser(description="Brute-force DES/ECB con progreso y Top-N")
    ap.add_argument("-i", "--infile", required=True, help="cipher.bin (DES/ECB con padding PKCS#7)")
    ap.add_argument("--contains", default="", help="pista/palabra(s) clave (ej: 'reunete 7 pm')")
    ap.add_argument("--charset", default="AB", help="conjunto de caracteres para generar claves (default: 'AB')")
    ap.add_argument("--length", type=int, default=8, help="longitud de clave (DES=8)")
    ap.add_argument("--wordlist", help="ruta de wordlist (cada línea = una clave de 8 chars)")
    ap.add_argument("--every", type=int, default=5000, help="cada N intentos imprime progreso")
    ap.add_argument("--top", type=int, default=8, help="tamaño del ranking Top-N")
    ap.add_argument("--stop-on-hit", action="store_true", help="detener al primer match con contains")
    args = ap.parse_args()

    # Advertencias básicas
    if not args.wordlist and (len(args.charset) ** args.length) > 50_000_000:
        print("[!] Advertencia: el espacio de búsqueda es MUY grande. Reduce charset/length o usa --wordlist.")
    if args.length != 8:
        print("[!] Nota: DES requiere 8 bytes. Este demo aceptará length!=8, pero las claves no válidas fallarán.")

    ciphertext = open(args.infile, "rb").read()
    contains = args.contains.lower().encode() if args.contains else b""

    # Fuente de claves
    if args.wordlist:
        keys = wordlist_keys(args.wordlist)
    else:
        keys = product_keys(args.charset, args.length)

    top_heap: List[Tuple[float, str, bytes]] = []  # (score, key, pt)
    tested = 0
    start = time.time()
    last_print = start

    try:
        for key in keys:
            tested += 1
            pt = try_key(ciphertext, key)
            if not pt:
                # también registramos candidatos “casi válidos” con score bajo => no tiene sentido
                pass
            else:
                s = score_plaintext(pt, contains)
                if len(top_heap) < args.top:
                    heapq.heappush(top_heap, (s, key, pt))
                else:
                    # mantenemos min-heap de tamaño fijo
                    if s > top_heap[0][0]:
                        heapq.heapreplace(top_heap, (s, key, pt))

                # ¿hit fuerte?
                if args.stop_on_hit and contains and contains in pt.lower():
                    print_top(top_heap, start, tested)
                    print("\n[+] ¡HIT! Deteniendo en la primera coincidencia fuerte.\n")
                    print(f"[+] Clave: {key}")
                    print(f"[+] Texto:\n{pt.decode(errors='replace')}")
                    return

            # Progreso periódico
            if tested % args.every == 0:
                print_top(top_heap, start, tested)

        # Termina el espacio de búsqueda
        print_top(top_heap, start, tested)
        if top_heap:
            best = max(top_heap, key=lambda x: x[0])
            print("\n[=] Búsqueda finalizada. Mejor candidato:")
            print(f"    key='{best[1]}'  score={best[0]:.3f}")
            print(f"    texto:\n{best[2].decode(errors='replace')}")
        else:
            print("\n[=] No se encontraron candidatos válidos.")

    except KeyboardInterrupt:
        print("\n[!] Interrumpido por el usuario.")
        print_top(top_heap, start, tested)

if __name__ == "__main__":
    main()
