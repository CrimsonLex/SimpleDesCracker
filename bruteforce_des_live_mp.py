#!/usr/bin/env python3
# DES ECB brute-force multiproceso con progreso y Top-N
# Soporta: --wordlist  o  --charset/--length (generado)
# Usa N procesos configurables con --procs (0 = todos los núcleos)

import argparse, itertools, string, time, heapq, sys
from typing import Iterable, Tuple, List, Optional
from multiprocessing import Process, Queue, cpu_count
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
        hits = sum(1 for token in contains.split() if token in lower_pt)
        bonus_kw = min(1.0, 0.25 * hits)

    # 3) heurística simple de “parece español”
    allowed = set(COMMON_ES.encode("utf-8"))
    es_ratio = sum((b in allowed) or chr(b).islower() or chr(b).isspace() for b in pt) / len(pt)

    # mezcla ponderada (ajustable)
    score = 0.55 * print_ratio + 0.35 * es_ratio + 0.10 * bonus_kw
    # boost fuerte si match exacto
    if contains and contains in pt.lower():
        score += 0.50
    return score

# ---------- Generadores de claves ----------
def product_keys_interleaved(charset: str, length: int, start: int, step: int) -> Iterable[str]:
    """
    Recorre charset^length repartiendo el espacio por 'interleaving':
    cada proceso i prueba índices i, i+step, i+2*step, ...
    """
    base = len(charset)
    total = base ** length

    def idx_to_key(i: int) -> str:
        s = []
        for _ in range(length):
            s.append(charset[i % base])
            i //= base
        k = "".join(reversed(s))
        # Ajuste a 8 chars (DES exige 8 bytes exactos)
        if len(k) < 8: k = (k + (k[-1] if k else 'A')*8)[:8]
        if len(k) > 8: k = k[:8]
        return k

    i = start
    while i < total:
        yield idx_to_key(i)
        i += step

def wordlist_chunks(path: str, procs: int) -> List[List[str]]:
    """Carga la wordlist y la divide en N trozos (1 por proceso)."""
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        keys = [ln.strip() for ln in f if len(ln.strip()) == 8]
    if procs <= 1:
        return [keys]
    size = (len(keys) + procs - 1) // procs
    return [keys[i:i+size] for i in range(0, len(keys), size)]

# ---------- Impresión de Top-N ----------
def print_top(top: List[Tuple[float, str, bytes]], start_time: float, kps: float):
    elapsed = max(1e-6, time.time() - start_time)
    print("\n=== PROGRESO ===")
    if kps > 0:
        print(f"Velocidad: {int(kps):,} claves/s  |  Tiempo: {elapsed:,.1f}s")
    print(f"Top {len(top)} candidatos:")
    for rank, (score, key, pt) in enumerate(sorted(top, reverse=True), 1):
        preview = pt[:100].decode(errors="replace").replace("\n", " ")
        print(f"#{rank:02d}  score={score:0.3f}  key='{key}'  :: {preview}")
    print("=" * 60, flush=True)

# ---------- Worker ----------
def worker(ciphertext: bytes, keys_iter: Iterable[str], contains: bytes, every: int, outq: Queue, stopq: Queue):
    tested = 0
    best = (0.0, "", b"")
    start = time.time()
    for key in keys_iter:
        if not stopq.empty():
            break
        tested += 1
        pt = try_key(ciphertext, key)
        if pt:
            s = score_plaintext(pt, contains)
            if s > best[0]:
                best = (s, key, pt)
                outq.put(("best", s, key, pt[:160]))
            if contains and contains in pt.lower():
                outq.put(("hit", s, key, pt))
                stopq.put(True)
                break
        if tested % every == 0:
            kps = tested / max(1e-6, (time.time() - start))
            outq.put(("progress", kps))
    outq.put(("done",) + best)

# ---------- Main ----------
def main():
    ap = argparse.ArgumentParser(description="Brute-force DES/ECB multiproceso con progreso y Top-N")
    ap.add_argument("-i", "--infile", required=True, help="cipher.bin (DES/ECB con padding PKCS#7)")
    ap.add_argument("--contains", default="", help="pista/palabra(s) clave (ej: 'reunete 7 pm')")
    ap.add_argument("--charset", default="AB", help="conjunto de caracteres para generar claves (si no hay wordlist)")
    ap.add_argument("--length", type=int, default=8, help="longitud de clave base (DES=8)")
    ap.add_argument("--wordlist", help="ruta de wordlist (cada línea = clave de 8 chars)")
    ap.add_argument("--every", type=int, default=5000, help="cada N intentos reporta progreso")
    ap.add_argument("--top", type=int, default=8, help="tamaño del ranking Top-N")
    ap.add_argument("--stop-on-hit", action="store_true", help="detener al primer match con contains")
    ap.add_argument("--procs", type=int, default=0, help="Nº de procesos (0 = todos los núcleos)")
    args = ap.parse_args()

    # Advertencias básicas
    if not args.wordlist and (len(args.charset) ** args.length) > 50_000_000:
        print("[!] Advertencia: el espacio de búsqueda es MUY grande. Reduce charset/length o usa --wordlist.")
    if args.length != 8:
        print("[!] Nota: DES requiere 8 bytes. Este demo aceptará length!=8, pero las claves no válidas fallarán.")

    ciphertext = open(args.infile, "rb").read()
    contains = args.contains.lower().encode() if args.contains else b""
    procs = args.procs or max(1, cpu_count())

    # Preparar iteradores de claves por proceso
    key_iters = []
    total_est = 0
    if args.wordlist:
        chunks = wordlist_chunks(args.wordlist, procs)
        total_est = sum(len(c) for c in chunks)
        for i in range(procs):
            key_iters.append(chunks[i] if i < len(chunks) else [])
    else:
        total_est = (len(args.charset) ** args.length)
        for i in range(procs):
            key_iters.append(list(product_keys_interleaved(args.charset, args.length, i, procs)))

    print(f"[*] Núcleos: {procs}  |  Fuente: {'wordlist' if args.wordlist else 'generador'}  |  Espacio ~ {total_est:,} claves")

    outq, stopq = Queue(), Queue()
    ps = [Process(target=worker, args=(ciphertext, key_iters[i], contains, args.every, outq, stopq)) for i in range(procs)]
    for p in ps:
        p.daemon = True
        p.start()

    top_heap: List[Tuple[float, str, bytes]] = []
    start = time.time()
    kps_smoothed = 0.0
    alive = procs

    try:
        while alive:
            msg = outq.get()
            tag = msg[0]
            if tag == "progress":
                kps = msg[1] * procs               # aproximamos velocidad global
                kps_smoothed = 0.7*kps_smoothed + 0.3*kps
                sys.stdout.write(f"\r~{int(kps_smoothed):,} claves/s   ETA: {total_est/max(1,kps_smoothed)/60:.1f} min")
                sys.stdout.flush()
            elif tag == "best":
                score, key, preview = msg[1], msg[2], msg[3]
                prev = preview.decode(errors="replace").replace("\n"," ")
                print(f"\n[TOP] score={score:.3f} key='{key}' :: {prev[:100]}")
                if len(top_heap) < args.top:
                    heapq.heappush(top_heap, (score, key, preview))
                else:
                    if score > top_heap[0][0]:
                        heapq.heapreplace(top_heap, (score, key, preview))
            elif tag == "hit":
                score, key, pt = msg[1], msg[2], msg[3]
                print_top(top_heap, start, kps_smoothed)
                print(f"\n[HIT] key='{key}' score={score:.3f}\n--- Texto ---\n{pt.decode(errors='replace')}\n")
                if args.stop_on_hit:
                    break
            elif tag == "done":
                score, key, pt = msg[1], msg[2], msg[3]
                if key:
                    if len(top_heap) < args.top:
                        heapq.heappush(top_heap, (score, key, pt))
                    else:
                        if score > top_heap[0][0]:
                            heapq.heapreplace(top_heap, (score, key, pt))
                alive -= 1
    except KeyboardInterrupt:
        print("\n[!] Interrumpido por el usuario.")
    finally:
        for p in ps:
            p.terminate()
            p.join(timeout=0.2)

    print_top(top_heap, start, kps_smoothed)
    if top_heap:
        best = max(top_heap, key=lambda x: x[0])
        print(f"\n[=] Búsqueda finalizada. Mejor candidato:\n    key='{best[1]}'  score={best[0]:.3f}")
        try:
            print(f"    texto:\n{best[2].decode(errors='replace')}")
        except:
            pass
    else:
        print("\n[=] No se encontraron candidatos válidos.")

if __name__ == "__main__":
    main()