from Crypto.Cipher import DES
from Crypto.Util.Padding import pad
import argparse

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-k", "--key", required=True, help="Clave de 8 bytes exactos")
    parser.add_argument("-i", "--infile", required=True, help="Archivo de entrada")
    parser.add_argument("-o", "--outfile", default="cipher.bin", help="Archivo cifrado")
    args = parser.parse_args()

    key = args.key.encode()
    if len(key) != 8:
        raise ValueError("La clave debe tener exactamente 8 caracteres")

    data = open(args.infile, "rb").read()
    cipher = DES.new(key, DES.MODE_ECB)
    ct_bytes = cipher.encrypt(pad(data, 8))

    open(args.outfile, "wb").write(ct_bytes)
    print(f"[OK] Mensaje cifrado con clave: {args.key}")

if __name__ == "__main__":
    main()
