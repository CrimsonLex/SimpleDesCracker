Encrypt
python3 encrypt_des.py -k "AAABBBAA" -i mensaje.txt -o cipher.bin

Decrypt
python3 bruteforce_des_live_mp.py -i cipher.bin --charset ABCD --length 8 --processes 4