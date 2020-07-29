from cube import Cube
import sys
from tqdm import tqdm 


BLOCK_SIZE=54
IV = bytes(c+65 for c in range(54))
KEY = "D R2 F2 D B2 D2 R2 B2 D L2 D' R D B L2 B' L' R' B' F2 R2 D R2 B2 R2 D L2 D2 F2 R2 F' D' B2 D' B U B' L R' D'"


def byte_enc_block(block, key):
	c = Cube(block)
	c.scramble(key)
	return c.get_block_bytes()


def byte_dec_block(block, key):
    c = Cube(block)
    c.unscramble(key)
    return c.get_block_bytes()


def xor(block, key):
    return bytes([b ^ k for b, k in zip(block, key)])


def byte_enc_file(file, iv, key):
    data = b""
    with open(file, "rb") as fp:
        data = fp.read()

    # Pad data to block size of 54
    pad_dat = data if len(data) % BLOCK_SIZE == 0 else (data + b"#" * (BLOCK_SIZE-len(data) % BLOCK_SIZE))
	
    #split into 54 byte chunks
    blocks = [pad_dat[i:i+BLOCK_SIZE] for i in range(0, len(pad_dat), BLOCK_SIZE)]

    # Set up empty cipher blocks in a list with IV block at the start
    cipher_blocks = [iv] + [[] for i in range(len(blocks))]

    i = 0

    for plain_block in tqdm(blocks):
        xor_block = xor(plain_block, cipher_blocks[i])			# Plain XOR Previous Cipher (IV if first)
        cipher_blocks[i+1] = byte_enc_block(xor_block, key)		# Encrypt XOR'd block and add to cipher blocks
        i+=1

    with open("enc_" + file.split('.')[0], "wb") as fp:
        fp.write(b"".join(cipher_blocks[1:]))


def byte_dec_file(file, iv, key):
    with open(file, "rb") as fp:
        data = fp.read()

    # Create a list of cipher blocks with the IV at the start
    cipher_blocks = [iv] + [data[i:i+BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]

    # Create a list of empty lists to store the plaintext in
    plain_blocks = [[] for block in cipher_blocks[1:]]

    i = len(plain_blocks)

    for block in tqdm(cipher_blocks[1:][::-1]):					# For each ciphertext block
        decrypt = byte_dec_block(block, key)					# Decrypt (unscramble) with our key
        plain_blocks[i-1] = xor(decrypt, cipher_blocks[i-1])	# xor the decrypted block with the previous cipher block
        i -= 1

    with open("dec_" + file.split('.')[0], "wb") as fp:
        fp.write(b"".join(plain_blocks))


def main():
    if len(sys.argv) < 3:
        print("\npython {} [-d | -e] FILE\n".format(sys.argv[0]))
        return
    if sys.argv[1] == "-e":
        byte_enc_file(sys.argv[2], IV, KEY)#std_moves_to_py(KEY))
    elif sys.argv[1] == "-d":
        byte_dec_file(sys.argv[2], IV, KEY)#std_moves_to_py(rev_alg(KEY)))


if __name__=="__main__":
	main()