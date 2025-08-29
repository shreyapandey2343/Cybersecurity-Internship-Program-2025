import hashlib
from PIL import Image

# --- Function to generate SHA256 hash of a file ---
def generate_hash(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            sha256.update(chunk)
    return sha256.hexdigest()

# --- Function to embed hash into cover image (LSB method, simple) ---
def embed_hash(cover_image, target_file, stego_image):
    hash_value = generate_hash(target_file)
    print(f"[+] Hash of target file: {hash_value}")

    img = Image.open(cover_image)
    pixels = img.load()

    binary_hash = ''.join(format(ord(c), '08b') for c in hash_value)

    # Store hash bits in the first row pixels
    for i, bit in enumerate(binary_hash):
        x = i % img.width
        y = i // img.width
        r, g, b = pixels[x, y]
        r = (r & ~1) | int(bit)  # change only the last bit of red channel
        pixels[x, y] = (r, g, b)

    img.save(stego_image)
    print(f"[+] Hash embedded into {stego_image}")

# --- Function to extract hash from stego image ---
def extract_hash(stego_image, hash_length=64):  # SHA256 = 64 hex chars
    img = Image.open(stego_image)
    pixels = img.load()

    bits = ""
    for i in range(hash_length * 8):
        x = i % img.width
        y = i // img.width
        r, g, b = pixels[x, y]
        bits += str(r & 1)

    chars = [chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8)]
    hidden_hash = ''.join(chars)
    print(f"[+] Extracted hash: {hidden_hash}")
    return hidden_hash

# --- Main user input flow ---
print("=== Stenographic File Integrity Checker ===")
choice = input("Do you want to (E)mbed or (V)erify? ").strip().lower()

if choice == "e":
    target = input("Enter the path of target file (e.g., report.pdf): ")
    cover = input("Enter the path of cover image (e.g., cover.png): ")
    stego = input("Enter output stego image name (e.g., stego.png): ")
    embed_hash(cover, target, stego)

elif choice == "v":
    target = input("Enter the path of target file (to verify): ")
    stego = input("Enter the path of stego image: ")
    extracted_hash = extract_hash(stego)
    current_hash = generate_hash(target)
    print(f"[+] Current hash of target: {current_hash}")

    if extracted_hash == current_hash:
        print("[✓] File integrity verified — no modification detected.")
    else:
        print("[✗] WARNING: File has been modified!")

else:
    print("Invalid choice. Please enter E or V.")
