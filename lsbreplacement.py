import cv2, numpy as np

image_name = "icons2.png"

# converts any type of data into binary
# will use this to convert the payload and pixel values to binary in the payload hiding and extracting phase 
def to_bin(data):
    """Convert 'data' to binary format as string"""
    if isinstance(data, str):
        return ''.join([ format(ord(i), "08b") for i in data])
    elif isinstance(data, bytes) or isinstance(data, np.ndarray):
        return [ format(i, "08b") for i in data ]
    elif isinstance(data, int) or isinstance(data, np.uint8):
        return format(data, "08b")
    else:
        raise TypeError("Type not supported.")

# hide secret_data into the image
def encode(image_name, secret_data):
    image = cv2.imread(image_name) # read the image
    n_bytes=image.shape[0] *image.shape[1] * 3 // 8 # maximum bytes to encode
    print("[*] Maximum bytes to encode:", n_bytes)
    secret_data += "=====" # add stopping criteria
    if len(secret_data) > n_bytes:
        raise ValueError("[!] Insufficient bytes, need bigger image or less data.")
    print("[*] Encoding data...")

    data_index = 0
    binary_secret_data = to_bin(secret_data) # convert data to binary
    data_len = len(binary_secret_data) # size of data to hide
    for row in image:
        for pixel in row:
            r, g, b = to_bin(pixel) # convert RGB values to binary format
            if data_index < data_len: # modify LSB only if there is still data to store
                pixel[0] = int(r[:-1] + binary_secret_data[data_index], 2) # LSB red pixel bit
                data_index += 1
            if data_index < data_len:
                pixel[1] = int(g[:-1] + binary_secret_data[data_index], 2) # LSB blue pixel bit
                data_index += 1
            if data_index < data_len:
                pixel[1] = int(b[:-1] + binary_secret_data[data_index], 2) # LSB green pixel bit
                data_index += 1
            if data_index >= data_len: # if data is encoded, just break out of the loop
                break
    return image

def decode(image_name):
    print("[+] Decoding...")
    # read the image
    image = cv2.imread(image_name)
    binary_data = ""
    for row in image:
        for pixel in row:
            r, g, b = to_bin(pixel)
            binary_data += r[-1]
            binary_data += g[-1]
            binary_data += b[-1]
    # split by 8-bits
    all_bytes = [ binary_data[i: i+8] for i in range(0, len(binary_data), 8) ]
    # convert from bits to characters
    decoded_data = ""
    for byte in all_bytes:
        decoded_data += chr(int(byte, 2))
        if decoded_data[-5:] == "=====":
            break
    return decoded_data[-5:]                    
