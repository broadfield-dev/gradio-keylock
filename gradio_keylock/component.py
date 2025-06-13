import gradio as gr
from PIL import Image, ImageDraw, ImageFont
import json
import logging
import os
import struct
import tempfile
import random
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
import numpy as np
import re

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
PREFERRED_FONTS = ["Arial", "Helvetica", "DejaVu Sans", "Verdana", "Calibri", "sans-serif"]

class AppServerLogic:
    def __init__(self):
        self.private_key_object = None
        self.public_key_pem = ""
        self._initialize_keys()

    def _initialize_keys(self):
        key_pem = os.environ.get('KEYLOCK_PRIV_KEY')
        if not key_pem:
            pk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            key_pem = pk.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()).decode('utf-8')
        try:
            self.private_key_object = serialization.load_pem_private_key(key_pem.encode(), password=None)
            self.public_key_pem = self.private_key_object.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')
        except Exception as e:
            logging.error(f"Key initialization failed: {e}")

    @staticmethod
    def _parse_kv_string(kv_string: str) -> dict:
        payload = {}
        if not kv_string:
            return payload
        lines = kv_string.strip().splitlines()
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # Use regex to split only on the first '=' or ':'
            parts = re.split(r'[:=]', line, 1)
            if len(parts) == 2:
                key, value = parts
                key = key.strip()
                value = value.strip()
                
                if (key.startswith('"') and key.endswith('"')) or \
                   (key.startswith("'") and key.endswith("'")):
                    key = key[1:-1]
                if (value.startswith('"') and value.endswith('"')) or \
                   (value.startswith("'") and value.endswith("'")):
                    value = value[1:-1]
                
                if key:
                    payload[key] = value
        return payload

    def decode_payload(self, image_input):
        if not self.private_key_object:
            return {"status": "Error", "message": "Server key not configured."}
        try:
            pixel_data = np.array(image_input.convert("RGB")).ravel()
            header_binary = "".join(str(p & 1) for p in pixel_data[:32])
            data_length = int(header_binary, 2)
            required_pixels = 32 + data_length * 8
            if required_pixels > len(pixel_data):
                raise ValueError("Incomplete payload in image.")
            data_binary = "".join(str(p & 1) for p in pixel_data[32:required_pixels])
            crypto_payload = int(data_binary, 2).to_bytes(data_length, byteorder='big')
            offset = 4
            encrypted_aes_key_len = struct.unpack('>I', crypto_payload[:offset])[0]
            encrypted_aes_key = crypto_payload[offset:offset + encrypted_aes_key_len]; offset += encrypted_aes_key_len
            nonce = crypto_payload[offset:offset + 12]; offset += 12
            ciphertext = crypto_payload[offset:]
            recovered_aes_key = self.private_key_object.decrypt(encrypted_aes_key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            payload = json.loads(AESGCM(recovered_aes_key).decrypt(nonce, ciphertext, None).decode())
            return {"status": "Success", "payload": payload}
        except Exception as e:
            return {"status": "Error", "message": f"Decryption Failed: {e}"}

    @staticmethod
    def _get_font(preferred_fonts, base_size):
        fp = None
        for n in preferred_fonts:
            try: ImageFont.truetype(n.lower()+".ttf", 10); fp = n.lower()+".ttf"; break
            except IOError: continue
        if fp: return ImageFont.truetype(fp, base_size)
        return ImageFont.load_default(size=base_size)

    @staticmethod
    def _generate_starfield_image(w=800, h=800):
        center_x, center_y = w / 2, h / 2
        y_coords, x_coords = np.mgrid[0:h, 0:w]
        distance = np.sqrt((x_coords - center_x)**2 + (y_coords - center_y)**2)
        max_distance = np.sqrt(center_x**2 + center_y**2)
        distance_norm = distance / max_distance
        bg_center_color = np.array([20, 25, 40])
        bg_outer_color = np.array([0, 0, 5])
        gradient = bg_outer_color + (bg_center_color - bg_outer_color) * (1 - distance_norm[..., np.newaxis])
        img = Image.fromarray(gradient.astype(np.uint8), 'RGB')
        draw = ImageDraw.Draw(img)
        for _ in range(int((w * h) / 200)):
            x, y = random.randint(0, w - 1), random.randint(0, h - 1)
            brightness = random.randint(30, 90)
            draw.point((x, y), fill=(int(brightness*0.9), int(brightness*0.9), brightness))
        star_colors = [(255, 255, 255), (220, 230, 255), (255, 240, 220)]
        for _ in range(int((w * h) / 1000)):
            x, y = random.randint(0, w - 1), random.randint(0, h - 1)
            size = 0.5 + (2.5 * (random.random() ** 2))
            brightness = 120 + (135 * (random.random() ** 1.5))
            color = random.choice(star_colors)
            final_color = tuple(int(c * (brightness / 255.0)) for c in color)
            glow_size = size * 3
            glow_color = tuple(int(c * 0.3) for c in final_color)
            draw.ellipse([x - glow_size, y - glow_size, x + glow_size, y + glow_size], fill=glow_color)
            draw.ellipse([x - size, y - size, x + size, y + size], fill=final_color)
        return img

    def _draw_overlay(self, image: Image.Image) -> Image.Image:
        img_overlayed = image.copy().convert("RGBA")
        draw = ImageDraw.Draw(img_overlayed, "RGBA")
        width, height = img_overlayed.size
        overlay_color = (10, 15, 30, 200)
        title_color = (200, 220, 255)
        font_bold = self._get_font(PREFERRED_FONTS, 30)
        draw.rectangle([0, 20, width, 80], fill=overlay_color)
        draw.text((width / 2, 50), "KeyLock Secure Data", fill=title_color, font=font_bold, anchor="ms")
        draw.text((width / 2, 80), "Secure Keys", fill=title_color, font=font_bold, anchor="ms")
        final_image_rgb = Image.new("RGB", img_overlayed.size, (0, 0, 0))
        final_image_rgb.paste(img_overlayed, (0, 0), img_overlayed)
        return final_image_rgb

    def generate_encrypted_image(self, payload_dict):
        if not payload_dict:
            raise gr.Error("Payload is empty or could not be parsed. Please provide valid Key=Value pairs.")
        base_image = self._generate_starfield_image()
        image_with_overlay = self._draw_overlay(base_image)
        json_bytes = json.dumps(payload_dict).encode('utf-8')
        public_key = serialization.load_pem_public_key(self.public_key_pem.encode('utf-8'))
        aes_key, nonce = os.urandom(32), os.urandom(12)
        ciphertext = AESGCM(aes_key).encrypt(nonce, json_bytes, None)
        rsa_key = public_key.encrypt(aes_key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        payload = struct.pack('>I', len(rsa_key)) + rsa_key + nonce + ciphertext
        pixel_data = np.array(image_with_overlay).ravel()
        binary_payload = ''.join(format(b, '08b') for b in struct.pack('>I', len(payload)) + payload)
        pixel_data[:len(binary_payload)] = (pixel_data[:len(binary_payload)] & 0xFE) | np.array(list(binary_payload), dtype=np.uint8)
        final_image = Image.fromarray(pixel_data.reshape(image_with_overlay.size[1], image_with_overlay.size[0], 3), 'RGB')
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
            final_image.save(f.name, "PNG")
            return f.name, f.name

    @staticmethod
    def generate_pem_keys():
        pk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        priv = pk.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()).decode()
        pub = pk.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        return priv, pub

class KeylockDecoderComponent:
    def __init__(self, server_logic: AppServerLogic):
        self.server_logic = server_logic
        self.image_input = None
        self.status_display = None

    def build_ui(self):
        with gr.Group():
            self.image_input = gr.Image(label="KeyLock Image", type="pil", show_label=False)
            self.status_display = gr.Markdown("Upload a KeyLock image to auto-fill credentials.")
            with gr.Accordion("Generate Encrypted Image", open=False):
                payload_input = gr.Textbox(
                    label="Payload to Encrypt (Demo)",
                    placeholder="USER = \"demo-user\"\nPASS: DEMO_test_PASS\n# Lines starting with # are ignored",
                    lines=5,
                    value="""
                    USER = "TestUser"
                    PASS: TestPass
                    "GROQ_API_KEY" = "ALKSDFJASHFKSFH"
                    "HF_API_KEY" : "SDFLSDJFFIEWOIFHOWI"
                    "OPENAI_API_KEY" : SDFLSJDSFSDF
                    """,
                )
                generate_img_button = gr.Button("Generate Image", variant="secondary")
                generated_image_preview = gr.Image(label="Generated Image Preview", type="filepath", interactive=False)
                generated_file_download = gr.File(label="Download Uncorrupted PNG", interactive=False)
            with gr.Accordion("Create New Standalone Key Pair", open=False):
                generate_keys_button = gr.Button("Generate Keys", variant="secondary")
                with gr.Row():
                    output_private_key = gr.Code(label="Generated Private Key", language="python")
                    output_public_key = gr.Code(label="Generated Public Key", language="python")
        
        def generate_wrapper(kv_string):
            payload_dict = self.server_logic._parse_kv_string(kv_string)
            return self.server_logic.generate_encrypted_image(payload_dict)

        generate_img_button.click(
            fn=generate_wrapper,
            inputs=[payload_input],
            outputs=[generated_image_preview, generated_file_download]
        )
        generate_keys_button.click(
            fn=self.server_logic.generate_pem_keys,
            inputs=None,
            outputs=[output_private_key, output_public_key]
        )
        return self.image_input, self.status_display
