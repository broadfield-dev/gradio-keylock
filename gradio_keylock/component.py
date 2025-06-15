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
    def __init__(self, server_logic):
        self.server_logic = server_logic
        self.image_input = None
        self.status_display = None
        
        self.CSS = """
            #login-container {
                max-width: 480px;
                margin: 4rem auto !important;
                margin-top: 0px !important;
                padding: 2rem 2.5rem;
                border: 1px solid #30363d;
                border-radius: 12px;
                box-shadow: 0px 0px 14px rgba(0, 0, 0, 0.5);
            }
            #keylock-logo {
                text-align: center;
                font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
                margin-bottom: 1.5rem;
            }
            #keylock-logo svg {
                width: 48px;
                height: 48px;
                fill: #58a6ff;
                margin-bottom: 0.75rem;
            }
            #keylock-logo h1 {
                font-size: 24px;
                font-weight: 600;
                margin: 0;
                color: var(--body-text-color);
            }
            #image-upload-box {
                background-color: #0d1117 !important;
                border: 2px dashed #30363d !important;
                border-radius: 8px !important;
                min-height: 220px;
                transition: border-color 0.2s ease-in-out, background-color 0.2s ease-in-out;
            }
            #image-upload-box:hover {
                border-color: #58a6ff !important;
                background-color: #161b22 !important;
            }
            #image-upload-box .!h-full.w-full > div:first-of-type {
                display: flex;
                align-items: center;
                justify-content: center;
                color: #8b949e;
            }
            #status-display {
                text-align: center;
                padding: 1rem;
                border-radius: 6px;
                margin-top: 1rem;
                min-height: 50px;
                background-color: #161b22;
                border: 1px solid #30363d;
                transition: all 0.3s ease;
            }
            #status-display ul {
                list-style-type: none;
                padding: 0;
                margin: 0.5rem 0 0 0;
                text-align: left;
            }
            #status-display li {
                background-color: #0d1117;
                padding: 0.5rem;
                margin-top: 0.5rem;
                border-radius: 4px;
                border: 1px solid #30363d;
            }
            .tool-accordion {
                border-color: #30363d !important;
                background-color: #0d1117 !important;
                border-radius: 8px !important;
                margin-top: 1.5rem;
            }
            .tool-accordion > .label-wrap {
                background-color: #161b22 !important;
                color: var(--primary-100) !important;
                padding: 10px;
            }
        """

    def _handle_login_attempt(self, image_input: Image.Image):
        if image_input is None:
            return gr.update(value='<p style="color:#8b949e;">Awaiting KeyLock image...</p>', visible=True)
        
        result = self.server_logic.decode_payload(image_input)

        if result["status"] == "Success":
            payload_html = "<ul>"
            for key, value in result['payload'].items():
                value_display = "•" * len(str(value)) if "pass" in key.lower() else value
                payload_html += f"<li><strong>{key}:</strong> {value_display}</li>"
            payload_html += "</ul>"
            
            return gr.update(
                value=f'<div style="color:#3fb950;">'
                      f'<h4>Authentication Success</h4>'
                      f'{payload_html}'
                      f'</div>',
                visible=True
            )
        else:
            return gr.update(
                value=f'<p style="color:#f85149;"><strong>Login Failed:</strong> {result["message"]}</p>',
                visible=True
            )

    def build_ui(self, visible=True, compact=True, closed=True ):
        with gr.Accordion(elem_id="login-container", visible=False if visible==False else True):
            #<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 48" fill="currentColor"><path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zM9 6c0-1.66 1.34-3 3-3s3 1.34 3 3v2H9V6zm9 14H6V10h12v10zm-6-3c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2z"></path></svg>;
        
            gr.HTML("""
                <div id="keylock-logo">
                    <h1>KeyLock Authentication</h1>
                </div>
            """)
            
            self.image_input = gr.Image(
                label="KeyLock Image",
                type="pil",
                show_label=False,
                elem_id="image-upload-box"
            )
            
            self.status_display = gr.HTML(
                '<p style="color:#8b949e;">Upload a KeyLock image to authenticate.</p>',
                elem_id="status-display"
            )

            with gr.Accordion("Generator Tools", open=False if compact==True else True, elem_classes=["tool-accordion"]):
                with gr.Tabs():
                    with gr.TabItem("Encrypt Payload"):
                        payload_input = gr.Textbox(
                            label="Data to Encrypt (Key=Value format)",
                            placeholder="USER = \"demo-user\"\nPASS: DEMO_test_PASS\n# Lines starting with # are ignored",
                            lines=5,
                            value="""USER = "TestUser"\nPASS: TestPass\n"GROQ_API_KEY" = "ALKSDFJASHFKSFH" """,
                        )
                        generate_img_button = gr.Button("Generate Encrypted Image", variant="primary")
                        generated_image_preview = gr.Image(label="Generated Image Preview", type="filepath", interactive=False)
                        generated_file_download = gr.File(label="Download Uncorrupted PNG", interactive=False)
                    
                    with gr.TabItem("Create Key Pair"):
                        gr.Markdown("Create a new standalone RSA-2048 key pair.")
                        generate_keys_button = gr.Button("Generate Keys", variant="secondary")
                        with gr.Row():
                            output_private_key = gr.Code(label="Generated Private Key", language="python", interactive=False)
                            output_public_key = gr.Code(label="Generated Public Key", language="python", interactive=False)

        def generate_wrapper(kv_string):
            payload_dict = self.server_logic._parse_kv_string(kv_string)
            return self.server_logic.generate_encrypted_image(payload_dict)

        self.image_input.upload(
            fn=self._handle_login_attempt,
            inputs=[self.image_input],
            outputs=[self.status_display]
        )
        
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
