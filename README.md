# Gradio KeyLock Component

A Gradio custom component that securely encodes JSON data into a visually appealing PNG image and decodes it back. This is achieved through a combination of steganography (LSB encoding) and hybrid encryption (RSA + AES-GCM).

The component provides a user interface for:
1.  **Decoding**: Uploading a KeyLock image to extract the secure payload.
2.  **Encoding**: Generating a new KeyLock image from a JSON payload.
3.  **Key Generation**: Creating new RSA key pairs for use in other applications.

## Installation

You can install the component directly from GitHub:

```bash
pip install git+https://github.com/broadfield-dev/gradio-keylock.git
```

## Usage

The component is composed of two classes: `AppServerLogic`, which handles the cryptography and image manipulation, and `KeylockDecoderComponent`, the Gradio UI component itself.

### Generate a Private Key and save to your environment

```bash
KEYLOCK_PRIV_KEY=**private key value**
```

Here is a simple example of how to use it in a Gradio application:

```python
# demo/app.py
import gradio as gr
from gradio_keylock import KeylockDecoderComponent, AppServerLogic

# Instantiate the backend logic once
server_logic = AppServerLogic()

with gr.Blocks(theme=gr.themes.Soft()) as demo:
    gr.Markdown("# Gradio KeyLock Component Demo")
    gr.Markdown(
        "Upload an image created by the component to see the decoded payload. "
        "You can also generate a new image below."
    )

    # Instantiate the custom component, passing the server logic
    keylock_component = KeylockDecoderComponent(server_logic=server_logic)

    # Create a separate component to display the output
    output_json = gr.JSON(label="Decoded Payload")

    # Define a function to update the output when the component's value changes
    def get_payload(result):
        if result and result.get("status") == "Success":
            return result.get("payload")
        return None

    # Link the component's "change" event to the output display
    keylock_component.change(fn=get_payload, inputs=keylock_component, outputs=output_json)

demo.launch()
```

## Features

-   **Hybrid Encryption**: Uses RSA-OAEP to encrypt an AES key and AES-GCM to encrypt the payload, providing both security and efficiency.
-   **Steganography**: Hides the encrypted payload in the least significant bits (LSB) of an image's pixel data.
-   **Self-Contained UI**: The component includes accordions for generating new images and key pairs directly in the Gradio interface.
-   **Dynamic Image Generation**: Creates a visually pleasing starfield background for each new encoded image.

## Development

To install for development, clone the repository and install in editable mode:
```bash
git clone https://github.com/broadfield-dev/gradio-keylock.git
cd gradio-keylock
pip install -e .
```
