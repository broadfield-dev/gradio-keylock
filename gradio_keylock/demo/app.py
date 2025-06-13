import gradio as gr
from gradio_keylock.component import KeylockDecoderComponent, AppServerLogic
import json

server_logic = AppServerLogic()

example_db = {"USER":"TestUser","PASS":"TestPass"}

def login_fn(username,password):
    if username==example_db.get("USER") and password==example_db.get("PASS"):
        return "### ✅ Logged in"
    else:
        return "### 🛑 Incorrect Username or Password"

def process_image_and_display_payload(image):
    if image is None:
        return "Upload a KeyLock image to auto-fill credentials.", {}

    result_dict = server_logic.decode_payload(image)
    
    if result_dict.get("status") == "Success":
        user = result_dict.get("payload", {}).get("USER", "")
        user_pass = result_dict.get("payload", {}).get("PASS", "")
        
        GROQ_API_KEY = result_dict.get("payload", {}).get("GROQ_API_KEY", "")
        HF_TOKEN = result_dict.get("payload", {}).get("HF_TOKEN", "")
        OPENAI_API_KEY = result_dict.get("payload", {}).get("OPENAI_API_KEY", "")
        OPENROUTER_API_KEY = result_dict.get("payload", {}).get("OPENROUTER_API_KEY", "")
        
        status_message = f"<p style='color:green; font-weight:bold;'>✅ Success! Decoded credentials for '{user}'.</p>"
        payload = result_dict.get("payload", {})
    else:
        message = result_dict.get("message", "An unknown error occurred.")
        status_message = f"<p style='color:red; font-weight:bold;'>❌ Error: {message}</p>"
        payload = {}

    return status_message, payload, user, user_pass, GROQ_API_KEY, HF_TOKEN, OPENAI_API_KEY, OPENROUTER_API_KEY

with gr.Blocks(theme=gr.themes.Soft()) as demo:
    gr.Markdown("# Gradio KeyLock Component Demo")
    gr.Markdown(
        "**Instructions:**\n"
        "1. Use the 'Generate Encrypted Image' section to create a new secure image.\n"
        "2. Download the generated image or drag it to the 'KeyLock Image' upload area.\n"
        "3. The decoded data will **automatically** appear below."
    )
    with gr.Row():
        with gr.Column():
            gr.Markdown("## Login")
            user_name=gr.Textbox(label='User Name')
            user_pass=gr.Textbox(label='Password', type='password')
            login_btn=gr.Button("Login")
            login_msg=gr.Markdown("### Enter user name and password")
            gr.Markdown("## API Keys (Demo)")
            user_GROQ=gr.Textbox(label='GROQ_API_KEY')
            user_HF=gr.Textbox(label='HF_TOKEN')
            user_OPENAI=gr.Textbox(label='OPENAI_API_KEY')
            user_OPENROUTER=gr.Textbox(label='OPENROUTER_API_KEY')
            
        with gr.Column():
            keylock_builder = KeylockDecoderComponent(server_logic)
            image_input, status_display = keylock_builder.build_ui()
        
            output_json = gr.JSON(label="Decoded Payload")
    
    login_btn.click(login_fn,[user_name,user_pass], login_msg)
    image_input.upload(
        fn=process_image_and_display_payload,
        inputs=image_input,
        outputs=[status_display, output_json, user_name, user_pass, user_GROQ, user_HF, user_OPENAI, user_OPENROUTER]
    )

demo.launch()
