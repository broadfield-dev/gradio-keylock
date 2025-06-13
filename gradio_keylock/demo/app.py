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
