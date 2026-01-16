import pyttsx3
import wave
import os


class NarrationRecorder:
    def __init__(self, output_audio):
        self.engine = pyttsx3.init()
        self.engine.setProperty("rate", 155)
        self.engine.setProperty("volume", 1.0)
        self.output_audio = output_audio

    def record(self, messages):
        os.makedirs(os.path.dirname(self.output_audio), exist_ok=True)

        self.engine.save_to_file(" ".join(messages), self.output_audio)
        self.engine.runAndWait()
