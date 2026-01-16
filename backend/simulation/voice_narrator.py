import pyttsx3
import threading
import queue
import time


class VoiceNarrator:
    def __init__(self):
        self.engine = pyttsx3.init()
        self.engine.setProperty("rate", 155)
        self.engine.setProperty("volume", 1.0)

        self.queue = queue.Queue()
        self._stop_event = threading.Event()

        # Start ONE voice thread
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        while not self._stop_event.is_set():
            try:
                message = self.queue.get(timeout=0.1)
                self.engine.say(message)
                self.engine.runAndWait()
            except queue.Empty:
                continue

    def speak(self, messages):
        for msg in messages:
            self.queue.put(msg)

    def stop(self):
        self._stop_event.set()
