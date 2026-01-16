import cv2
import os


class VideoGenerator:
    def __init__(self, output_path, fps=5):
        self.output_path = output_path
        self.fps = fps
        self.writer = None

    def start(self, frame_shape):
        height, width, channels = frame_shape

        # ✅ Windows-safe codec
        fourcc = cv2.VideoWriter_fourcc(*"XVID")

        # Ensure output directory exists
        os.makedirs(os.path.dirname(self.output_path), exist_ok=True)

        self.writer = cv2.VideoWriter(
            self.output_path,
            fourcc,
            self.fps,
            (width, height)
        )

        if not self.writer.isOpened():
            raise RuntimeError("VideoWriter failed to open")

    def add_frame(self, frame):
        # Ensure uint8 and 3-channel
        frame = frame.astype("uint8")
        if frame.shape[2] == 4:
            frame = frame[:, :, :3]

        self.writer.write(frame)

    def close(self):
        if self.writer:
            self.writer.release()
