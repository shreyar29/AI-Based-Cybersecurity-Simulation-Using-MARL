from moviepy.video.io.VideoFileClip import VideoFileClip
from moviepy.audio.io.AudioFileClip import AudioFileClip


def merge(video_path, audio_path, output_path):
    video = VideoFileClip(video_path)
    audio = AudioFileClip(audio_path)

    # ✅ MoviePy v2 compatible
    final = video.with_audio(audio)

    final.write_videofile(
        output_path,
        codec="libx264",
        audio_codec="aac"
    )

    video.close()
    audio.close()


if __name__ == "__main__":
    merge(
        video_path="outputs/videos/scenario_4.avi",
        audio_path="outputs/videos/scenario_4.wav",
        output_path="outputs/videos/scenario_4_narrated.mp4"
    )
