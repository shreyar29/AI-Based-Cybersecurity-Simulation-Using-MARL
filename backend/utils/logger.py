import csv
import os

class CSVLogger:
    def __init__(self, filepath):
        self.filepath = filepath
        self.file_exists = os.path.exists(filepath)

        if not self.file_exists:
            with open(self.filepath, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "episode",
                    "attacker_reward",
                    "defender_reward",
                    "insider_reward",
                    "soc_reward"
                ])

    def log(self, episode, rewards):
        with open(self.filepath, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                episode,
                rewards["attacker"],
                rewards["defender"],
                rewards["insider"],
                rewards["soc"]
            ])
