import matplotlib
matplotlib.use("Agg") 
import matplotlib.pyplot as plt
import numpy as np

class SimulationVisualizer:
    def __init__(self):
        self.fig, self.ax = plt.subplots(figsize=(6, 6))

    def draw(self, state, scenario, step):
        self.ax.clear()

        attack = scenario["attack_strength"]
        stealth = scenario["stealth"]
        soc = scenario["soc_load"]

        # Color logic based on attack intensity
        color = "red" if attack > 0.6 else "green"

        nodes = {
            "Server": (0.5, 0.7),
            "Database": (0.7, 0.5),
            "Firewall": (0.5, 0.5),
            "Client1": (0.3, 0.3),
            "Client2": (0.7, 0.3),
            "Client3": (0.2, 0.5),
            "Client4": (0.8, 0.5),
            "SOC": (0.1, 0.8),
            "Gateway": (0.5, 0.9),
            "Cloud": (0.9, 0.8)
        }

        # Plot nodes
        for name, (x, y) in nodes.items():
            self.ax.scatter(x, y, c=color, s=400)
            self.ax.text(x, y + 0.03, name, ha="center", fontsize=8)

        if attack > 0.6:
            self.ax.plot([0.3, 0.5], [0.3, 0.7], "r--", linewidth=2)
            self.ax.plot([0.5, 0.7], [0.7, 0.5], "r--", linewidth=2)

        if stealth > 0.6:
            self.ax.plot([0.5, 0.5], [0.5, 0.7], "g-", linewidth=2)

        self.ax.set_title(
            f"Step {step} | Attack={attack:.2f} | Stealth={stealth:.2f} | SOC Load={soc:.2f}",
            fontsize=10
        )

        self.ax.set_xlim(0, 1)
        self.ax.set_ylim(0, 1)
        self.ax.axis("off")

        self.fig.canvas.draw()
        width, height = self.fig.canvas.get_width_height()

        frame = np.frombuffer(
            self.fig.canvas.buffer_rgba(), dtype=np.uint8
        ).reshape((height, width, 4))

        # Convert RGBA → RGB
        frame = frame[:, :, :3]

        return frame
