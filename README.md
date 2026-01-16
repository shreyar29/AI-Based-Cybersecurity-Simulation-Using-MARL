# AI-Based Cybersecurity Simulation Using Multi-Agent Reinforcement Learning (MARL)

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![React](https://img.shields.io/badge/React-18-61DAFB)
![FastAPI](https://img.shields.io/badge/FastAPI-0.68%2B-009688)
![PyTorch](https://img.shields.io/badge/PyTorch-1.9%2B-EE4C2C)
![License](https://img.shields.io/badge/License-MIT-green)

## 📋 Table of Contents
- [Abstract](#abstract)
- [Problem Statement](#problem-statement)
- [Objectives](#objectives)
- [Methodology](#methodology)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Usage](#usage)
- [Evaluation Metrics](#evaluation-metrics)
- [Results](#results)
- [Screenshots](#screenshots)
- [Future Work](#future-work)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

---

## 📝 Abstract
This project presents an advanced **AI-based cybersecurity simulation framework** utilizing **Multi-Agent Reinforcement Learning (MARL)**. It models high-fidelity interactions between **Attacker Agents (Red Team)** and **Defender Agents (Blue Team)** within a simulated enterprise network environment. The system enables the evaluation of adaptive defense strategies against dynamic cyber threats, providing a platform for research into autonomous cyber defense mechanisms.

## ❓ Problem Statement
Traditional rule-based intrusion detection and prevention systems (IDPS) are often reactive and struggle to adapt to novel, sophisticated cyber attacks. Static defense policies fail to account for the dynamic nature of adversary behavior. There is a critical need for **adaptive, autonomous defense systems** capable of learning from interactions and proactively mitigating threats in real-time.

## 🎯 Objectives
- **Develop a Cyber Simulation Environment**: Create a realistic network environment capturing nodes, vulnerabilities, and traffic flow.
- **Implement MARL Agents**: Train autonomous Attacker and Defender agents using Deep Q-Networks (DQN) strategies.
- **Simulate Advanced Scenarios**: Model complex attack vectors including insider threats and multi-stage kill chains.
- **Visualize Interactions**: Provide a real-time React-based dashboard to visualize agent actions, network state, and attack propagation.

## 🔬 Methodology

### Reinforcement Learning Framework
The simulation is modeled as a Markov Game where agents interact with the environment:
- **State Space**: Network topology, node compromise status, traffic logs, and vulnerability states.
- **Action Space**:
    - *Attacker*: Scan, Exploit, Privilege Escalation, Lateral Movement, Data Exfiltration.
    - *Defender*: Monitor, Isolate Node, Patch Vulnerability, Block IP, Deceive (Honeypot).
- **Reward Function**:
    - *Attacker*: Positive reward for compromising nodes and exfiltrating data.
    - *Defender*: Positive reward for maintaining service availability and detecting intrusions; negative reward for false positives or downtime.

### Agents
1. **Attacker Agent (Red)**: Learns to find optimal paths to critical assets.
2. **Defender Agent (Blue)**: Learns to minimize system impact and neutralize threats.
3. **Insider Threat Agent**: Simulates compromised internal accounts with legitimate access.
4. **SOC Agent**: High-level orchestrator for Security Operations Center decision making.

## 🏗️ Architecture
The system consists of a Python-based backend handling the simulation logic and ML training, coupled with a React frontend for visualization.

![Architecture Diagram](https://via.placeholder.com/800x400?text=System+Architecture+Diagram)
*(Placeholder: Insert your high-level architecture diagram here showing the interaction between the Gym Environment, MARL Agents, API Layer, and React UI)*

## 📂 Project Structure

```bash
ai_cybersecurity_simulation/
├── backend/                  # Python Backend & Simulation Logic
│   ├── agents/               # RL Agent implementations (Attacker, Defender, etc.)
│   ├── api/                  # FastAPI routes and WebSocket handlers
│   ├── env/                  # Custom Gym Environment for Cyber Network
│   ├── marl/                 # Deep Learning models (DQN) and Replay Buffers
│   ├── scenarios/            # Attack scenario definitions
│   ├── simulation/           # Simulation orchestration and visualizers
│   ├── utils/                # Helper functions (logging, config)
│   ├── main.py               # Main API entry point
│   ├── train.py              # Training script for RL agents
│   └── requirements.txt      # Python dependencies
│
├── cyber-sim-ui/             # React Frontend Dashboard
│   ├── public/               # Static assets
│   ├── src/                  # React components, stores, and views
│   ├── package.json          # Node dependencies
│   └── requirements.txt      # (Reference) Frontend library list
│
└── README.md                 # Project Documentation
```

## ⚙️ Installation

### Prerequisites
- **Python** 3.8 or higher
- **Node.js** 14.0 or higher
- **npm** or **yarn**

### 1. Backend Setup
Navigate to the backend directory and install Python dependencies.

```bash
cd backend
python -m venv venv
# Windows
.\venv\Scripts\activate
# Linux/Mac
source venv/bin/activate

pip install -r requirements.txt
```
*(Note: If using Windows and `pyttsx3`, ensure `pypiwin32` is installed if errors occur.)*

### 2. Frontend Setup
Navigate to the frontend directory and install Node modules.

```bash
cd cyber-sim-ui
npm install
```

## 🚀 Usage

### Running the Backend
Start the FastAPI server (which hosts the WebSocket endpoint for simulation data).
```bash
# In /backend directory (with venv activated)
uvicorn main:app --reload
```
The API will run at `http://localhost:8000`.

### Running the Simulation / Training
To train the agents or run a headless simulation:
```bash
# In /backend directory
python train.py
```

### Running the Frontend
Start the React development server to view the dashboard.
```bash
# In /cyber-sim-ui directory
npm start
```
Open `http://localhost:3000` in your browser. The UI should connect to the backend WebSocket automatically.

## 🔧 Configuration (.env)
Create a `.env` file in the `backend/` directory for custom configurations (optional).

```ini
# .env.example
ENV_TYPE=production
DEBUG=False
DB_URL=sqlite:///./cyber_sim.db
SECRET_KEY=your_secret_key_here
```

## 📊 Evaluation Metrics
The system performance is evaluated using:
- **Time to Compromise (TTC)**: Time taken by the attacker to reach the target.
- **Time to Detect (TTD)**: Speed of the defender in identifying the breach.
- **System Availability**: Percentage of uptime for critical services.
- **Reward Accumulation**: Convergence of agent policies over episodes.

## 📈 Results
*(Template: Add charts or graphs showing training loss and reward curves over time.)*
- **Training Convergence**: [Insert Graph]
- **Win/Loss Ratio**: [Insert Graph]

## 📸 Screenshots
*(Template: Add screenshots of the simulation dashboard.)*

| Dashboard Overview | Attack Path Visualization |
|:------------------:|:-------------------------:|
| ![Dashboard](https://via.placeholder.com/400x200?text=Dashboard) | ![AttackGraph](https://via.placeholder.com/400x200?text=Attack+Graph) |

## 🔮 Future Work
- Integrate Graph Neural Networks (GNN) for better topology learning.
- Add support for real-time CVE database integration.
- Deploy reinforcement learning agents in a containerized emulation environment (e.g., Mininet, Docker).

## 🤝 Contributing
Contributions are welcome! Please follow these steps:
1. Fork the repository.
2. Create your feature branch (`git checkout -b feature/AmazingFeature`).
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`).
4. Push to the branch (`git push origin feature/AmazingFeature`).
5. Open a Pull Request.

## 🛠️ Troubleshooting
- **WebSocket Connection Failed**: Ensure the backend is running on port 8000 and the frontend is pointing to the correct URL.
- **ModuleNotFoundError**: Run `pip install -r requirements.txt` again to check for missing packages.

## 📜 License
Distributed under the MIT License. See `LICENSE` for more information.

## 👤 Author
**SHREYA R**  

---
*Built for the Advancement of AI in Cybersecurity*
