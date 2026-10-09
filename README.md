# 🛡️ CYBERPULSE
### AI-Powered Cybersecurity Intelligence & Investigation

> **Don't just detect anomalies. Understand the attack.**

CyberPulse is an AI-assisted cybersecurity intelligence prototype designed to analyze behavioral patterns, identify suspicious activities, evaluate security risks, and support evidence-based investigations.

The system combines behavioral identity analysis, attack progression simulation, risk evaluation, audit logging, and policy enforcement in a unified investigation dashboard.

## 🚀 Key Features

### 1. Behavioral Identity Analysis
- Analyze behavioral patterns of monitored entities.
- Track behavioral mutations and deviations from established baselines.
- Identify potentially suspicious activities.

### 2. Attack Scenario Simulation
- Simulate a five-stage attack progression:
  - Normal Activity
  - Port Scanning
  - Brute Force
  - Lateral Movement
  - Data Exfiltration
- Observe how risk scores change across scenarios.

### 3. Cybersecurity Investigation
- Visualize security incidents and critical alerts.
- Examine entity behavior and supporting evidence.
- Organize information to support investigation workflows.

### 4. Unknown Behavior Detection
- Identify unfamiliar behavioral patterns.
- Evaluate unknown activity using decision-gate logic.
- Support further investigation of uncertain events.

### 5. Audit & Policy Controls
- Evaluate simulated security policy violations.
- Demonstrate deterministic audit verification.
- Apply configurable risk thresholds to flag potential breaches.

### 6. Baseline Poisoning Defense
- Simulate manipulated behavioral baselines.
- Evaluate how suspicious baseline changes affect risk assessment.
- Test defensive logic against simulated poisoning scenarios.

### 7. Risk Analysis & Validation
- Calculate risk scores for simulated activities.
- Test repeatability and counterfactual risk calculations.
- Validate attack progression and reset behavior.

## 🖥️ Application Modules

- Command Center
- Entity Identity
- Investigation
- Audit & Policy

## 🧰 Technology Stack

- React
- TypeScript
- Vite
- Tailwind CSS
- Lucide React
- Google Gemini API integration

## 📁 Project Structure

```text
AI-Cybersecurity-Intelligence/
├── src/
│   ├── data/
│   │   └── syntheticData.ts
│   ├── logic/
│   │   ├── riskEngine.ts
│   │   └── validationEngine.ts
│   ├── pages/
│   │   ├── CommandCenter.tsx
│   │   ├── EntityIdentity.tsx
│   │   ├── Investigation.tsx
│   │   └── UnknownAuditPolicy.tsx
│   ├── types/
│   │   └── cyberpulse.ts
│   ├── App.tsx
│   ├── index.css
│   └── main.tsx
├── .env.example
├── .gitignore
├── index.html
├── metadata.json
├── package.json
├── README.md
├── tsconfig.json
└── vite.config.ts
'''
## 🔗 Project Links

- **GitHub Repository:** https://github.com/joyceolive-26/AI-Cybersecurity-Intelligence
- **Live Demo:** https://cyberpulse-1.ai.studio
