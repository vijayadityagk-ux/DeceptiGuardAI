🛡️ Project Overview
DeceptiGuard is a next-generation cybersecurity platform designed to detect and retaliate against zero-day phishing, brand spoofing, and social engineering attacks. By utilizing an isolated execution environment and multimodal artificial intelligence, it moves beyond static rule-based filtering to understand manipulative intent and visual deception in real-time.

🚀 Core Features
Multimodal Threat Intake: Extracts text, URLs, and manipulative language from uploaded screenshots, SMS logs, or emails via OCR de-cloaking.

Zero-Trust Playwright Sandbox: Renders suspicious links safely in a headless backend container, capturing a pristine visual viewport and extracting hidden credential forms.

6-Factor Gemini Reasoning: Evaluates psychological coercion, visual brand dissonance, and domain legitimacy using Google's multimodal AI to generate an explainable threat dossier.

Active Honeypot Tarpitting: Retaliates against confirmed credential harvesters by synthesizing decoy data and poisoning the attacker's database via automated form injection.

🏗️ Technical Architecture
Frontend Client: Built with React Native and Expo Web, featuring a dark-mode cybersecurity dashboard and real-time WebSocket telemetry rendering.

FastAPI Gateway: An asynchronous backend managing threat intakes, orchestrating sandbox deployments, and broadcasting live 7-step pipeline status via WebSockets.

Intelligence Engine: Integrates the Google GenAI SDK to cross-reference captured structural data with visual snapshots, ensuring zero-day threat identification.

Persistent Storage: Utilizes SQLAlchemy ORM for logging threat history, spoofed brand targets, and tracking successful honeypot deployments.

⚙️ Quick Start Setup
Clone & Install Dependencies: Run pip install -r requirements.txt in the backend directory and npm install in the frontend directory to prepare the environment.

Environment Configuration: Create a .env file in the backend containing your GEMINI_API_KEY and PostgreSQL or SQLite database connection strings.

Initialize Sandbox: Execute npx playwright install --with-deps chromium on your server to download the necessary headless browser binaries.

Launch Services: Start the backend with uvicorn app.main:app --host 0.0.0.0 --port 8000 and the frontend with npx expo start --web.
