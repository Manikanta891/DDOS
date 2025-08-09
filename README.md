# 🛡️ DDoS Prevention System for Cloud Architecture & Tool

This project presents a **Machine Learning-powered Intrusion Detection System (IDS)** to detect and mitigate **DDoS (Distributed Denial of Service) attacks** in cloud environments. The system is part of a broader **DDoS Prevention Tool** which aims to ensure uptime, security, and scalability for cloud-hosted web applications.

---

## 🧠 Project Overview

- 📡 **Goal**: Detect abnormal traffic patterns using ML to identify potential DDoS/DoS attacks.
- ⚙️ **IDS Module**: A supervised ML model trained on network traffic data to classify **normal** vs **malicious** traffic.
- ☁️ **Cloud Deployment**: Built for integration with cloud platforms like AWS, with Docker-based containerization for portability.

---

## 🔍 Problem Statement

> Large-scale DDoS attacks overwhelm cloud services, making websites and APIs unreachable. Traditional firewalls fail to detect new patterns.  
>  
> Our solution: **Build a smart IDS/IPS using Deep Packet Inspection + Machine Learning** to auto-classify and filter traffic before it hits load balancers.

---

## 🧪 How It Works

1. 📥 **Traffic Capture**  
   - Network packets are captured using tools like **Scapy** on a cloud VM (e.g., AWS EC2).

2. 📊 **Feature Extraction**  
   - Important headers and payload patterns are extracted (IP, protocol, packet size, flags, etc.)

3. 🧠 **ML-based IDS Prediction**  
   - A pre-trained ML model (Random Forest) classifies traffic as **normal** or **abnormal**.

4. 🚫 **Action Triggered (IPS)**  
   - If traffic is abnormal, block rules are triggered via firewall/iptables.
   - If traffic is normal, it proceeds to the load balancer.

---

## 📈 Dataset Used

- Publicly available DDoS datasets like **CICIDS2017** and **custom simulated traffic**
- Balanced samples for model performance

---

## ⚙️ Tech Stack

- **Python** for data processing and model development  
- **Scikit-learn / XGBoost** for training IDS  
- **Scapy** for real-time traffic sniffing  
- **Docker** for containerizing IDS model  
- **AWS EC2 + S3** for deployment and logging  

---

## 📌 Key Features

- 🚀 Real-time traffic classification
- 🧠 ML-powered IDS (high detection accuracy)
- 🔒 Auto-blocking malicious IPs
- ☁️ Scalable deployment on cloud
- 📦 Containerized using Docker for portability

---

## 📊 Results

- Achieved >95% accuracy on test data
- Real-time prediction latency < 1 second
- Successfully blocked simulated DDoS attempts in AWS testbed

---

## 🚀 Future Scope

- Develop the IPS component into a fully automated rule engine  
- Add LSTM or Deep Learning for better anomaly detection  
- Build a real-time dashboard with Grafana/ELK stack  
- Deploy using Kubernetes for load-balanced scaling  

---

## 🧑‍💻 Developed By

**Manikanta Sandula**  

> *This project was developed as part of Smart India Hackathon 2024 under the DRDO Problem Statement.*  
> *It showcases my skills in Cloud Security, ML, and Infrastructure Engineering.*

```
