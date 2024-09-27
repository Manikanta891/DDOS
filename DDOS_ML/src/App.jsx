import React, { useState, useEffect } from 'react';
import { Pie } from 'react-chartjs-2';
import './App.css'; // Import the CSS file
import {
  Chart as ChartJS,
  ArcElement,
  Tooltip,
  Legend
} from 'chart.js';

// Register required components for ChartJS
ChartJS.register(ArcElement, Tooltip, Legend);

const App = () => {
  const [result, setResult] = useState({
    "Normal Traffic Count": 0,
    "DoS Attack Count": 0,
    "DDoS Attack Count": 0,
    "DDoS Bot Traffic Count": 0,
    "Normal IPs":[],
    "DoS IPs": [],
    "DDoS IPs": [],
    "DDoS Bot IPs": []
  });
  const [isRunning, setIsRunning] = useState(false);
  const [intervalId, setIntervalId] = useState(null);

  const fetchDDoSDetection = async () => {
    try {
      const response = await fetch('http://localhost:5000/api/detect_ddos'); // Change to your Flask API URL
      const data = await response.json();
      setResult(data); // Set the entire result object
    } catch (error) {
      console.error('Error fetching the DDoS detection result:', error);
    }
  };

  const handleStartClick = () => {
    if (!isRunning) {
      setIsRunning(true);
      fetchDDoSDetection(); // Fetch immediately on start
      const id = setInterval(fetchDDoSDetection, 5000); // Fetch every 5 seconds
      setIntervalId(id);
    }
  };

  const handleStopClick = () => {
    if (window.confirm("Are you sure you want to stop DDoS detection?")) {
      setIsRunning(false);
      clearInterval(intervalId); // Stop the interval
    }
  };

  const handleResetClick = () => {
    if (!isRunning) {
      // Reset the result state to initial values
      setResult({
        "Normal Traffic Count": 0,
        "DoS Attack Count": 0,
        "DDoS Attack Count": 0,
        "DDoS Bot Traffic Count": 0,
        "Normal IPs":[],
        "DoS IPs": [],
        "DDoS IPs": [],
        "DDoS Bot IPs": []
      });
    } else {
      alert("Please stop the detection before resetting!");
    }
  };

  useEffect(() => {
    // Clean up the interval on component unmount
    return () => clearInterval(intervalId);
  }, [intervalId]);

  // Collect messages for dropped packets
  const droppedMessages = [
    ...result["DoS IPs"].map(ip => `Packet is dropped from the ${ip}`),
    ...result["DDoS IPs"].map(ip => `Packet is dropped from the ${ip}`),
    ...result["DDoS Bot IPs"].map(ip => `Packet is dropped from the ${ip}`)
  ];

  // Data for the Pie Chart
  const pieData = {
    labels: ['Normal Traffic', 'DoS Attacks', 'DDoS Attacks', 'DDoS Bot Traffic'],
    datasets: [
      {
        label: '# of Packets',
        data: [
          result["Normal Traffic Count"],
          result["DoS Attack Count"],
          result["DDoS Attack Count"],
          result["DDoS Bot Traffic Count"]
        ],
        backgroundColor: ['#36A2EB', '#FF6384', '#FFCE56', '#4BC0C0'], // Colors for each slice
        hoverBackgroundColor: ['#36A2EB', '#FF6384', '#FFCE56', '#4BC0C0']
      }
    ]
  };

  return (
    <div className="container">
      <h1>DDoS Detection System</h1>
  
      {/* Network Traffic Section */}
      <div className="network-traffic">
        <h2>Network Traffic</h2>
        <button onClick={handleStartClick}>Start DDoS Detection</button>
        <button onClick={handleStopClick} disabled={!isRunning}>Stop DDoS Detection</button>
        <button onClick={handleResetClick} disabled={isRunning}>Reset</button>
      </div>
  
      {/* Intrusion Detection System Section */}
      <div className="intrusion-detection">
        <h2>Intrusion Detection System</h2>
        <p><strong>Normal Traffic Count:</strong> {result["Normal Traffic Count"]}</p>
        <p><strong>DoS Attack Count:</strong> {result["DoS Attack Count"]}</p>
        <p><strong>DDoS Attack Count:</strong> {result["DDoS Attack Count"]}</p>
        <p><strong>DDoS Bot Traffic Count:</strong> {result["DDoS Bot Traffic Count"]}</p>
        <p><strong>Normal IPs:</strong> {result["Normal IPs"].length > 0 ? result["Normal IPs"].join(', ') : 'None'}</p>
        <p><strong>DoS IPs:</strong> {result["DoS IPs"].length > 0 ? result["DoS IPs"].join(', ') : 'None'}</p>
        <p><strong>DDoS IPs:</strong> {result["DDoS IPs"].length > 0 ? result["DDoS IPs"].join(', ') : 'None'}</p>
        <p><strong>DDoS Bot IPs:</strong> {result["DDoS Bot IPs"].length > 0 ? result["DDoS Bot IPs"].join(', ') : 'None'}</p>
      </div>
  
      {/* Intrusion Prevention System Section */}
      <div className="intrusion-prevention">
        <div className="prevention-container">
          <h3>Allowed IP Addresses</h3>
          <p>Allowed all packets from {result["Normal IPs"].length > 0 ? result["Normal IPs"].join(', ') : 'None'}</p>
        </div>
        <div className="prevention-container">
          <h3>Blocked IP Addresses</h3>
          <p>Blocked all packets from {[...result["DoS IPs"], ...result["DDoS IPs"]].length > 0 ? [...result["DoS IPs"], ...result["DDoS IPs"]].join(', ') : 'None'}</p>
        </div>
        <div className="prevention-container">
          <h3>Delayed IP Addresses</h3>
          <p>Delayed all packets from {result["DDoS Bot IPs"].length > 0 ? result["DDoS Bot IPs"].join(', ') : 'None'}</p>
        </div>
      </div>
  
      {/* Traffic Distribution Section */}
      <div className="traffic-distribution">
        <h3>Traffic Distribution</h3>
        <div className="chart-container">
          <Pie data={pieData} />
        </div>
      </div>
    </div>
  );
  
};

export default App;
