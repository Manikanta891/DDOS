// src/App.jsx
import React, { useState } from 'react';
import axios from 'axios';
import './App.css';

function App() {
    const [values, setValues] = useState({ value1: null, value2: null, value3: null, value4: null });

    const runPythonScript = () => {
        axios.get('http://localhost:5000/run-script')
            .then(response => {
                const { value1, value2, value3, value4 } = response.data;
                setValues({ value1, value2, value3, value4 });
            })
            .catch(error => {
                console.error('Error running Python script:', error);
            });
    };

    return (
        <div className="App">
            <h1>Run Python Script with Flask</h1>
            <button onClick={runPythonScript}>Run Python Code</button>

            <div className="results">
                <p>Value 1: {values.value1}</p>
                <p>Value 2: {values.value2}</p>
                <p>Value 3: {values.value3}</p>
                <p>Value 4: {values.value4}</p>
            </div>
        </div>
    );
}

export default App;
