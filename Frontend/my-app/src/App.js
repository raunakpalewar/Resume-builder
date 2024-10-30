import React from 'react';
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import './App.css';
import SignIn from './Components/Signin';
import SignUp from './Components/SignUp';

function App() {
  return (
    <Router>
      <div>
        <Routes>
          <Route path="/signin" element={<SignIn />} />
          <Route path="/" element={<SignUp />} />
          {/* Add more routes here if needed */}
        </Routes>
      </div>
    </Router>
  );
}

export default App;
