import { Routes, Route } from 'react-router-dom';
import './App.css'; // Import component styles
import LandingPage from './pages/LandingPage';
import TransformerPage from './pages/TransformerPage';

function App() {
  return (
    <div className="App">
      <Routes>
        <Route path="/" element={<LandingPage />} />
        <Route path="/transformer" element={<TransformerPage />} />
      </Routes>
    </div>
  );
}

export default App;