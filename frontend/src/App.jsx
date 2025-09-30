import { Routes, Route } from 'react-router-dom';
import './App.css';
import LandingPage from './pages/LandingPage';
import TransformerPage from './pages/TransformerPage'; // We will build this next

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