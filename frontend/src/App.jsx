import React from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { AuthProvider } from './contexts/AuthContext';
import ProtectedRoute from './components/ProtectedRoute';
import LandingPage from './pages/LandingPage';
import EditorPage from './pages/EditorPage';
import TransformerPage from './pages/TransformerPage';
import LoginPage from './pages/LoginPage.jsx';
import RegisterPage from './pages/RegisterPage.jsx';
import RequestDemoPage from './pages/RequestDemoPage';
import SolutionsPage from './pages/SolutionsPage';
import EnterprisePage from './pages/EnterprisePage';
import AboutPage from './pages/AboutPage';
import ContactPage from './pages/ContactPage';
import ApiSettingsPage from './pages/ApiSettingsPage';
import UserProfile from './components/profile/UserProfile';
import './App.css';

function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <div className="app-container">
          <Routes>
            {/* Публичные маршруты */}
            <Route path="/" element={<LandingPage />} />
            <Route path="/login" element={<LoginPage />} />
            <Route path="/register" element={<RegisterPage />} />
            <Route path="/request-demo" element={<RequestDemoPage />} />
            <Route path="/solutions" element={<SolutionsPage />} />
            <Route path="/enterprise" element={<EnterprisePage />} />
            <Route path="/about" element={<AboutPage />} />
            <Route path="/contact" element={<ContactPage />} />
            
            {/* Защищенные маршруты */}
            <Route 
              path="/transformer" 
              element={
                <ProtectedRoute>
                  <TransformerPage />
                </ProtectedRoute>
              } 
            />
            <Route 
              path="/editor" 
              element={
                <ProtectedRoute>
                  <EditorPage />
                </ProtectedRoute>
              } 
            />
            <Route 
              path="/profile" 
              element={
                <ProtectedRoute>
                  <UserProfile />
                </ProtectedRoute>
              } 
            />
            <Route 
              path="/api-settings" 
              element={
                <ProtectedRoute>
                  <ApiSettingsPage />
                </ProtectedRoute>
              } 
            />
          </Routes>
        </div>
      </AuthProvider>
    </BrowserRouter>
  );
}

export default App;