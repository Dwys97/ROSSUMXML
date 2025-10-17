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
import ApiDocsPage from './pages/ApiDocsPage';
import APIDocumentationPage from './pages/APIDocumentationPage';
import UserProfile from './components/profile/UserProfile';
import AdminDashboard from './pages/admin/AdminDashboard';
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
            <Route path="/about" element={<AboutPage />} />
            <Route path="/contact" element={<ContactPage />} />
            <Route path="/api-docs" element={<ApiDocsPage />} />
            <Route path="/api-documentation" element={<APIDocumentationPage />} />
            <Route path="/api-docs" element={<ApiDocsPage />} />
            
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
              path="/admin" 
              element={
                <ProtectedRoute>
                  <AdminDashboard />
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