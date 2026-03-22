import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App.tsx';
import './index.css';

import { GoogleOAuthProvider } from '@react-oauth/google';
import { ThemeProvider } from './contexts/ThemeContext.tsx';

const clientId = import.meta.env.VITE_GOOGLE_CLIENT_ID;

if (!clientId) {
    console.error("Missing VITE_GOOGLE_CLIENT_ID! Make sure your .env file is set up correctly in the frontend directory.");
}

ReactDOM.createRoot(document.getElementById('root')!).render(
    <React.StrictMode>
        <GoogleOAuthProvider clientId={clientId || ""}>
            <ThemeProvider>
                <App />
            </ThemeProvider>
        </GoogleOAuthProvider>
    </React.StrictMode>,
);