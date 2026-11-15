import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import { LocaleProvider } from './i18n';
import { NavigationProvider } from './navigation';
import '../../../packages/ui/src/tokens.css';
import './styles.css';

createRoot(document.getElementById('root')!).render(<StrictMode><LocaleProvider><NavigationProvider><App/></NavigationProvider></LocaleProvider></StrictMode>);
