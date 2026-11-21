import { createRoot } from 'react-dom/client';
import { BrowserRouter, HashRouter } from 'react-router-dom';
import App from './App';
import './index.css';

const isElectronOrFile =
  typeof window !== 'undefined' &&
  (window.location.protocol === 'file:' || !!(window as any).electronAPI?.isElectron);

const RouterComponent = isElectronOrFile ? HashRouter : BrowserRouter;

createRoot(document.getElementById('root')!).render(
  <RouterComponent>
    <App />
  </RouterComponent>
);

