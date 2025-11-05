// Admin overlay injection script
// This script injects an admin button overlay into proxied pages

(function() {
  'use strict';
  
  // Check if admin overlay should be shown
  // This is determined server-side and injected as a script tag
  const adminOverlayEnabled = window.GateProxyAdminOverlay === true;
  
  if (!adminOverlayEnabled) {
    return;
  }
  
  // Create overlay button
  const overlay = document.createElement('div');
  overlay.id = 'gateproxy-admin-overlay';
  overlay.innerHTML = `
    <a href="/gateProxyAdmin" title="Admin Panel" id="gateproxy-admin-button">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z"/>
        <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/>
      </svg>
    </a>
  `;
  
  // Add styles
  const style = document.createElement('style');
  style.textContent = `
    #gateproxy-admin-overlay {
      position: fixed;
      top: 20px;
      right: 20px;
      z-index: 999999;
      pointer-events: none;
    }
    #gateproxy-admin-button {
      display: flex;
      align-items: center;
      justify-content: center;
      width: 48px;
      height: 48px;
      background: rgba(86, 102, 255, 0.9);
      color: white;
      border-radius: 50%;
      text-decoration: none;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
      transition: all 0.2s ease;
      pointer-events: auto;
      backdrop-filter: blur(10px);
    }
    #gateproxy-admin-button:hover {
      background: rgba(86, 102, 255, 1);
      transform: translateY(-2px);
      box-shadow: 0 6px 16px rgba(0, 0, 0, 0.2);
    }
    #gateproxy-admin-button svg {
      width: 20px;
      height: 20px;
    }
    @media (max-width: 768px) {
      #gateproxy-admin-overlay {
        top: 10px;
        right: 10px;
      }
      #gateproxy-admin-button {
        width: 44px;
        height: 44px;
      }
      #gateproxy-admin-button svg {
        width: 18px;
        height: 18px;
      }
    }
  `;
  
  document.head.appendChild(style);
  document.body.appendChild(overlay);
})();

