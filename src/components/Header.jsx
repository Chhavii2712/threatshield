/**
 * ThreatShield — Header Component
 *
 * Top bar: shield logo, live status, time, feed controls
 */

import { useState, useEffect } from 'react';
import './Header.css';

export default function Header({ isRunning, speed, onTogglePause, onSpeedChange, onClear, stats }) {
  const [time, setTime] = useState(new Date());

  useEffect(() => {
    const timer = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  const formatTime = (d) =>
    d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });

  const formatDate = (d) =>
    d.toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric' });

  return (
    <header className="header" id="header">
      <div className="header__brand">
        <div className="header__logo">
          <svg viewBox="0 0 32 32" className="header__shield-icon" aria-hidden="true">
            <path
              d="M16 2L4 8v8c0 7.2 5.1 13.9 12 15.4C22.9 29.9 28 23.2 28 16V8L16 2z"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
            />
            <path
              d="M16 6L8 10v6c0 5 3.6 9.7 8 10.7V6z"
              fill="url(#shieldGrad)"
              opacity="0.6"
            />
            <path
              d="M12 16l3 3 5-6"
              fill="none"
              stroke="var(--accent-success)"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
            <defs>
              <linearGradient id="shieldGrad" x1="0" y1="0" x2="1" y2="1">
                <stop offset="0%" stopColor="var(--accent-primary)" />
                <stop offset="100%" stopColor="var(--accent-secondary)" />
              </linearGradient>
            </defs>
          </svg>
          <div>
            <h1 className="header__title">ThreatShield</h1>
            <p className="header__subtitle">Security Operations Center</p>
          </div>
        </div>
      </div>

      <div className="header__status">
        <div className={`header__live-dot ${isRunning ? 'header__live-dot--active' : ''}`} />
        <span className="header__live-label">{isRunning ? 'LIVE' : 'PAUSED'}</span>
        <div className="header__divider" />
        <span className="header__event-count mono">{stats.total.toLocaleString()} events</span>
      </div>

      <div className="header__time">
        <span className="header__clock mono">{formatTime(time)}</span>
        <span className="header__date">{formatDate(time)}</span>
      </div>

      <div className="header__controls">
        <button
          className={`header__btn ${isRunning ? 'header__btn--pause' : 'header__btn--play'}`}
          onClick={onTogglePause}
          id="btn-toggle-feed"
          title={isRunning ? 'Pause feed' : 'Resume feed'}
        >
          {isRunning ? (
            <svg viewBox="0 0 20 20" width="16" height="16"><rect x="4" y="3" width="4" height="14" rx="1" fill="currentColor"/><rect x="12" y="3" width="4" height="14" rx="1" fill="currentColor"/></svg>
          ) : (
            <svg viewBox="0 0 20 20" width="16" height="16"><polygon points="4,3 18,10 4,17" fill="currentColor"/></svg>
          )}
        </button>

        <div className="header__speed-group">
          {[1, 2, 5].map((s) => (
            <button
              key={s}
              className={`header__speed-btn ${speed === s ? 'header__speed-btn--active' : ''}`}
              onClick={() => onSpeedChange(s)}
              id={`btn-speed-${s}x`}
            >
              {s}x
            </button>
          ))}
        </div>

        <button className="header__btn header__btn--danger" onClick={onClear} id="btn-clear-feed" title="Clear all events">
          <svg viewBox="0 0 20 20" width="14" height="14"><path d="M5 4h10l-1 12H6L5 4zm3-2h4m-7 2h10" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/></svg>
        </button>
      </div>
    </header>
  );
}
