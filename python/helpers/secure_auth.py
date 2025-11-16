"""
Secure authentication utilities for Agent Zero.

This module provides secure authentication mechanisms including:
- Proper password hashing with bcrypt
- Rate limiting to prevent brute force attacks
- Session management with secure tokens
- Login attempt monitoring and logging
"""

import bcrypt
import secrets
import time
import hashlib
import logging
from typing import Optional, Dict, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
from python.helpers import dotenv

logger = logging.getLogger(__name__)


@dataclass
class LoginAttempt:
    """Track login attempts for rate limiting."""
    count: int = 0
    last_attempt: float = 0.0
    locked_until: float = 0.0


class SecureAuth:
    """
    Secure authentication manager with proper password hashing,
    rate limiting, and session management.
    """
    
    # Rate limiting configuration
    MAX_ATTEMPTS = 5
    LOCKOUT_DURATION = 900  # 15 minutes in seconds
    ATTEMPT_WINDOW = 300    # 5 minutes in seconds
    
    # Session configuration
    SESSION_TIMEOUT = 86400  # 24 hours in seconds
    TOKEN_LENGTH = 32
    
    def __init__(self):
        self._login_attempts: Dict[str, LoginAttempt] = {}
        self._active_sessions: Dict[str, Dict] = {}
        
    def hash_password(self, password: str) -> str:
        """
        Hash a password using bcrypt with proper salt.
        
        Args:
            password: Plain text password
            
        Returns:
            Hashed password string
        """
        # Generate a salt and hash the password
        salt = bcrypt.gensalt(rounds=12)
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')
    
    def verify_password(self, password: str, hashed_password: str) -> bool:
        """
        Verify a password against its hash.
        
        Args:
            password: Plain text password to verify
            hashed_password: Stored hashed password
            
        Returns:
            True if password matches, False otherwise
        """
        try:
            return bcrypt.checkpw(
                password.encode('utf-8'), 
                hashed_password.encode('utf-8')
            )
        except Exception as e:
            logger.error(f"Password verification error: {e}")
            return False
    
    def is_rate_limited(self, identifier: str) -> Tuple[bool, Optional[int]]:
        """
        Check if a user/identifier is rate limited.
        
        Args:
            identifier: User identifier (IP, username, etc.)
            
        Returns:
            Tuple of (is_limited, remaining_lockout_time)
        """
        now = time.time()
        attempt = self._login_attempts.get(identifier, LoginAttempt())
        
        # Check if currently locked out
        if attempt.locked_until > now:
            remaining_time = int(attempt.locked_until - now)
            return True, remaining_time
        
        # Reset old attempts outside the window
        if now - attempt.last_attempt > self.ATTEMPT_WINDOW:
            attempt.count = 0
        
        return False, None
    
    def record_failed_attempt(self, identifier: str) -> Tuple[bool, Optional[int]]:
        """
        Record a failed login attempt and apply rate limiting if needed.
        
        Args:
            identifier: User identifier (IP, username, etc.)
            
        Returns:
            Tuple of (is_now_locked, lockout_duration)
        """
        now = time.time()
        attempt = self._login_attempts.get(identifier, LoginAttempt())
        
        # Reset old attempts outside the window
        if now - attempt.last_attempt > self.ATTEMPT_WINDOW:
            attempt.count = 0
        
        attempt.count += 1
        attempt.last_attempt = now
        
        # Check if should be locked out
        if attempt.count >= self.MAX_ATTEMPTS:
            attempt.locked_until = now + self.LOCKOUT_DURATION
            self._login_attempts[identifier] = attempt
            
            logger.warning(
                f"Authentication locked for {identifier} due to {attempt.count} failed attempts"
            )
            return True, self.LOCKOUT_DURATION
        
        self._login_attempts[identifier] = attempt
        return False, None
    
    def record_successful_login(self, identifier: str):
        """
        Record a successful login and reset failed attempts.
        
        Args:
            identifier: User identifier (IP, username, etc.)
        """
        # Clear failed attempts for this identifier
        if identifier in self._login_attempts:
            del self._login_attempts[identifier]
        
        logger.info(f"Successful authentication for {identifier}")
    
    def generate_session_token(self) -> str:
        """
        Generate a secure session token.
        
        Returns:
            Cryptographically secure random token
        """
        return secrets.token_urlsafe(self.TOKEN_LENGTH)
    
    def create_session(self, user_data: Dict) -> str:
        """
        Create a new authenticated session.
        
        Args:
            user_data: User information to store in session
            
        Returns:
            Session token
        """
        token = self.generate_session_token()
        now = time.time()
        
        session_data = {
            'user_data': user_data,
            'created_at': now,
            'last_accessed': now,
            'expires_at': now + self.SESSION_TIMEOUT
        }
        
        self._active_sessions[token] = session_data
        return token
    
    def validate_session(self, token: str) -> Optional[Dict]:
        """
        Validate a session token and return user data if valid.
        
        Args:
            token: Session token to validate
            
        Returns:
            User data if valid, None otherwise
        """
        session = self._active_sessions.get(token)
        if not session:
            return None
        
        now = time.time()
        
        # Check if session has expired
        if now > session['expires_at']:
            self.invalidate_session(token)
            return None
        
        # Update last accessed time
        session['last_accessed'] = now
        
        return session['user_data']
    
    def invalidate_session(self, token: str):
        """
        Invalidate a session token.
        
        Args:
            token: Session token to invalidate
        """
        if token in self._active_sessions:
            del self._active_sessions[token]
    
    def cleanup_expired_sessions(self):
        """Remove expired sessions from memory."""
        now = time.time()
        expired_tokens = []
        
        for token, session in self._active_sessions.items():
            if now > session['expires_at']:
                expired_tokens.append(token)
        
        for token in expired_tokens:
            del self._active_sessions[token]
        
        if expired_tokens:
            logger.info(f"Cleaned up {len(expired_tokens)} expired sessions")
    
    def get_credentials_hash(self) -> Optional[str]:
        """
        Get the hash of configured credentials for backward compatibility.
        
        Returns:
            SHA256 hash of username:password for legacy compatibility
        """
        user = dotenv.get_dotenv_value("AUTH_LOGIN")
        password = dotenv.get_dotenv_value("AUTH_PASSWORD")
        
        if not user:
            return None
        
        # Use SHA256 for backward compatibility with existing sessions
        return hashlib.sha256(f"{user}:{password}".encode()).hexdigest()
    
    def verify_credentials(self, username: str, password: str) -> bool:
        """
        Verify user credentials against configured values.
        
        Args:
            username: Provided username
            password: Provided password
            
        Returns:
            True if credentials are valid
        """
        configured_user = dotenv.get_dotenv_value("AUTH_LOGIN")
        configured_password = dotenv.get_dotenv_value("AUTH_PASSWORD")
        
        if not configured_user or not configured_password:
            return False
        
        return username == configured_user and password == configured_password
    
    def get_auth_stats(self) -> Dict:
        """
        Get authentication statistics for monitoring.
        
        Returns:
            Dictionary with auth statistics
        """
        return {
            'active_sessions': len(self._active_sessions),
            'tracked_login_attempts': len(self._login_attempts),
            'locked_identifiers': sum(
                1 for attempt in self._login_attempts.values() 
                if attempt.locked_until > time.time()
            )
        }


# Global authentication instance
_auth_manager = SecureAuth()


def get_auth_manager() -> SecureAuth:
    """Get the global authentication manager instance."""
    return _auth_manager


def cleanup_expired_sessions():
    """Clean up expired sessions (call periodically)."""
    _auth_manager.cleanup_expired_sessions()