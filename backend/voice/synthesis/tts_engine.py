"""
Text-to-Speech engine for voice output.
"""

import logging
import tempfile
import os
from typing import Optional
from pathlib import Path

from backend.config import settings

logger = logging.getLogger(__name__)


class TTSEngine:
    """Text-to-Speech engine."""
    
    def __init__(self):
        self.engine = None
        self.temp_dir = Path(tempfile.gettempdir()) / "cyber_llm_audio"
        self.temp_dir.mkdir(exist_ok=True)
        self._initialize_engine()
    
    def _initialize_engine(self):
        """Initialize TTS engine."""
        try:
            import pyttsx3
            self.engine = pyttsx3.init()
            
            # Configure voice properties
            self._configure_voice()
            
        except ImportError:
            logger.warning("pyttsx3 not available - using mock TTS")
            self.engine = None
        except Exception as e:
            logger.error(f"TTS engine initialization error: {e}")
            self.engine = None
    
    def _configure_voice(self):
        """Configure voice properties."""
        if not self.engine:
            return
        
        try:
            # Set speech rate
            self.engine.setProperty('rate', settings.voice_rate)
            
            # Set volume
            self.engine.setProperty('volume', settings.voice_volume)
            
            # Try to set a professional voice
            voices = self.engine.getProperty('voices')
            if voices:
                # Prefer female voice for assistant
                for voice in voices:
                    if 'female' in voice.name.lower() or 'zira' in voice.name.lower():
                        self.engine.setProperty('voice', voice.id)
                        break
                else:
                    # Use first available voice
                    self.engine.setProperty('voice', voices[0].id)
            
        except Exception as e:
            logger.error(f"Voice configuration error: {e}")
    
    def is_available(self) -> bool:
        """Check if TTS is available."""
        return self.engine is not None
    
    def synthesize(self, text: str, save_to_file: bool = True) -> Optional[str]:
        """Convert text to speech."""
        if not self.is_available():
            return self._mock_synthesis(text, save_to_file)
        
        try:
            if save_to_file:
                # Generate audio file
                audio_file = self.temp_dir / f"tts_{hash(text)}.wav"
                self.engine.save_to_file(text, str(audio_file))
                self.engine.runAndWait()
                
                logger.info(f"TTS audio saved: {audio_file}")
                return str(audio_file)
            else:
                # Speak directly
                self.engine.say(text)
                self.engine.runAndWait()
                return None
                
        except Exception as e:
            logger.error(f"TTS synthesis error: {e}")
            return self._mock_synthesis(text, save_to_file)
    
    def _mock_synthesis(self, text: str, save_to_file: bool) -> Optional[str]:
        """Mock TTS for demonstration."""
        if save_to_file:
            # Create a placeholder audio file
            audio_file = self.temp_dir / f"mock_tts_{hash(text)}.wav"
            with open(audio_file, "w") as f:
                f.write(f"Mock audio file for text: {text[:100]}...")
            
            logger.info(f"Mock TTS file created: {audio_file}")
            return str(audio_file)
        else:
            logger.info(f"Mock TTS would speak: {text[:100]}...")
            return None
    
    def speak_async(self, text: str):
        """Speak text asynchronously."""
        if not self.is_available():
            logger.info(f"Mock async speech: {text[:100]}...")
            return
        
        try:
            import threading
            
            def speak_thread():
                self.engine.say(text)
                self.engine.runAndWait()
            
            thread = threading.Thread(target=speak_thread)
            thread.daemon = True
            thread.start()
            
        except Exception as e:
            logger.error(f"Async speech error: {e}")
    
    def get_voices(self) -> list:
        """Get available voices."""
        if not self.is_available():
            return ["mock-voice-1", "mock-voice-2"]
        
        try:
            voices = self.engine.getProperty('voices')
            return [
                {
                    "id": voice.id,
                    "name": voice.name,
                    "gender": "female" if "female" in voice.name.lower() else "male",
                    "language": getattr(voice, 'languages', ['en'])
                }
                for voice in voices
            ]
        except Exception as e:
            logger.error(f"Error getting voices: {e}")
            return []
    
    def set_voice(self, voice_id: str) -> bool:
        """Set voice by ID."""
        if not self.is_available():
            return False
        
        try:
            self.engine.setProperty('voice', voice_id)
            return True
        except Exception as e:
            logger.error(f"Error setting voice: {e}")
            return False
    
    def set_rate(self, rate: int) -> bool:
        """Set speech rate."""
        if not self.is_available():
            return False
        
        try:
            self.engine.setProperty('rate', rate)
            return True
        except Exception as e:
            logger.error(f"Error setting rate: {e}")
            return False
    
    def set_volume(self, volume: float) -> bool:
        """Set speech volume (0.0 to 1.0)."""
        if not self.is_available():
            return False
        
        try:
            self.engine.setProperty('volume', max(0.0, min(1.0, volume)))
            return True
        except Exception as e:
            logger.error(f"Error setting volume: {e}")
            return False
    
    def generate_security_announcements(self, vulnerability_type: str, severity: str) -> str:
        """Generate security-focused announcements."""
        announcements = {
            "xss": {
                "critical": "Critical Cross-Site Scripting vulnerability detected. Immediate action required.",
                "high": "High severity XSS vulnerability found. Review and patch recommended.",
                "medium": "Medium severity XSS issue identified. Schedule remediation.",
                "low": "Low severity XSS detected. Consider fixing during next maintenance."
            },
            "sql_injection": {
                "critical": "Critical SQL Injection vulnerability discovered. Database at risk. Immediate attention required.",
                "high": "High severity SQL Injection found. Data exposure possible.",
                "medium": "Medium severity SQL Injection detected. Review database security.",
                "low": "Low severity SQL Injection identified. Monitor and fix when possible."
            },
            "rce": {
                "critical": "Critical Remote Code Execution vulnerability detected. System compromise possible.",
                "high": "High severity RCE vulnerability found. Immediate patching required.",
                "medium": "Medium severity RCE issue identified. Schedule urgent fixes.",
                "low": "Low severity RCE detected. Review and patch during maintenance."
            }
        }
        
        return announcements.get(vulnerability_type, {}).get(
            severity, 
            f"{severity.title()} severity {vulnerability_type} vulnerability detected."
        )
    
    def generate_scan_status_update(self, scan_type: str, progress: int, total: int) -> str:
        """Generate scan progress announcements."""
        percentage = int((progress / total) * 100) if total > 0 else 0
        
        if percentage == 0:
            return f"Starting {scan_type} scan. Initializing security assessment."
        elif percentage < 25:
            return f"{scan_type} scan in progress. {percentage} percent complete. Initial reconnaissance phase."
        elif percentage < 50:
            return f"{scan_type} scan continuing. {percentage} percent complete. Vulnerability detection phase."
        elif percentage < 75:
            return f"{scan_type} scan advancing. {percentage} percent complete. Deep analysis phase."
        elif percentage < 100:
            return f"{scan_type} scan nearly complete. {percentage} percent done. Finalizing results."
        else:
            return f"{scan_type} scan completed successfully. Generating security report."
    
    def cleanup_temp_files(self):
        """Clean up temporary audio files."""
        try:
            for file_path in self.temp_dir.glob("*.wav"):
                if file_path.exists():
                    file_path.unlink()
            logger.info("Cleaned up temporary audio files")
        except Exception as e:
            logger.error(f"Error cleaning up audio files: {e}")
    
    def __del__(self):
        """Cleanup on destruction."""
        if hasattr(self, 'engine') and self.engine:
            try:
                self.engine.stop()
            except:
                pass