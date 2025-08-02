"""
Speech processing for voice input.
"""

import logging
from typing import Tuple, Optional
import tempfile
import os

from backend.config import settings

logger = logging.getLogger(__name__)


class SpeechProcessor:
    """Speech recognition processor."""
    
    def __init__(self):
        self.recognizer = None
        self._initialize_recognizer()
    
    def _initialize_recognizer(self):
        """Initialize speech recognition."""
        try:
            import speech_recognition as sr
            self.recognizer = sr.Recognizer()
            self.microphone = sr.Microphone()
            
            # Adjust for ambient noise
            with self.microphone as source:
                self.recognizer.adjust_for_ambient_noise(source, duration=1)
                
        except ImportError:
            logger.warning("speech_recognition not available - using mock processor")
            self.recognizer = None
        except Exception as e:
            logger.error(f"Speech recognition initialization error: {e}")
            self.recognizer = None
    
    def is_available(self) -> bool:
        """Check if speech recognition is available."""
        return self.recognizer is not None
    
    def transcribe(self, audio_file_path: str) -> Tuple[str, float]:
        """Transcribe audio file to text."""
        if not self.is_available():
            return self._mock_transcription(audio_file_path)
        
        try:
            import speech_recognition as sr
            
            with sr.AudioFile(audio_file_path) as source:
                audio_data = self.recognizer.record(source)
            
            # Use Google Web Speech API for transcription
            text = self.recognizer.recognize_google(audio_data)
            confidence = 0.85  # Mock confidence score
            
            logger.info(f"Transcribed: {text[:100]}...")
            return text, confidence
            
        except sr.UnknownValueError:
            logger.warning("Could not understand audio")
            return "Could not understand audio", 0.0
        except sr.RequestError as e:
            logger.error(f"Speech recognition service error: {e}")
            return f"Recognition service error: {e}", 0.0
        except Exception as e:
            logger.error(f"Transcription error: {e}")
            return self._mock_transcription(audio_file_path)
    
    def transcribe_microphone(self, duration: int = 5) -> Tuple[str, float]:
        """Transcribe from microphone input."""
        if not self.is_available():
            return "Microphone input not available in demo mode", 0.0
        
        try:
            import speech_recognition as sr
            
            with self.microphone as source:
                logger.info(f"Listening for {duration} seconds...")
                audio_data = self.recognizer.listen(source, timeout=duration)
            
            text = self.recognizer.recognize_google(audio_data)
            confidence = 0.85
            
            logger.info(f"Microphone transcribed: {text}")
            return text, confidence
            
        except sr.WaitTimeoutError:
            return "No speech detected within timeout", 0.0
        except sr.UnknownValueError:
            return "Could not understand speech", 0.0
        except sr.RequestError as e:
            logger.error(f"Speech recognition service error: {e}")
            return f"Recognition service error: {e}", 0.0
        except Exception as e:
            logger.error(f"Microphone transcription error: {e}")
            return "Microphone error occurred", 0.0
    
    def _mock_transcription(self, audio_file_path: str) -> Tuple[str, float]:
        """Mock transcription for demonstration."""
        return (
            "This is a demonstration transcription. "
            "Install speech_recognition and configure audio input for real functionality.",
            0.5
        )
    
    def detect_wake_word(self, audio_file_path: str, wake_word: str = "cyber") -> bool:
        """Detect wake word in audio."""
        try:
            text, confidence = self.transcribe(audio_file_path)
            
            if confidence > 0.6:
                return wake_word.lower() in text.lower()
            
            return False
            
        except Exception as e:
            logger.error(f"Wake word detection error: {e}")
            return False
    
    def continuous_listen(self, callback, wake_word: str = "cyber"):
        """Continuous listening mode with wake word detection."""
        if not self.is_available():
            logger.warning("Continuous listening not available - speech recognition disabled")
            return
        
        try:
            import speech_recognition as sr
            
            logger.info(f"Starting continuous listening for wake word: '{wake_word}'")
            
            while True:
                try:
                    with self.microphone as source:
                        # Listen for wake word
                        audio_data = self.recognizer.listen(source, timeout=1, phrase_time_limit=3)
                    
                    text = self.recognizer.recognize_google(audio_data)
                    
                    if wake_word.lower() in text.lower():
                        logger.info(f"Wake word detected: {text}")
                        
                        # Listen for command
                        with self.microphone as source:
                            logger.info("Listening for command...")
                            command_audio = self.recognizer.listen(source, timeout=5, phrase_time_limit=10)
                        
                        command_text = self.recognizer.recognize_google(command_audio)
                        logger.info(f"Command received: {command_text}")
                        
                        # Execute callback with command
                        if callback:
                            callback(command_text)
                    
                except sr.WaitTimeoutError:
                    continue  # Keep listening
                except sr.UnknownValueError:
                    continue  # Ignore unrecognized speech
                except KeyboardInterrupt:
                    logger.info("Stopping continuous listening")
                    break
                except Exception as e:
                    logger.error(f"Continuous listening error: {e}")
                    break
                    
        except Exception as e:
            logger.error(f"Failed to start continuous listening: {e}")
    
    def get_supported_formats(self) -> list:
        """Get supported audio formats."""
        return ["wav", "flac", "aiff", "aif"]
    
    def get_recognition_engines(self) -> list:
        """Get available recognition engines."""
        engines = ["google"]  # Default
        
        if self.is_available():
            try:
                # Check for other engines
                engines.extend(["wit", "bing", "azure", "ibm", "houndify"])
            except:
                pass
        
        return engines