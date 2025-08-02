"""
Voice processing endpoints.
"""

from fastapi import APIRouter, HTTPException, Depends, UploadFile, File
import base64
import tempfile
import os
import logging

from backend.config import settings
from backend.api.models.schemas import VoiceRequest, VoiceResponse
from backend.api.endpoints.auth import get_current_user
from backend.voice.recognition.speech_processor import SpeechProcessor
from backend.voice.synthesis.tts_engine import TTSEngine

logger = logging.getLogger(__name__)

router = APIRouter()

# Initialize voice components
speech_processor = SpeechProcessor()
tts_engine = TTSEngine()


@router.post("/transcribe", response_model=VoiceResponse)
async def transcribe_audio(
    audio_file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user)
):
    """Transcribe audio to text."""
    if not settings.voice_enabled:
        raise HTTPException(status_code=404, detail="Voice features disabled")
    
    try:
        # Save uploaded file temporarily
        with tempfile.NamedTemporaryFile(delete=False, suffix=".wav") as tmp_file:
            content = await audio_file.read()
            tmp_file.write(content)
            tmp_file_path = tmp_file.name
        
        # Process audio
        text, confidence = speech_processor.transcribe(tmp_file_path)
        
        # Clean up
        os.unlink(tmp_file_path)
        
        logger.info(f"Audio transcribed for user {current_user['username']}: {text[:50]}...")
        
        return VoiceResponse(
            text=text,
            confidence=confidence
        )
        
    except Exception as e:
        logger.error(f"Transcription error: {e}")
        raise HTTPException(status_code=500, detail="Failed to transcribe audio")


@router.post("/synthesize")
async def synthesize_speech(
    text: str,
    current_user: dict = Depends(get_current_user)
):
    """Convert text to speech."""
    if not settings.voice_enabled:
        raise HTTPException(status_code=404, detail="Voice features disabled")
    
    try:
        # Generate audio
        audio_path = tts_engine.synthesize(text)
        
        # Convert to base64
        with open(audio_path, "rb") as audio_file:
            audio_data = base64.b64encode(audio_file.read()).decode()
        
        # Clean up
        os.unlink(audio_path)
        
        logger.info(f"Speech synthesized for user {current_user['username']}")
        
        return {
            "audio_data": audio_data,
            "format": "wav",
            "text": text
        }
        
    except Exception as e:
        logger.error(f"Speech synthesis error: {e}")
        raise HTTPException(status_code=500, detail="Failed to synthesize speech")


@router.get("/status")
async def voice_status(current_user: dict = Depends(get_current_user)):
    """Get voice system status."""
    return {
        "voice_enabled": settings.voice_enabled,
        "speech_recognition_available": speech_processor.is_available(),
        "tts_available": tts_engine.is_available(),
        "supported_formats": ["wav", "mp3", "ogg"]
    }