# main.py
# Backend server for the Ethical Hacking AI Assistant

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
from peft import PeftModel
import chromadb
from langchain.vectorstores import Chroma
from langchain.embeddings import HuggingFaceEmbeddings
import speech_recognition as sr
from gtts import gTTS
import os
import uuid

# --- Configuration ---
# Specifies the pre-trained model to be used, in this case, a smaller, more manageable version of LLaMA.
MODEL_NAME = "PY007/TinyLlama-1.1B-Chat-v1.0"
# Defines the path to the fine-tuned model adapter, which contains the specialized cybersecurity knowledge.
ADAPTER_PATH = "./model/tinyllama-lora-tuned-adapter-cybersecurity"
# Sets the directory for the ChromaDB vector store, used for Retrieval-Augmented Generation (RAG).
CHROMA_DB_PATH = "./chroma_db"
# Specifies the embedding model for converting text to vectors for ChromaDB.
EMBEDDING_MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"
# Directory to store temporary audio files for voice interaction.
AUDIO_TMP_DIR = "audio_tmp"

# --- Initialization ---
app = FastAPI(
    title="Ethical Hacking AI Assistant API",
    description="An API for an AI assistant specialized in ethical hacking and cybersecurity.",
    version="1.0.0"
)

# Create temporary audio directory if it doesn't exist
os.makedirs(AUDIO_TMP_DIR, exist_ok=True)

# --- Pydantic Models ---
# Defines the structure for incoming text-based queries.
class Query(BaseModel):
    text: str
    use_rag: bool = False

# Defines the structure for incoming voice-based queries.
class VoiceQuery(BaseModel):
    audio_path: str
    use_rag: bool = False

# --- Model and Tokenizer Loading ---
# Configure 4-bit quantization to reduce memory usage and improve performance on consumer hardware.
bnb_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_quant_type="nf4",
    bnb_4bit_compute_dtype=torch.bfloat16,
)

# Load the base model with the specified quantization configuration.
# The device_map="auto" argument automatically uses the GPU if available.
base_model = AutoModelForCausalLM.from_pretrained(
    MODEL_NAME,
    quantization_config=bnb_config,
    device_map="auto",
    trust_remote_code=True,
)

# Load the fine-tuned LoRA adapter and merge it with the base model.
# This creates the specialized cybersecurity model.
model = PeftModel.from_pretrained(base_model, ADAPTER_PATH)
tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME, trust_remote_code=True)
tokenizer.pad_token = tokenizer.eos_token

# --- RAG Setup (ChromaDB) ---
# Initialize embeddings model for RAG.
embeddings = HuggingFaceEmbeddings(model_name=EMBEDDING_MODEL_NAME)
# Initialize ChromaDB client for persistent storage.
vectorstore = Chroma(persist_directory=CHROMA_DB_PATH, embedding_function=embeddings)

# --- Helper Functions ---
def generate_response(query_text: str, use_rag: bool) -> str:
    """
    Generates a response from the LLM, with an option to use RAG.

    Args:
        query_text: The user's query.
        use_rag: Flag to determine if RAG should be used.

    Returns:
        The generated response from the model.
    """
    context = ""
    if use_rag:
        # Retrieve relevant documents from ChromaDB if RAG is enabled.
        docs = vectorstore.similarity_search(query_text, k=3)
        context = "\n".join([doc.page_content for doc in docs])

    # Format the prompt with or without the retrieved context.
    prompt = f"### Instruction:\n{context}\n\n### User:\n{query_text}\n\n### Assistant:"
    
    # Encode the prompt and generate a response from the model.
    inputs = tokenizer(prompt, return_tensors="pt").to("cuda")
    outputs = model.generate(**inputs, max_new_tokens=250, eos_token_id=tokenizer.eos_token_id)
    
    # Decode and return the generated text.
    response = tokenizer.decode(outputs[0], skip_special_tokens=True)
    return response.split("### Assistant:")[-1].strip()

def speech_to_text(audio_path: str) -> str:
    """
    Converts speech from an audio file to text.

    Args:
        audio_path: The path to the audio file.

    Returns:
        The transcribed text.
    """
    r = sr.Recognizer()
    with sr.AudioFile(audio_path) as source:
        audio = r.record(source)
    try:
        return r.recognize_google(audio)
    except sr.UnknownValueError:
        raise HTTPException(status_code=400, detail="Could not understand the audio.")
    except sr.RequestError as e:
        raise HTTPException(status_code=500, detail=f"Speech recognition service error: {e}")

def text_to_speech(text: str) -> str:
    """
    Converts text to speech and saves it as an audio file.

    Args:
        text: The text to be converted.

    Returns:
        The path to the generated audio file.
    """
    tts = gTTS(text=text, lang='en')
    audio_filename = f"{uuid.uuid4()}.mp3"
    audio_path = os.path.join(AUDIO_TMP_DIR, audio_filename)
    tts.save(audio_path)
    return audio_path

# --- API Endpoints ---
@app.post("/query")
async def process_query(query: Query):
    """
    Handles text-based queries to the AI assistant.
    """
    try:
        response_text = generate_response(query.text, query.use_rag)
        return {"response": response_text}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/voice_query")
async def process_voice_query(query: VoiceQuery):
    """
    Handles voice-based queries to the AI assistant.
    """
    try:
        # Convert speech to text.
        query_text = speech_to_text(query.audio_path)
        # Generate a response.
        response_text = generate_response(query_text, query.use_rag)
        # Convert the response text back to speech.
        response_audio_path = text_to_speech(response_text)
        return {"response_text": response_text, "response_audio_path": response_audio_path}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/")
def read_root():
    """
    Root endpoint to confirm the API is running.
    """
    return {"message": "Ethical Hacking AI Assistant API is running."}
