"""
Chat endpoints for LLM interaction.
"""

from fastapi import APIRouter, HTTPException, Depends
import time
import uuid
import logging
from typing import List

from backend.config import settings
from backend.api.models.schemas import ChatRequest, ChatResponse, ChatMessage
from backend.api.endpoints.auth import get_current_user
from backend.llm.manager import LLMManager
from backend.rag.retrieval import RAGRetriever

logger = logging.getLogger(__name__)

router = APIRouter()

# Initialize LLM manager and RAG retriever
llm_manager = LLMManager()
rag_retriever = RAGRetriever()


@router.post("/", response_model=ChatResponse)
async def chat(
    request: ChatRequest,
    current_user: dict = Depends(get_current_user)
):
    """Main chat endpoint for LLM interaction."""
    start_time = time.time()
    conversation_id = request.conversation_id or str(uuid.uuid4())
    
    try:
        logger.info(f"Chat request from {current_user['username']}: {request.message[:100]}...")
        
        # Prepare context with ethical hacking system prompt
        system_prompt = """You are an expert ethical hacking and cybersecurity assistant. Your role is to help with:

- Bug bounty hunting and vulnerability research
- Penetration testing methodologies
- Security tool usage and automation
- CVE analysis and exploit development
- Security report writing
- OWASP guidelines and best practices

Always provide ethical guidance and emphasize responsible disclosure. Only assist with authorized testing and legitimate security research."""

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": request.message}
        ]
        
        # Use RAG if enabled
        sources = []
        if request.use_rag:
            try:
                relevant_docs = rag_retriever.retrieve(request.message)
                if relevant_docs:
                    context = "\n\n".join([doc.page_content for doc in relevant_docs])
                    enhanced_prompt = f"Context information:\n{context}\n\nUser question: {request.message}"
                    messages[-1]["content"] = enhanced_prompt
                    sources = [doc.metadata.get("source", "unknown") for doc in relevant_docs]
            except Exception as e:
                logger.warning(f"RAG retrieval failed: {e}")
        
        # Get LLM response
        response = await llm_manager.generate_response(
            messages=messages,
            model=request.model,
            temperature=request.temperature,
            max_tokens=request.max_tokens
        )
        
        response_time = time.time() - start_time
        
        logger.info(f"Chat response generated in {response_time:.2f}s")
        
        return ChatResponse(
            response=response["content"],
            conversation_id=conversation_id,
            model_used=response["model"],
            tokens_used=response.get("tokens_used", 0),
            response_time=response_time,
            sources=sources if sources else None
        )
        
    except Exception as e:
        logger.error(f"Chat error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/models")
async def list_models(current_user: dict = Depends(get_current_user)):
    """List available LLM models."""
    try:
        models = llm_manager.list_available_models()
        return {"models": models}
    except Exception as e:
        logger.error(f"Error listing models: {e}")
        raise HTTPException(status_code=500, detail="Failed to list models")


@router.post("/clear/{conversation_id}")
async def clear_conversation(
    conversation_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Clear conversation history."""
    # In a real implementation, this would clear the conversation from the database
    logger.info(f"Cleared conversation {conversation_id} for user {current_user['username']}")
    return {"message": f"Conversation {conversation_id} cleared"}


@router.get("/history")
async def get_chat_history(
    current_user: dict = Depends(get_current_user),
    limit: int = 50
):
    """Get chat history for the current user."""
    # Mock response - implement with real database
    return {
        "conversations": [],
        "total": 0,
        "message": "Chat history feature coming soon"
    }