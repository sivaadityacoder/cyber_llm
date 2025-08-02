"""
Rate limiting middleware.
"""

import time
import redis
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from backend.config import settings
import logging

logger = logging.getLogger(__name__)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limiting middleware using Redis."""
    
    def __init__(self, app):
        super().__init__(app)
        try:
            self.redis_client = redis.from_url(settings.redis_url)
            # Test connection
            self.redis_client.ping()
            self.redis_available = True
        except Exception as e:
            logger.warning(f"Redis not available, using in-memory rate limiting: {e}")
            self.redis_available = False
            self.memory_store = {}
    
    async def dispatch(self, request: Request, call_next):
        """Process rate limiting."""
        client_ip = request.client.host
        current_time = int(time.time())
        window_start = current_time - 60  # 1-minute window
        
        try:
            if self.redis_available:
                # Use Redis for rate limiting
                key = f"rate_limit:{client_ip}"
                pipe = self.redis_client.pipeline()
                pipe.zremrangebyscore(key, 0, window_start)
                pipe.zcard(key)
                pipe.zadd(key, {str(current_time): current_time})
                pipe.expire(key, 60)
                result = pipe.execute()
                request_count = result[1]
            else:
                # Use in-memory store
                if client_ip not in self.memory_store:
                    self.memory_store[client_ip] = []
                
                # Clean old entries
                self.memory_store[client_ip] = [
                    req_time for req_time in self.memory_store[client_ip] 
                    if req_time > window_start
                ]
                
                request_count = len(self.memory_store[client_ip])
                self.memory_store[client_ip].append(current_time)
            
            if request_count >= settings.rate_limit_per_minute:
                raise HTTPException(
                    status_code=429,
                    detail="Rate limit exceeded. Too many requests."
                )
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Rate limiting error: {e}")
            # Continue without rate limiting on error
        
        response = await call_next(request)
        return response