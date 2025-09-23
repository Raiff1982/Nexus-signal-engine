"""Webhook integration for Nexus Signal Engine."""

import aiohttp
import asyncio
from typing import Dict, Any, List, Optional
import json
import logging
from dataclasses import dataclass
from datetime import datetime, UTC

logger = logging.getLogger(__name__)

@dataclass
class WebhookConfig:
    """Configuration for a webhook endpoint."""
    url: str
    secret: Optional[str] = None
    events: List[str] = None
    retry_count: int = 3
    timeout: int = 10

class WebhookManager:
    """Manages webhook subscriptions and deliveries."""
    
    def __init__(self):
        self.webhooks: Dict[str, WebhookConfig] = {}
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def initialize(self):
        """Initialize the aiohttp session."""
        if not self.session:
            self.session = aiohttp.ClientSession()
    
    async def close(self):
        """Close the aiohttp session."""
        if self.session:
            await self.session.close()
            self.session = None
    
    def register_webhook(self, webhook_id: str, config: WebhookConfig):
        """Register a new webhook."""
        self.webhooks[webhook_id] = config
        logger.info(f"Registered webhook {webhook_id} for events {config.events}")
    
    def unregister_webhook(self, webhook_id: str):
        """Unregister a webhook."""
        if webhook_id in self.webhooks:
            del self.webhooks[webhook_id]
            logger.info(f"Unregistered webhook {webhook_id}")
    
    async def notify(self, event: str, payload: Dict[str, Any]):
        """Notify all registered webhooks about an event."""
        if not self.session:
            await self.initialize()
        
        timestamp = datetime.now(UTC).isoformat()
        
        for webhook_id, config in self.webhooks.items():
            if not config.events or event in config.events:
                webhook_payload = {
                    "event": event,
                    "timestamp": timestamp,
                    "data": payload
                }
                
                for attempt in range(config.retry_count):
                    try:
                        async with self.session.post(
                            config.url,
                            json=webhook_payload,
                            timeout=config.timeout
                        ) as response:
                            if response.status == 200:
                                logger.info(f"Successfully notified webhook {webhook_id}")
                                break
                            else:
                                logger.warning(
                                    f"Webhook {webhook_id} returned status {response.status}"
                                )
                    except Exception as e:
                        logger.error(f"Error notifying webhook {webhook_id}: {str(e)}")
                        if attempt == config.retry_count - 1:
                            logger.error(f"Max retries reached for webhook {webhook_id}")
                        await asyncio.sleep(2 ** attempt)  # Exponential backoff