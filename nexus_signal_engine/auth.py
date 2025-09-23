"""Authentication and authorization module for Nexus Signal Engine."""

from datetime import datetime, timedelta, UTC
from typing import Optional, Dict, List, Union
from jose import JWTError, jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2AuthorizationCodeBearer
from pydantic import BaseModel, EmailStr
import aiohttp
import logging
from enum import Enum

# Configure logging
logger = logging.getLogger(__name__)

# Security configuration
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

class Role(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"

class Permission(str, Enum):
    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    MANAGE = "manage"

class UserProfile(BaseModel):
    email: EmailStr
    full_name: str
    roles: List[Role]
    permissions: List[Permission]
    metadata: Dict = {}

class Token(BaseModel):
    access_token: str
    token_type: str
    expires_in: int

class AuthConfig:
    """Configuration for OAuth2 providers."""
    def __init__(
        self,
        oauth2_providers: Dict[str, Dict[str, str]],
        jwt_secret_key: str,
        token_expire_minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES
    ):
        self.providers = oauth2_providers
        self.jwt_secret_key = jwt_secret_key
        self.token_expire_minutes = token_expire_minutes

class AuthManager:
    """Manages authentication and authorization."""
    
    def __init__(self, config: AuthConfig):
        self.config = config
        self.users: Dict[str, UserProfile] = {}
        self.oauth2_schemes = {
            provider: OAuth2AuthorizationCodeBearer(
                authorizationUrl=settings["auth_url"],
                tokenUrl=settings["token_url"],
                scopes=settings.get("scopes", {})
            )
            for provider, settings in config.providers.items()
        }
    
    async def authenticate_user(
        self,
        provider: str,
        code: str
    ) -> Optional[UserProfile]:
        """Authenticate user with OAuth2 provider."""
        try:
            provider_config = self.config.providers[provider]
            
            # Exchange authorization code for token
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    provider_config["token_url"],
                    data={
                        "grant_type": "authorization_code",
                        "code": code,
                        "client_id": provider_config["client_id"],
                        "client_secret": provider_config["client_secret"],
                        "redirect_uri": provider_config["redirect_uri"]
                    }
                ) as response:
                    if response.status != 200:
                        logger.error(f"Token exchange failed: {await response.text()}")
                        return None
                    
                    token_data = await response.json()
                    
                # Get user info
                async with session.get(
                    provider_config["userinfo_url"],
                    headers={"Authorization": f"Bearer {token_data['access_token']}"}
                ) as response:
                    if response.status != 200:
                        logger.error(f"User info fetch failed: {await response.text()}")
                        return None
                    
                    user_data = await response.json()
                    
                    # Create or update user profile
                    user_profile = UserProfile(
                        email=user_data["email"],
                        full_name=user_data.get("name", ""),
                        roles=[Role.VIEWER],  # Default role
                        permissions=[Permission.READ],  # Default permission
                        metadata={
                            "provider": provider,
                            "provider_user_id": user_data.get("sub", ""),
                            "last_login": datetime.now(UTC).isoformat()
                        }
                    )
                    
                    self.users[user_profile.email] = user_profile
                    return user_profile
                    
        except Exception as e:
            logger.error(f"Authentication failed: {str(e)}")
            return None
    
    def create_access_token(self, user_profile: UserProfile) -> Token:
        """Create JWT access token."""
        expires_delta = timedelta(minutes=self.config.token_expire_minutes)
        expire = datetime.now(UTC) + expires_delta
        
        to_encode = {
            "sub": user_profile.email,
            "roles": [role.value for role in user_profile.roles],
            "permissions": [perm.value for perm in user_profile.permissions],
            "exp": expire
        }
        
        encoded_jwt = jwt.encode(
            to_encode,
            self.config.jwt_secret_key,
            algorithm=ALGORITHM
        )
        
        return Token(
            access_token=encoded_jwt,
            token_type="bearer",
            expires_in=expires_delta.seconds
        )
    
    async def get_current_user(
        self,
        token: str = Depends(OAuth2AuthorizationCodeBearer)
    ) -> UserProfile:
        """Validate JWT token and return current user."""
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
        try:
            payload = jwt.decode(
                token,
                self.config.jwt_secret_key,
                algorithms=[ALGORITHM]
            )
            email: str = payload.get("sub")
            if email is None:
                raise credentials_exception
            
            user_profile = self.users.get(email)
            if user_profile is None:
                raise credentials_exception
                
            return user_profile
            
        except JWTError:
            raise credentials_exception
    
    def check_permission(
        self,
        user: UserProfile,
        required_permissions: Union[Permission, List[Permission]]
    ) -> bool:
        """Check if user has required permissions."""
        if isinstance(required_permissions, Permission):
            required_permissions = [required_permissions]
            
        # Admin role has all permissions
        if Role.ADMIN in user.roles:
            return True
            
        return all(perm in user.permissions for perm in required_permissions)