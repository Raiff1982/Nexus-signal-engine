"""Role-Based Access Control (RBAC) module for Nexus Signal Engine."""

from typing import Dict, List, Set, Optional
from dataclasses import dataclass, field
from enum import Enum
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class ResourceType(str, Enum):
    """Types of resources that can be protected."""
    MESSAGE = "message"
    ANALYSIS = "analysis"
    REPORT = "report"
    USER = "user"
    SYSTEM = "system"
    WEBHOOK = "webhook"

class Action(str, Enum):
    """Actions that can be performed on resources."""
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    EXECUTE = "execute"
    MANAGE = "manage"

@dataclass
class Permission:
    """Permission definition."""
    resource_type: ResourceType
    action: Action
    conditions: Dict = field(default_factory=dict)

@dataclass
class Role:
    """Role definition with associated permissions."""
    name: str
    description: str
    permissions: Set[Permission] = field(default_factory=set)
    metadata: Dict = field(default_factory=dict)

@dataclass
class AccessPolicy:
    """Access policy linking roles to conditions."""
    role: str
    resource_type: ResourceType
    actions: Set[Action]
    conditions: Dict = field(default_factory=dict)

class RBACManager:
    """Manages role-based access control."""
    
    def __init__(self):
        self.roles: Dict[str, Role] = {}
        self.policies: List[AccessPolicy] = []
        self._setup_default_roles()
    
    def _setup_default_roles(self):
        """Set up default roles and permissions."""
        # Admin role
        admin_role = Role(
            name="admin",
            description="System administrator with full access",
            permissions={
                Permission(resource_type=rt, action=action)
                for rt in ResourceType
                for action in Action
            }
        )
        
        # Analyst role
        analyst_role = Role(
            name="analyst",
            description="Security analyst with analysis capabilities",
            permissions={
                Permission(ResourceType.MESSAGE, Action.READ),
                Permission(ResourceType.MESSAGE, Action.CREATE),
                Permission(ResourceType.ANALYSIS, Action.READ),
                Permission(ResourceType.ANALYSIS, Action.CREATE),
                Permission(ResourceType.REPORT, Action.READ),
                Permission(ResourceType.REPORT, Action.CREATE),
            }
        )
        
        # Viewer role
        viewer_role = Role(
            name="viewer",
            description="Read-only access to reports and analyses",
            permissions={
                Permission(ResourceType.ANALYSIS, Action.READ),
                Permission(ResourceType.REPORT, Action.READ),
            }
        )
        
        self.roles.update({
            "admin": admin_role,
            "analyst": analyst_role,
            "viewer": viewer_role
        })
    
    def add_role(self, role: Role):
        """Add a new role to the system."""
        if role.name in self.roles:
            raise ValueError(f"Role {role.name} already exists")
        
        self.roles[role.name] = role
        logger.info(f"Added new role: {role.name}")
    
    def add_policy(self, policy: AccessPolicy):
        """Add a new access policy."""
        self.policies.append(policy)
        logger.info(
            f"Added new policy for role {policy.role} "
            f"on {policy.resource_type}"
        )
    
    def check_permission(
        self,
        role_name: str,
        resource_type: ResourceType,
        action: Action,
        context: Optional[Dict] = None
    ) -> bool:
        """
        Check if a role has permission to perform an action.
        
        Args:
            role_name: Name of the role
            resource_type: Type of resource being accessed
            action: Action being performed
            context: Additional context for permission evaluation
            
        Returns:
            bool: True if permission is granted, False otherwise
        """
        if role_name not in self.roles:
            logger.warning(f"Unknown role: {role_name}")
            return False
        
        role = self.roles[role_name]
        
        # Check direct role permissions
        for permission in role.permissions:
            if (permission.resource_type == resource_type and
                permission.action == action):
                return True
        
        # Check policies
        for policy in self.policies:
            if (policy.role == role_name and
                policy.resource_type == resource_type and
                action in policy.actions):
                
                # Evaluate conditions if present
                if policy.conditions and context:
                    try:
                        return self._evaluate_conditions(
                            policy.conditions,
                            context
                        )
                    except Exception as e:
                        logger.error(
                            f"Error evaluating policy conditions: {str(e)}"
                        )
                        return False
                return True
        
        return False
    
    def _evaluate_conditions(self, conditions: Dict, context: Dict) -> bool:
        """Evaluate policy conditions against context."""
        for key, value in conditions.items():
            if key not in context:
                return False
            
            if isinstance(value, list):
                if context[key] not in value:
                    return False
            elif context[key] != value:
                return False
        
        return True