"""
Nexus Signal Engine - A real-world, agent-driven, adversarially resilient AI signal analysis and memory engine.
"""

from .core import NexisSignalEngine
from .hoax import HoaxFilter, HoaxFilterResult

__version__ = '1.0.0'
__all__ = ['NexisSignalEngine', 'HoaxFilter', 'HoaxFilterResult']