"""Base Agent Module for AI Cybersecurity Multi-Agent Investigation Architecture.

Defines the abstract BaseAgent interface, standard execution schemas,
metric tracking, and structured output formatting.
"""

from abc import ABC, abstractmethod
import time
from typing import Dict, Any, List, Optional


class BaseAgent(ABC):
    """Abstract Base Class for all specialized cybersecurity investigation agents."""

    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
        self.call_count = 0
        self.total_execution_time = 0.0
        self.error_count = 0

    @abstractmethod
    def analyze(self, data: Any, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Core analysis method to be implemented by each specialized agent.

        Args:
            data: Structured input telemetry or preceding agent findings.
            context: Optional shared contextual state or investigation metadata.

        Returns:
            Structured dictionary containing findings, evidence, risk, and explanation.
        """
        pass

    def run(self, data: Any, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Wrapper around analyze() with execution timing, error handling, and tracing."""
        self.call_count += 1
        start_time = time.perf_counter()
        
        try:
            result = self.analyze(data, context)
            execution_time = time.perf_counter() - start_time
            self.total_execution_time += execution_time
            
            # Enrich with agent metadata
            result["_agent_meta"] = {
                "agent_name": self.name,
                "execution_time_seconds": round(execution_time, 4),
                "status": "SUCCESS"
            }
            return result
        except Exception as e:
            execution_time = time.perf_counter() - start_time
            self.total_execution_time += execution_time
            self.error_count += 1
            return {
                "agent": self.name,
                "suspicious": False,
                "risk_contribution": 0.0,
                "entities": [],
                "evidence": [f"Execution error: {str(e)}"],
                "events": [],
                "explanation": f"Agent {self.name} encountered an unhandled exception: {str(e)}",
                "_agent_meta": {
                    "agent_name": self.name,
                    "execution_time_seconds": round(execution_time, 4),
                    "status": "ERROR",
                    "error_message": str(e)
                }
            }

    def get_performance_stats(self) -> Dict[str, Any]:
        """Returns runtime performance statistics for this agent."""
        avg_time = (self.total_execution_time / self.call_count) if self.call_count > 0 else 0.0
        return {
            "agent_name": self.name,
            "call_count": self.call_count,
            "total_execution_time_sec": round(self.total_execution_time, 4),
            "average_time_per_call_sec": round(avg_time, 6),
            "error_count": self.error_count
        }
