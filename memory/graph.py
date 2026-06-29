from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import networkx as nx

logger = logging.getLogger(__name__)


class KnowledgeGraph:
    def __init__(self, db_path: Path = Path("phishx_memory.db")):
        self.db_path = db_path
        self.graph = nx.Graph()

    def build_from_case(self, case_id: str, iocs: Dict[str, List[str]], analysis: Dict[str, Any]) -> None:
        self.graph.add_node(case_id, type="case", verdict=analysis.get("verdict", ""), score=analysis.get("score", 0))
        for ioc_type, values in iocs.items():
            for value in values:
                self.graph.add_node(value, type=ioc_type)
                self.graph.add_edge(case_id, value, relation="contains")
        for reason in analysis.get("reasons", []):
            self.graph.add_node(reason, type="reason")
            self.graph.add_edge(case_id, reason, relation="triggered")
