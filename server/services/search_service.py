"""Search service — full-text indexing and search."""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class SearchableDocument:
    doc_id: str
    doc_type: str  # event | alert | session
    content: str
    fields: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = 0.0


@dataclass
class SearchResult:
    doc_id: str
    doc_type: str
    score: float
    fields: Dict[str, Any]
    highlights: Dict[str, List[str]] = field(default_factory=dict)


class SearchService:
    """
    In-memory full-text search with TF-IDF scoring.
    For production, use Elasticsearch or OpenSearch.

    Usage::

        svc = SearchService()
        svc.index(doc_id="evt-001", doc_type="event", content="bash prompt injection", fields={...})
        results = svc.search("prompt injection", limit=20)
    """

    def __init__(self) -> None:
        self._docs: Dict[str, SearchableDocument] = {}
        self._inverted_index: Dict[str, Dict[str, int]] = defaultdict(dict)
        # term → {doc_id: term_freq}

    def index(
        self,
        doc_id: str,
        doc_type: str,
        content: str,
        fields: Optional[Dict[str, Any]] = None,
        timestamp: float = 0.0,
    ) -> None:
        """Index a document for full-text search."""
        doc = SearchableDocument(
            doc_id=doc_id,
            doc_type=doc_type,
            content=content.lower(),
            fields=fields or {},
            timestamp=timestamp,
        )
        self._docs[doc_id] = doc

        # Update inverted index
        terms = self._tokenize(content)
        for term in terms:
            self._inverted_index[term][doc_id] = self._inverted_index[term].get(doc_id, 0) + 1

    def index_batch(self, documents: List[Dict[str, Any]]) -> int:
        """Index multiple documents. Returns count indexed."""
        count = 0
        for doc in documents:
            self.index(
                doc_id=doc["doc_id"],
                doc_type=doc.get("doc_type", "event"),
                content=doc.get("content", ""),
                fields=doc.get("fields"),
                timestamp=doc.get("timestamp", 0.0),
            )
            count += 1
        return count

    def search(
        self,
        query: str,
        doc_type: Optional[str] = None,
        start_time: Optional[float] = None,
        end_time: Optional[float] = None,
        limit: int = 50,
        offset: int = 0,
        highlight: bool = True,
    ) -> Tuple[List[SearchResult], int]:
        """
        Search indexed documents. Returns (results, total_count).
        """
        query_terms = self._tokenize(query)
        if not query_terms:
            return [], 0

        # Score documents using TF-IDF-like scoring
        scores: Dict[str, float] = defaultdict(float)
        num_docs = max(len(self._docs), 1)

        for term in query_terms:
            doc_matches = self._inverted_index.get(term, {})
            idf = 1.0  # simplified; real IDF = log(N/df)
            if doc_matches:
                idf = 1.0 + (num_docs / len(doc_matches)) ** 0.5
            for doc_id, tf in doc_matches.items():
                scores[doc_id] += tf * idf

        # Filter
        results: List[SearchResult] = []
        for doc_id, score in sorted(scores.items(), key=lambda x: -x[1]):
            doc = self._docs.get(doc_id)
            if not doc:
                continue
            if doc_type and doc.doc_type != doc_type:
                continue
            if start_time and doc.timestamp < start_time:
                continue
            if end_time and doc.timestamp > end_time:
                continue

            highlights: Dict[str, List[str]] = {}
            if highlight:
                highlights = self._generate_highlights(doc.content, query_terms)

            results.append(SearchResult(
                doc_id=doc_id,
                doc_type=doc.doc_type,
                score=round(score, 4),
                fields=doc.fields,
                highlights=highlights,
            ))

        total = len(results)
        return results[offset:offset + limit], total

    def delete(self, doc_id: str) -> bool:
        """Remove a document from the index."""
        doc = self._docs.pop(doc_id, None)
        if not doc:
            return False
        terms = self._tokenize(doc.content)
        for term in terms:
            self._inverted_index[term].pop(doc_id, None)
        return True

    def stats(self) -> Dict[str, int]:
        return {
            "total_documents": len(self._docs),
            "unique_terms": len(self._inverted_index),
        }

    # ------------------------------------------------------------------

    @staticmethod
    def _tokenize(text: str) -> List[str]:
        """Simple tokenizer — lowercase, split on non-word chars, min length 2."""
        return [t for t in re.split(r"\W+", text.lower()) if len(t) >= 2]

    @staticmethod
    def _generate_highlights(content: str, terms: List[str]) -> Dict[str, List[str]]:
        """Extract context snippets around matched terms."""
        snippets: List[str] = []
        for term in terms[:5]:
            idx = content.find(term)
            if idx >= 0:
                start = max(0, idx - 40)
                end = min(len(content), idx + len(term) + 40)
                snippet = "..." + content[start:end] + "..."
                snippets.append(snippet)
        return {"content": snippets} if snippets else {}
