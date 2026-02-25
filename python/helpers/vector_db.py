# Security: Safe expression evaluation to replace simple_eval (RCE vulnerability)
import ast
import uuid
from collections.abc import Sequence
from typing import Any

# faiss needs to be patched for python 3.12 on arm #TODO remove once not needed
import faiss
from langchain.embeddings import CacheBackedEmbeddings
from langchain.storage import InMemoryByteStore
from langchain_community.docstore.in_memory import InMemoryDocstore
from langchain_community.vectorstores import FAISS
from langchain_community.vectorstores.utils import (
    DistanceStrategy,
)
from langchain_core.documents import Document

# Allowed AST node types for safe expression evaluation
ALLOWED_AST_NODES = {
    ast.Expression, ast.Compare, ast.BoolOp, ast.UnaryOp,
    ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE,
    ast.In, ast.NotIn, ast.Not,
    ast.Name, ast.Constant, ast.List, ast.Tuple, ast.Set,
    ast.Call, ast.Attribute, ast.Subscript
}

# BoolOp and Compare operators are checked via isinstance
BOOL_OPS = {ast.And, ast.Or}
CMP_OPS = {ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.In, ast.NotIn}


def _safe_eval_node(node: ast.AST, data: dict) -> any:
    """Safely evaluate an AST node against the data dictionary."""
    if isinstance(node, ast.Expression):
        return _safe_eval_node(node.body, data)
    elif isinstance(node, ast.Constant):
        return node.value
    elif isinstance(node, ast.Name):
        if node.id in data:
            return data[node.id]
        raise NameError(f"Unknown variable: {node.id}")
    elif isinstance(node, ast.Compare):
        left = _safe_eval_node(node.left, data)
        for op, comparator in zip(node.ops, node.comparators, strict=False):
            right = _safe_eval_node(comparator, data)
            if isinstance(op, ast.Eq):
                left = left == right
            elif isinstance(op, ast.NotEq):
                left = left != right
            elif isinstance(op, ast.Lt):
                left = left < right
            elif isinstance(op, ast.LtE):
                left = left <= right
            elif isinstance(op, ast.Gt):
                left = left > right
            elif isinstance(op, ast.GtE):
                left = left >= right
            elif isinstance(op, ast.In):
                left = left in right
            elif isinstance(op, ast.NotIn):
                left = left not in right
            else:
                raise ValueError(f"Disallowed operator: {type(op).__name__}")
        return left
    elif isinstance(node, ast.BoolOp):
        values = [_safe_eval_node(v, data) for v in node.values]
        if isinstance(node.op, ast.And):
            result = True
            for v in values:
                result = result and v
                if not result:
                    return False
            return result
        elif isinstance(node.op, ast.Or):
            result = False
            for v in values:
                result = result or v
                if result:
                    return True
            return result
        else:
            raise ValueError(f"Disallowed bool op: {type(node.op).__name__}")
    elif isinstance(node, ast.UnaryOp):
        operand = _safe_eval_node(node.operand, data)
        if isinstance(node.op, ast.Not):
            return not operand
        else:
            raise ValueError(f"Disallowed unary op: {type(node.op).__name__}")
    elif isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return [_safe_eval_node(e, data) for e in node.elts]
    elif isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id == "len":
            args = [_safe_eval_node(arg, data) for arg in node.args]
            return len(*args)
        raise ValueError("Function calls are not allowed")
    elif isinstance(node, ast.Attribute):
        raise ValueError("Attribute access is not allowed")
    elif isinstance(node, ast.Subscript):
        value = _safe_eval_node(node.value, data)
        idx = _safe_eval_node(node.slice, data)
        return value[idx]
    else:
        raise ValueError(f"Disallowed node type: {type(node).__name__}")


def safe_eval_condition(condition: str, data: dict) -> any:
    """Safely evaluate a condition string against a data dictionary.

    Replaces simple_eval() with a secure AST-based implementation.
    """
    try:
        tree = ast.parse(condition, mode="eval")
        for node in ast.walk(tree):
            if type(node) not in ALLOWED_AST_NODES:
                raise ValueError(f"Disallowed node type: {type(node).__name__}")
        return _safe_eval_node(tree, data)
    except Exception:
        return False

from agent import Agent  # noqa: E402


class MyFaiss(FAISS):
    # override aget_by_ids
    def get_by_ids(self, ids: Sequence[str], /) -> list[Document]:
        # return all self.docstore._dict[id] in ids
        return [
            self.docstore._dict[id]
            for id in (ids if isinstance(ids, list) else [ids])
            if id in self.docstore._dict
        ]  # type: ignore

    async def aget_by_ids(self, ids: Sequence[str], /) -> list[Document]:
        return self.get_by_ids(ids)

    def get_all_docs(self) -> dict[str, Document]:
        return self.docstore._dict  # type: ignore


class VectorDB:
    _cached_embeddings: dict[str, CacheBackedEmbeddings] = {}

    @staticmethod
    def _get_embeddings(agent: Agent, cache: bool = True):
        model = agent.get_embedding_model()
        if not cache:
            return model  # return raw embeddings if cache is False
        namespace = getattr(
            model,
            "model_name",
            "default",
        )
        if namespace not in VectorDB._cached_embeddings:
            store = InMemoryByteStore()
            VectorDB._cached_embeddings[namespace] = CacheBackedEmbeddings.from_bytes_store(
                model,
                store,
                namespace=namespace,
            )
        return VectorDB._cached_embeddings[namespace]

    def __init__(self, agent: Agent, cache: bool = True):
        self.agent = agent
        self.cache = cache  # store cache preference
        self.embeddings = self._get_embeddings(agent, cache=cache)
        self.index = faiss.IndexFlatIP(len(self.embeddings.embed_query("example")))

        self.db = MyFaiss(
            embedding_function=self.embeddings,
            index=self.index,
            docstore=InMemoryDocstore(),
            index_to_docstore_id={},
            distance_strategy=DistanceStrategy.COSINE,
            # normalize_L2=True,
            relevance_score_fn=cosine_normalizer,
        )

    async def search_by_similarity_threshold(
        self, query: str, limit: int, threshold: float, filter: str = ""
    ):
        comparator = get_comparator(filter) if filter else None

        return await self.db.asearch(
            query,
            search_type="similarity_score_threshold",
            k=limit,
            score_threshold=threshold,
            filter=comparator,
        )

    async def search_by_metadata(self, filter: str, limit: int = 0) -> list[Document]:
        comparator = get_comparator(filter)
        all_docs = self.db.get_all_docs()
        result = []
        for doc in all_docs.values():
            if comparator(doc.metadata):
                result.append(doc)
                # stop if limit reached and limit > 0
                if limit > 0 and len(result) >= limit:
                    break
        return result

    async def insert_documents(self, docs: list[Document]):
        ids = [str(uuid.uuid4()) for _ in range(len(docs))]

        if ids:
            for doc, id in zip(docs, ids, strict=False):
                doc.metadata["id"] = id  # add ids to documents metadata

            self.db.add_documents(documents=docs, ids=ids)
        return ids

    async def delete_documents_by_ids(self, ids: list[str]):
        # aget_by_ids is not yet implemented in faiss, need to do a workaround
        rem_docs = await self.db.aget_by_ids(ids)  # existing docs to remove (prevents error)
        if rem_docs:
            rem_ids = [doc.metadata["id"] for doc in rem_docs]  # ids to remove
            await self.db.adelete(ids=rem_ids)
        return rem_docs


def format_docs_plain(docs: list[Document]) -> list[str]:
    result = []
    for doc in docs:
        text = ""
        for k, v in doc.metadata.items():
            text += f"{k}: {v}\n"
        text += f"Content: {doc.page_content}"
        result.append(text)
    return result


def cosine_normalizer(val: float) -> float:
    res = (1 + val) / 2
    res = max(0, min(1, res))  # float precision can cause values like 1.0000000596046448
    return res


def get_comparator(condition: str):
    def comparator(data: dict[str, Any]):
        # Use safe_eval_condition instead of simple_eval to prevent RCE
        return safe_eval_condition(condition, data)
    return comparator
