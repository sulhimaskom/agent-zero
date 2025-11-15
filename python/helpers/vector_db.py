from typing import Any, List, Sequence
import uuid
import ast
import operator
from langchain_community.vectorstores import FAISS

# faiss needs to be patched for python 3.12 on arm #TODO remove once not needed
from python.helpers import faiss_monkey_patch
import faiss


from langchain_core.documents import Document
from langchain.storage import InMemoryByteStore
from langchain_community.docstore.in_memory import InMemoryDocstore
from langchain_community.vectorstores.utils import (
    DistanceStrategy,
)
from langchain.embeddings import CacheBackedEmbeddings

from agent import Agent


class MyFaiss(FAISS):
    # override aget_by_ids
    def get_by_ids(self, ids: Sequence[str], /) -> List[Document]:
        # return all self.docstore._dict[id] in ids
        return [self.docstore._dict[id] for id in (ids if isinstance(ids, list) else [ids]) if id in self.docstore._dict]  # type: ignore

    async def aget_by_ids(self, ids: Sequence[str], /) -> List[Document]:
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
            VectorDB._cached_embeddings[namespace] = (
                CacheBackedEmbeddings.from_bytes_store(
                    model,
                    store,
                    namespace=namespace,
                )
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
            for doc, id in zip(docs, ids):
                doc.metadata["id"] = id  # add ids to documents metadata

            self.db.add_documents(documents=docs, ids=ids)
        return ids

    async def delete_documents_by_ids(self, ids: list[str]):
        # aget_by_ids is not yet implemented in faiss, need to do a workaround
        rem_docs = await self.db.aget_by_ids(
            ids
        )  # existing docs to remove (prevents error)
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
    res = max(
        0, min(1, res)
    )  # float precision can cause values like 1.0000000596046448
    return res


# Safe operators whitelist for expression evaluation
SAFE_OPERATORS = {
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
    ast.And: lambda a, b: a and b,
    ast.Or: lambda a, b: a or b,
    ast.Not: lambda a: not a,
    ast.In: lambda a, b: a in b,
    ast.NotIn: lambda a, b: a not in b,
}

# Safe functions whitelist
SAFE_FUNCTIONS = {
    'len': len,
    'str': str,
    'int': int,
    'float': float,
    'bool': bool,
    'abs': abs,
    'min': min,
    'max': max,
    'sum': sum,
    'any': any,
    'all': all,
}

def _evaluate_node(node: ast.AST, data: dict[str, Any]) -> Any:
    """Safely evaluate an AST node with restricted operations."""
    if isinstance(node, ast.Constant):
        return node.value
    elif isinstance(node, ast.Name):
        if node.id in data:
            return data[node.id]
        elif node.id in SAFE_FUNCTIONS:
            return SAFE_FUNCTIONS[node.id]
        else:
            raise ValueError(f"Unsafe name access: {node.id}")
    elif isinstance(node, ast.BinOp):
        left = _evaluate_node(node.left, data)
        right = _evaluate_node(node.right, data)
        if type(node.op) in SAFE_OPERATORS:
            return SAFE_OPERATORS[type(node.op)](left, right)
        else:
            raise ValueError(f"Unsafe binary operator: {type(node.op).__name__}")
    elif isinstance(node, ast.UnaryOp):
        operand = _evaluate_node(node.operand, data)
        if type(node.op) in SAFE_OPERATORS:
            return SAFE_OPERATORS[type(node.op)](operand)
        else:
            raise ValueError(f"Unsafe unary operator: {type(node.op).__name__}")
    elif isinstance(node, ast.BoolOp):
        values = [_evaluate_node(value, data) for value in node.values]
        if type(node.op) in SAFE_OPERATORS:
            result = values[0]
            for value in values[1:]:
                result = SAFE_OPERATORS[type(node.op)](result, value)
            return result
        else:
            raise ValueError(f"Unsafe boolean operator: {type(node.op).__name__}")
    elif isinstance(node, ast.Compare):
        left = _evaluate_node(node.left, data)
        for op, comparator in zip(node.ops, node.comparators):
            right = _evaluate_node(comparator, data)
            if type(op) not in SAFE_OPERATORS:
                raise ValueError(f"Unsafe comparison operator: {type(op).__name__}")
            if not SAFE_OPERATORS[type(op)](left, right):
                return False
            left = right
        return True
    elif isinstance(node, ast.Call):
        func = _evaluate_node(node.func, data)
        args = [_evaluate_node(arg, data) for arg in node.args]
        if callable(func) and func in SAFE_FUNCTIONS.values():
            return func(*args)
        else:
            raise ValueError("Unsafe function call")
    elif isinstance(node, ast.Attribute):
        obj = _evaluate_node(node.value, data)
        if hasattr(obj, node.attr):
            attr = getattr(obj, node.attr)
            # Only allow safe attribute access
            if not callable(attr) or attr in SAFE_FUNCTIONS.values():
                return attr
            else:
                raise ValueError(f"Unsafe method access: {node.attr}")
        else:
            raise ValueError(f"Unsafe attribute access: {node.attr}")
    elif isinstance(node, ast.Subscript):
        # Allow safe subscript access like list[index] or dict[key]
        value = _evaluate_node(node.value, data)
        slice_val = _evaluate_node(node.slice, data) if hasattr(node, 'slice') else None
        # Only allow safe subscript operations
        if isinstance(value, (list, tuple, str)) and isinstance(slice_val, int):
            if 0 <= slice_val < len(value):
                return value[slice_val]
            else:
                raise ValueError(f"Index out of bounds: {slice_val}")
        elif isinstance(value, dict):
            return value.get(slice_val, None)
        else:
            raise ValueError(f"Unsafe subscript access on type: {type(value).__name__}")
    else:
        raise ValueError(f"Unsupported AST node type: {type(node).__name__}")

def safe_eval_condition(condition: str, data: dict[str, Any]) -> Any:
    """Safely evaluate a condition string using AST parsing."""
    try:
        # Parse the condition into an AST
        tree = ast.parse(condition, mode='eval')
        
        # Validate the AST contains only safe operations
        class SafeValidator(ast.NodeVisitor):
            def visit(self, node):
                if not isinstance(node, (
                    ast.Expression, ast.BinOp, ast.UnaryOp, ast.BoolOp,
                    ast.Compare, ast.Constant, ast.Name, ast.Call,
                    ast.Attribute, ast.Load, ast.Subscript, ast.Index,
                    ast.Num, ast.Str, ast.NameConstant, ast.List, ast.Tuple,
                    # Allow all operator nodes that are in SAFE_OPERATORS
                    ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE,
                    ast.And, ast.Or, ast.Not, ast.In, ast.NotIn,
                    ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Mod, ast.Pow,
                    ast.LShift, ast.RShift, ast.BitOr, ast.BitXor, ast.BitAnd, ast.Invert,
                    ast.FloorDiv, ast.MatMult
                )):
                    raise ValueError(f"Unsafe AST node: {type(node).__name__}")
                return super().visit(node)
        
        validator = SafeValidator()
        validator.visit(tree)
        
        # Evaluate the parsed AST safely
        return _evaluate_node(tree.body, data)
        
    except Exception as e:
        # Log the error for security monitoring
        # In production, this should be logged to a security monitoring system
        # PrintStyle.error(f"Safe evaluation failed for condition '{condition}': {e}")
        return False

def get_comparator(condition: str):
    def comparator(data: dict[str, Any]):
        try:
            result = safe_eval_condition(condition, data)
            return result
        except Exception as e:
            # PrintStyle.error(f"Error evaluating condition: {e}")
            return False

    return comparator
