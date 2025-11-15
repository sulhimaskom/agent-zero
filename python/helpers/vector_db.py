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
    ast.In: lambda a, b: a in b,
    ast.NotIn: lambda a, b: a not in b,
}

def safe_eval_condition(condition: str, data: dict[str, Any]) -> bool:
    """
    Safely evaluate a condition expression against metadata dictionary.
    
    This function uses AST parsing to safely evaluate expressions without using eval().
    Only allows basic comparisons, logical operators, and field access.
    
    Args:
        condition: String expression to evaluate (e.g., "status == 'active' and priority > 5")
        data: Dictionary containing the data to evaluate against
        
    Returns:
        Boolean result of the evaluation
        
    Raises:
        ValueError: If the expression contains unsafe operations
        SyntaxError: If the expression has invalid syntax
    """
    try:
        # Parse the expression into an AST
        tree = ast.parse(condition, mode='eval')
        return _evaluate_node(tree.body, data)
    except SyntaxError as e:
        raise SyntaxError(f"Invalid syntax in condition: {e}")
    except Exception as e:
        # Log the error for security monitoring
        # PrintStyle.error(f"Error evaluating condition '{condition}': {e}")
        return False

def _evaluate_node(node: ast.AST, data: dict[str, Any]) -> Any:
    """
    Recursively evaluate AST nodes safely.
    
    Args:
        node: AST node to evaluate
        data: Data dictionary for variable lookup
        
    Returns:
        Evaluated result
        
    Raises:
        ValueError: If unsafe operation is detected
    """
    if isinstance(node, ast.BoolOp):
        # Handle and/or operations
        values = [_evaluate_node(value, data) for value in node.values]
        if isinstance(node.op, ast.And):
            return all(values)
        elif isinstance(node.op, ast.Or):
            return any(values)
        else:
            raise ValueError(f"Unsupported boolean operator: {type(node.op)}")
    
    elif isinstance(node, ast.Compare):
        # Handle comparison operations (==, !=, <, <=, >, >=, in, not in)
        left = _evaluate_node(node.left, data)
        
        for op, comparator in zip(node.ops, node.comparators):
            right = _evaluate_node(comparator, data)
            
            if type(op) not in SAFE_OPERATORS:
                raise ValueError(f"Unsupported comparison operator: {type(op)}")
            
            result = SAFE_OPERATORS[type(op)](left, right)
            
            # For chained comparisons (a < b < c), all must be true
            if not result:
                return False
            left = right  # For next comparison in chain
        
        return True
    
    elif isinstance(node, ast.Name):
        # Handle variable/field access from data dictionary
        if node.id in data:
            return data[node.id]
        else:
            raise ValueError(f"Unknown field: {node.id}")
    
    elif isinstance(node, ast.Constant):
        # Handle literal values (strings, numbers, booleans, None)
        return node.value
    
    elif isinstance(node, ast.Attribute):
        # Handle attribute access (e.g., obj.attr)
        obj = _evaluate_node(node.value, data)
        if hasattr(obj, node.attr):
            return getattr(obj, node.attr)
        else:
            raise ValueError(f"Attribute '{node.attr}' not found on {type(obj)}")
    
    elif isinstance(node, ast.UnaryOp):
        # Handle unary operations (not, +, -)
        operand = _evaluate_node(node.operand, data)
        
        if isinstance(node.op, ast.Not):
            return not operand
        elif isinstance(node.op, ast.UAdd):
            return +operand
        elif isinstance(node.op, ast.USub):
            return -operand
        else:
            raise ValueError(f"Unsupported unary operator: {type(node.op)}")
    
    else:
        # Reject any other node types (function calls, imports, etc.)
        raise ValueError(f"Unsupported operation: {type(node).__name__}")

def get_comparator(condition: str):
    """
    Create a comparator function for filtering documents based on metadata.
    
    This function now uses safe_eval_condition instead of eval() to prevent
    arbitrary code execution vulnerabilities.
    
    Args:
        condition: String expression for filtering (e.g., "status == 'active'")
        
    Returns:
        Comparator function that takes a metadata dictionary and returns boolean
    """
    def comparator(data: dict[str, Any]):
        try:
            result = safe_eval_condition(condition, data)
            return result
        except Exception as e:
            # PrintStyle.error(f"Error evaluating condition: {e}")
            return False

    return comparator
