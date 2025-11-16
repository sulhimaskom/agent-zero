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


# Safe operators allowed in expressions
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

# Safe binary operators for arithmetic operations
SAFE_BINARY_OPERATORS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
}

# Safe unary operators
SAFE_UNARY_OPERATORS = {
    ast.UAdd: operator.pos,
    ast.USub: operator.neg,
    ast.Not: operator.not_,
}


class SafeExpressionEvaluator:
    """
    Safe expression evaluator using AST parsing to prevent code injection.
    Only allows specific safe operations and prevents arbitrary code execution.
    """
    
    def __init__(self):
        self.allowed_operators = SAFE_OPERATORS
        self.allowed_binary_operators = SAFE_BINARY_OPERATORS
        self.allowed_unary_operators = SAFE_UNARY_OPERATORS
    
    def evaluate(self, condition: str, data: dict[str, Any]) -> bool:
        """
        Safely evaluate a condition string against provided data.
        
        Args:
            condition: String expression to evaluate (e.g., "age > 18 and name == 'John'")
            data: Dictionary containing variable names and their values
            
        Returns:
            Boolean result of the evaluation
            
        Raises:
            ValueError: If the expression contains unsafe operations
            SyntaxError: If the expression has invalid syntax
        """
        try:
            # Parse the expression into an AST
            tree = ast.parse(condition, mode='eval')
            # Evaluate the AST safely
            result = self._evaluate_node(tree.body, data)
            # Ensure result is boolean
            return bool(result)
        except (SyntaxError, ValueError) as e:
            # Log the error for security monitoring
            # In production, you might want to log this to a security system
            raise ValueError(f"Unsafe or invalid expression: {e}")
        except Exception as e:
            # Any other exception means the expression is unsafe
            raise ValueError(f"Expression evaluation failed: {e}")
    
    def _evaluate_node(self, node, data: dict[str, Any]):
        """Recursively evaluate AST nodes safely."""
        
        if isinstance(node, ast.BoolOp):
            # Handle boolean operations (and, or)
            result = True if isinstance(node.op, ast.And) else False
            for value_node in node.values:
                value = self._evaluate_node(value_node, data)
                if isinstance(node.op, ast.And):
                    result = result and value
                    if not result:  # Short-circuit
                        break
                else:  # Or
                    result = result or value
                    if result:  # Short-circuit
                        break
            return result
        
        elif isinstance(node, ast.BinOp):
            # Handle binary operations
            left = self._evaluate_node(node.left, data)
            right = self._evaluate_node(node.right, data)
            
            if type(node.op) in self.allowed_binary_operators:
                return self.allowed_binary_operators[type(node.op)](left, right)
            elif type(node.op) in self.allowed_operators:
                return self.allowed_operators[type(node.op)](left, right)
            else:
                raise ValueError(f"Unsafe binary operator: {type(node.op).__name__}")
        
        elif isinstance(node, ast.UnaryOp):
            # Handle unary operations
            operand = self._evaluate_node(node.operand, data)
            if type(node.op) in self.allowed_unary_operators:
                return self.allowed_unary_operators[type(node.op)](operand)
            else:
                raise ValueError(f"Unsafe unary operator: {type(node.op).__name__}")
        
        elif isinstance(node, ast.Compare):
            # Handle comparison operations
            left = self._evaluate_node(node.left, data)
            for op, comparator_node in zip(node.ops, node.comparators):
                right = self._evaluate_node(comparator_node, data)
                if type(op) in self.allowed_operators:
                    if not self.allowed_operators[type(op)](left, right):
                        return False
                    left = right  # For chained comparisons
                else:
                    raise ValueError(f"Unsafe comparison operator: {type(op).__name__}")
            return True
        
        elif isinstance(node, ast.Name):
            # Handle variable names - only allow names from the provided data
            if node.id in data:
                return data[node.id]
            else:
                raise ValueError(f"Undefined variable: {node.id}")
        
        elif isinstance(node, ast.Constant):
            # Handle literal values (strings, numbers, booleans, None)
            return node.value
        
        elif isinstance(node, ast.List):
            # Handle list literals
            return [self._evaluate_node(elt, data) for elt in node.elts]
        
        elif isinstance(node, ast.Tuple):
            # Handle tuple literals
            return tuple(self._evaluate_node(elt, data) for elt in node.elts)
        
        elif isinstance(node, ast.Set):
            # Handle set literals
            return {self._evaluate_node(elt, data) for elt in node.elts}
        
        elif isinstance(node, ast.Dict):
            # Handle dictionary literals
            keys = [self._evaluate_node(k, data) for k in node.keys]
            values = [self._evaluate_node(v, data) for v in node.values]
            return dict(zip(keys, values))
        
        else:
            # Any other node type is potentially unsafe
            raise ValueError(f"Unsafe expression construct: {type(node).__name__}")


# Global evaluator instance
_evaluator = SafeExpressionEvaluator()


def get_comparator(condition: str):
    """
    Create a safe comparator function for filtering documents.
    
    Args:
        condition: String expression to evaluate against document metadata
        
    Returns:
        Function that takes a data dictionary and returns boolean result
    """
    def comparator(data: dict[str, Any]):
        try:
            result = _evaluator.evaluate(condition, data)
            return result
        except Exception as e:
            # Log the error for security monitoring
            # In production, you might want to log suspicious attempts
            # PrintStyle.error(f"Error evaluating condition: {e}")
            return False

    return comparator
