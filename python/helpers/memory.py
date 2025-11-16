from datetime import datetime
from typing import Any, List, Sequence
from langchain.storage import InMemoryByteStore, LocalFileStore
from langchain.embeddings import CacheBackedEmbeddings
from python.helpers import guids
from python.helpers.memory_monitor import get_memory_monitor, WeakValueDictionary

# from langchain_chroma import Chroma
from langchain_community.vectorstores import FAISS

# faiss needs to be patched for python 3.12 on arm #TODO remove once not needed
from python.helpers import faiss_monkey_patch
import faiss


from langchain_community.docstore.in_memory import InMemoryDocstore
from langchain_community.vectorstores.utils import (
    DistanceStrategy,
)
from langchain_core.embeddings import Embeddings

import os, json

import numpy as np

from python.helpers.print_style import PrintStyle
from . import files
from langchain_core.documents import Document
from python.helpers import knowledge_import
from python.helpers.log import Log, LogItem
from enum import Enum
from agent import Agent
import models
import logging
from simpleeval import simple_eval
import ast
import operator

# Safe operators allowed in expressions (same as vector_db.py)
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
    This is the same implementation as in vector_db.py for consistency.
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


# Global evaluator instance for memory module
_memory_evaluator = SafeExpressionEvaluator()


# Raise the log level so WARNING messages aren't shown
logging.getLogger("langchain_core.vectorstores.base").setLevel(logging.ERROR)


class MyFaiss(FAISS):
    # override aget_by_ids
    def get_by_ids(self, ids: Sequence[str], /) -> List[Document]:
        # return all self.docstore._dict[id] in ids
        return [self.docstore._dict[id] for id in (ids if isinstance(ids, list) else [ids]) if id in self.docstore._dict]  # type: ignore

    async def aget_by_ids(self, ids: Sequence[str], /) -> List[Document]:
        return self.get_by_ids(ids)

    def get_all_docs(self):
        return self.docstore._dict  # type: ignore


class Memory:

    class Area(Enum):
        MAIN = "main"
        FRAGMENTS = "fragments"
        SOLUTIONS = "solutions"
        INSTRUMENTS = "instruments"

    # Use weak value dictionary to prevent memory leaks
    index: WeakValueDictionary = WeakValueDictionary()
    
    # Track last access times for cleanup
    _last_access: dict[str, float] = {}
    
    # Expiry time for unused databases (1 hour)
    _EXPIRY_TIME = 3600

    @staticmethod
    async def get(agent: Agent):
        import time
        memory_subdir = agent.config.memory_subdir or "default"
        
        # Update last access time
        Memory._last_access[memory_subdir] = time.time()
        
        # Check if database exists and is still valid
        db = Memory.index.get(memory_subdir)
        if db is None:
            log_item = agent.context.log.log(
                type="util",
                heading=f"Initializing VectorDB in '/{memory_subdir}'",
            )
            db, created = Memory.initialize(
                log_item,
                agent.config.embeddings_model,
                memory_subdir,
                False,
            )
            Memory.index[memory_subdir] = db
            wrap = Memory(db, memory_subdir=memory_subdir)
            if agent.config.knowledge_subdirs:
                await wrap.preload_knowledge(
                    log_item, agent.config.knowledge_subdirs, memory_subdir
                )
            return wrap
        else:
            return Memory(
                db=db,
                memory_subdir=memory_subdir,
            )

    @staticmethod
    async def get_by_subdir(
        memory_subdir: str,
        log_item: LogItem | None = None,
        preload_knowledge: bool = True,
    ):
        import time
        
        # Update last access time
        Memory._last_access[memory_subdir] = time.time()
        
        # Check if database exists and is still valid
        db = Memory.index.get(memory_subdir)
        if db is None:
            import initialize

            agent_config = initialize.initialize_agent()
            model_config = agent_config.embeddings_model
            db, _created = Memory.initialize(
                log_item=log_item,
                model_config=model_config,
                memory_subdir=memory_subdir,
                in_memory=False,
            )
            wrap = Memory(db, memory_subdir=memory_subdir)
            if preload_knowledge and agent_config.knowledge_subdirs:
                await wrap.preload_knowledge(
                    log_item, agent_config.knowledge_subdirs, memory_subdir
                )
            Memory.index[memory_subdir] = db
        return Memory(db=db, memory_subdir=memory_subdir)

    @staticmethod
    async def reload(agent: Agent):
        memory_subdir = agent.config.memory_subdir or "default"
        if memory_subdir in Memory.index:
            del Memory.index[memory_subdir]
        if memory_subdir in Memory._last_access:
            del Memory._last_access[memory_subdir]
        return await Memory.get(agent)

    @staticmethod
    def initialize(
        log_item: LogItem | None,
        model_config: models.ModelConfig,
        memory_subdir: str,
        in_memory=False,
    ) -> tuple[MyFaiss, bool]:

        PrintStyle.standard("Initializing VectorDB...")

        if log_item:
            log_item.stream(progress="\nInitializing VectorDB")

        em_dir = files.get_abs_path(
            "memory/embeddings"
        )  # just caching, no need to parameterize
        db_dir = Memory._abs_db_dir(memory_subdir)

        # make sure embeddings and database directories exist
        os.makedirs(db_dir, exist_ok=True)

        if in_memory:
            store = InMemoryByteStore()
        else:
            os.makedirs(em_dir, exist_ok=True)
            store = LocalFileStore(em_dir)

        embeddings_model = models.get_embedding_model(
            model_config.provider,
            model_config.name,
            **model_config.build_kwargs(),
        )
        embeddings_model_id = files.safe_file_name(
            model_config.provider + "_" + model_config.name
        )

        # here we setup the embeddings model with the chosen cache storage
        embedder = CacheBackedEmbeddings.from_bytes_store(
            embeddings_model, store, namespace=embeddings_model_id
        )

        # initial DB and docs variables
        db: MyFaiss | None = None
        docs: dict[str, Document] | None = None

        created = False

        # if db folder exists and is not empty:
        if os.path.exists(db_dir) and files.exists(db_dir, "index.faiss"):
            db = MyFaiss.load_local(
                folder_path=db_dir,
                embeddings=embedder,
                allow_dangerous_deserialization=True,
                distance_strategy=DistanceStrategy.COSINE,
                # normalize_L2=True,
                relevance_score_fn=Memory._cosine_normalizer,
            )  # type: ignore

            # if there is a mismatch in embeddings used, re-index the whole DB
            emb_ok = False
            emb_set_file = files.get_abs_path(db_dir, "embedding.json")
            if files.exists(emb_set_file):
                embedding_set = json.loads(files.read_file(emb_set_file))
                if (
                    embedding_set["model_provider"] == model_config.provider
                    and embedding_set["model_name"] == model_config.name
                ):
                    # model matches
                    emb_ok = True

            # re-index -  create new DB and insert existing docs
            if db and not emb_ok:
                docs = db.get_all_docs()
                db = None

        # DB not loaded, create one
        if not db:
            index = faiss.IndexFlatIP(len(embedder.embed_query("example")))

            db = MyFaiss(
                embedding_function=embedder,
                index=index,
                docstore=InMemoryDocstore(),
                index_to_docstore_id={},
                distance_strategy=DistanceStrategy.COSINE,
                # normalize_L2=True,
                relevance_score_fn=Memory._cosine_normalizer,
            )

            # insert docs if reindexing
            if docs:
                PrintStyle.standard("Indexing memories...")
                if log_item:
                    log_item.stream(progress="\nIndexing memories")
                db.add_documents(documents=list(docs.values()), ids=list(docs.keys()))

            # save DB
            Memory._save_db_file(db, memory_subdir)
            # save meta file
            meta_file_path = files.get_abs_path(db_dir, "embedding.json")
            files.write_file(
                meta_file_path,
                json.dumps(
                    {
                        "model_provider": model_config.provider,
                        "model_name": model_config.name,
                    }
                ),
            )

            created = True

        return db, created

    def __init__(
        self,
        db: MyFaiss,
        memory_subdir: str,
    ):
        self.db = db
        self.memory_subdir = memory_subdir

    async def preload_knowledge(
        self, log_item: LogItem | None, kn_dirs: list[str], memory_subdir: str
    ):
        if log_item:
            log_item.update(heading="Preloading knowledge...")

        # db abs path
        db_dir = Memory._abs_db_dir(memory_subdir)

        # Load the index file if it exists
        index_path = files.get_abs_path(db_dir, "knowledge_import.json")

        # make sure directory exists
        if not os.path.exists(db_dir):
            os.makedirs(db_dir)

        index: dict[str, knowledge_import.KnowledgeImport] = {}
        if os.path.exists(index_path):
            with open(index_path, "r") as f:
                index = json.load(f)

        # preload knowledge folders
        index = self._preload_knowledge_folders(log_item, kn_dirs, index)

        for file in index:
            if index[file]["state"] in ["changed", "removed"] and index[file].get(
                "ids", []
            ):  # for knowledge files that have been changed or removed and have IDs
                await self.delete_documents_by_ids(
                    index[file]["ids"]
                )  # remove original version
            if index[file]["state"] == "changed":
                index[file]["ids"] = await self.insert_documents(
                    index[file]["documents"]
                )  # insert new version

        # remove index where state="removed"
        index = {k: v for k, v in index.items() if v["state"] != "removed"}

        # strip state and documents from index and save it
        for file in index:
            if "documents" in index[file]:
                del index[file]["documents"]  # type: ignore
            if "state" in index[file]:
                del index[file]["state"]  # type: ignore
        with open(index_path, "w") as f:
            json.dump(index, f)

    def _preload_knowledge_folders(
        self,
        log_item: LogItem | None,
        kn_dirs: list[str],
        index: dict[str, knowledge_import.KnowledgeImport],
    ):
        # load knowledge folders, subfolders by area
        for kn_dir in kn_dirs:
            for area in Memory.Area:
                index = knowledge_import.load_knowledge(
                    log_item,
                    files.get_abs_path("knowledge", kn_dir, area.value),
                    index,
                    {"area": area.value},
                )

        # load instruments descriptions
        index = knowledge_import.load_knowledge(
            log_item,
            files.get_abs_path("instruments"),
            index,
            {"area": Memory.Area.INSTRUMENTS.value},
            filename_pattern="**/*.md",
        )

        return index

    def get_document_by_id(self, id: str) -> Document | None:
        return self.db.get_by_ids(id)[0]

    async def search_similarity_threshold(
        self, query: str, limit: int, threshold: float, filter: str = ""
    ):
        comparator = Memory._get_comparator(filter) if filter else None

        return await self.db.asearch(
            query,
            search_type="similarity_score_threshold",
            k=limit,
            score_threshold=threshold,
            filter=comparator,
        )

    async def delete_documents_by_query(
        self, query: str, threshold: float, filter: str = ""
    ):
        k = 100
        tot = 0
        removed = []

        while True:
            # Perform similarity search with score
            docs = await self.search_similarity_threshold(
                query, limit=k, threshold=threshold, filter=filter
            )
            removed += docs

            # Extract document IDs and filter based on score
            # document_ids = [result[0].metadata["id"] for result in docs if result[1] < score_limit]
            document_ids = [result.metadata["id"] for result in docs]

            # Delete documents with IDs over the threshold score
            if document_ids:
                # fnd = self.db.get(where={"id": {"$in": document_ids}})
                # if fnd["ids"]: self.db.delete(ids=fnd["ids"])
                # tot += len(fnd["ids"])
                await self.db.adelete(ids=document_ids)
                tot += len(document_ids)

            # If fewer than K document IDs, break the loop
            if len(document_ids) < k:
                break

        if tot:
            self._save_db()  # persist
        return removed

    async def delete_documents_by_ids(self, ids: list[str]):
        # aget_by_ids is not yet implemented in faiss, need to do a workaround
        rem_docs = await self.db.aget_by_ids(
            ids
        )  # existing docs to remove (prevents error)
        if rem_docs:
            rem_ids = [doc.metadata["id"] for doc in rem_docs]  # ids to remove
            await self.db.adelete(ids=rem_ids)

        if rem_docs:
            self._save_db()  # persist
        return rem_docs

    async def insert_text(self, text, metadata: dict = {}):
        doc = Document(text, metadata=metadata)
        ids = await self.insert_documents([doc])
        return ids[0]

    async def insert_documents(self, docs: list[Document]):
        ids = [self._generate_doc_id() for _ in range(len(docs))]
        timestamp = self.get_timestamp()

        if ids:
            for doc, id in zip(docs, ids):
                doc.metadata["id"] = id  # add ids to documents metadata
                doc.metadata["timestamp"] = timestamp  # add timestamp
                if not doc.metadata.get("area", ""):
                    doc.metadata["area"] = Memory.Area.MAIN.value

            await self.db.aadd_documents(documents=docs, ids=ids)
            self._save_db()  # persist
        return ids

    async def update_documents(self, docs: list[Document]):
        ids = [doc.metadata["id"] for doc in docs]
        await self.db.adelete(ids=ids)  # delete originals
        ins = await self.db.aadd_documents(documents=docs, ids=ids)  # add updated
        self._save_db()  # persist
        return ins

    def _save_db(self):
        Memory._save_db_file(self.db, self.memory_subdir)

    def _generate_doc_id(self):
        while True:
            doc_id = guids.generate_id(10)  # random ID
            if not self.db.get_by_ids(doc_id):  # check if exists
                return doc_id

    @staticmethod
    def _save_db_file(db: MyFaiss, memory_subdir: str):
        abs_dir = Memory._abs_db_dir(memory_subdir)
        db.save_local(folder_path=abs_dir)

    @staticmethod
    def _get_comparator(condition: str):
        """
        Create a safe comparator function for filtering memory documents.
        
        Args:
            condition: String expression to evaluate against document metadata
            
        Returns:
            Function that takes a data dictionary and returns boolean result
        """
        def comparator(data: dict[str, Any]):
            try:
                result = _memory_evaluator.evaluate(condition, data)
                return result
            except Exception as e:
                # Log the error for security monitoring
                # In production, you might want to log suspicious attempts
                PrintStyle.error(f"Error evaluating condition: {e}")
                return False

        return comparator

    @staticmethod
    def _score_normalizer(val: float) -> float:
        res = 1 - 1 / (1 + np.exp(val))
        return res

    @staticmethod
    def _cosine_normalizer(val: float) -> float:
        res = (1 + val) / 2
        res = max(
            0, min(1, res)
        )  # float precision can cause values like 1.0000000596046448
        return res

    @staticmethod
    def _abs_db_dir(memory_subdir: str) -> str:
        return files.get_abs_path("memory", memory_subdir)

    @staticmethod
    def format_docs_plain(docs: list[Document]) -> list[str]:
        result = []
        for doc in docs:
            text = ""
            for k, v in doc.metadata.items():
                text += f"{k}: {v}\n"
            text += f"Content: {doc.page_content}"
            result.append(text)
        return result

    @staticmethod
    def get_timestamp():
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    @staticmethod
    def cleanup_expired_databases():
        """Remove expired or unused databases to prevent memory leaks."""
        import time
        current_time = time.time()
        expired_keys = []
        
        for key in list(Memory._last_access.keys()):
            if current_time - Memory._last_access[key] > Memory._EXPIRY_TIME:
                expired_keys.append(key)
        
        for key in expired_keys:
            if key in Memory.index:
                del Memory.index[key]
            if key in Memory._last_access:
                del Memory._last_access[key]
        
        # Clean up dead weak references
        Memory.index.cleanup_dead_references()
        
        if expired_keys:
            PrintStyle.success(f"Cleaned up {len(expired_keys)} expired memory databases")
    
    @staticmethod
    def get_memory_stats() -> dict[str, Any]:
        """Get memory usage statistics for debugging."""
        import time
        current_time = time.time()
        
        stats = {
            "active_databases": Memory.index.size(),
            "tracked_access_times": len(Memory._last_access),
            "database_keys": Memory.index.keys(),
            "last_access_times": {
                key: current_time - Memory._last_access[key] 
                for key in Memory._last_access.keys()
            }
        }
        
        return stats


def get_memory_subdir_abs(agent: Agent) -> str:
    return files.get_abs_path("memory", agent.config.memory_subdir or "default")


def get_custom_knowledge_subdir_abs(agent: Agent) -> str:
    for dir in agent.config.knowledge_subdirs:
        if dir != "default":
            return files.get_abs_path("knowledge", dir)
    raise Exception("No custom knowledge subdir set")


def reload():
    # clear the memory index, this will force all DBs to reload
    Memory.index = WeakValueDictionary()
    Memory._last_access = {}
