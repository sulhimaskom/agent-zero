"""
Graceful import utilities for optional dependencies.
Provides fallback behavior when optional dependencies are not available.
"""

import sys
from typing import Any, Optional, Tuple


def safe_import(module_name: str, fallback: Any = None, warning_message: Optional[str] = None) -> Tuple[Any, bool]:
    """
    Safely import a module with fallback behavior.
    
    Args:
        module_name: Name of the module to import
        fallback: Value to return if import fails
        warning_message: Custom warning message to display
        
    Returns:
        Tuple of (imported_module_or_fallback, success_boolean)
    """
    try:
        module = __import__(module_name, fromlist=[''])
        return module, True
    except ImportError as e:
        if warning_message:
            print(f"Warning: {warning_message} - {e}")
        else:
            print(f"Warning: Module '{module_name}' not available - some features will be limited: {e}")
        return fallback, False


def import_langchain_components():
    """
    Import LangChain components with graceful degradation.
    Returns a dictionary with available components.
    """
    components = {}
    
    # Core LangChain components
    components['langchain_core'], components['has_langchain_core'] = safe_import(
        'langchain_core',
        warning_message="LangChain core not available"
    )
    
    # Community components
    components['langchain_community'], components['has_langchain_community'] = safe_import(
        'langchain_community',
        warning_message="LangChain community integrations not available"
    )
    
    # Try to import specific classes if modules are available
    if components['has_langchain_core']:
        try:
            from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage, AIMessage
            from langchain_core.documents import Document
            from langchain_core.embeddings import Embeddings
            from langchain_core.language_models.chat_models import BaseChatModel
            from langchain_core.language_models.llms import BaseLLM
            from langchain_core.prompts import ChatPromptTemplate
            
            components.update({
                'BaseMessage': BaseMessage,
                'HumanMessage': HumanMessage,
                'SystemMessage': SystemMessage,
                'AIMessage': AIMessage,
                'Document': Document,
                'Embeddings': Embeddings,
                'BaseChatModel': BaseChatModel,
                'BaseLLM': BaseLLM,
                'ChatPromptTemplate': ChatPromptTemplate,
            })
        except ImportError as e:
            print(f"Warning: Some LangChain core classes not available: {e}")
    
    if components['has_langchain_community']:
        try:
            from langchain_community.vectorstores import FAISS
            from langchain_community.docstore.in_memory import InMemoryDocstore
            from langchain_community.vectorstores.utils import DistanceStrategy
            
            components.update({
                'FAISS': FAISS,
                'InMemoryDocstore': InMemoryDocstore,
                'DistanceStrategy': DistanceStrategy,
            })
        except ImportError as e:
            print(f"Warning: Some LangChain community classes not available: {e}")
    
    return components


def import_faiss():
    """Import FAISS with platform-specific handling."""
    try:
        # Try the monkey patch first
        from python.helpers import faiss_monkey_patch
        return faiss_monkey_patch.faiss, True
    except ImportError:
        try:
            # Try direct import
            import faiss
            return faiss, True
        except ImportError as e:
            print(f"Warning: FAISS not available - vector search will be limited: {e}")
            return None, False


def import_playwright():
    """Import Playwright with graceful degradation."""
    try:
        from playwright.sync_api import sync_playwright
        from playwright.async_api import async_playwright
        return sync_playwright, async_playwright, True
    except ImportError as e:
        print(f"Warning: Playwright not available - web automation features disabled: {e}")
        return None, None, False


def import_sentence_transformers():
    """Import sentence transformers with graceful degradation."""
    try:
        from sentence_transformers import SentenceTransformer
        return SentenceTransformer, True
    except ImportError as e:
        print(f"Warning: Sentence transformers not available - embedding features limited: {e}")
        return None, False


def get_sentence_transformers():
    """Get sentence transformers module."""
    return import_sentence_transformers()


# Global cache of imported components
_langchain_components = None
_faiss = None
_faiss_available = False


def get_langchain_components():
    """Get cached LangChain components."""
    global _langchain_components
    if _langchain_components is None:
        _langchain_components = import_langchain_components()
    return _langchain_components


def get_faiss():
    """Get cached FAISS module."""
    global _faiss, _faiss_available
    if _faiss is None:
        _faiss, _faiss_available = import_faiss()
    return _faiss, _faiss_available


def check_optional_dependencies():
    """Check availability of optional dependencies and return status."""
    langchain = get_langchain_components()
    faiss, faiss_available = get_faiss()
    
    status = {
        'langchain_core': langchain.get('has_langchain_core', False),
        'langchain_community': langchain.get('has_langchain_community', False),
        'faiss': faiss_available,
    }
    
    # Check other optional dependencies
    try:
        import sentence_transformers
        status['sentence_transformers'] = True
    except ImportError:
        status['sentence_transformers'] = False
    
    try:
        import playwright
        status['playwright'] = True
    except ImportError:
        status['playwright'] = False
    
    try:
        import tiktoken
        status['tiktoken'] = True
    except ImportError:
        status['tiktoken'] = False
    
    return status


if __name__ == "__main__":
    # Test imports when run directly
    print("Testing optional dependency imports...")
    
    langchain = get_langchain_components()
    print(f"LangChain core: {langchain.get('has_langchain_core', False)}")
    print(f"LangChain community: {langchain.get('has_langchain_community', False)}")
    
    faiss, available = get_faiss()
    print(f"FAISS: {available}")
    
    status = check_optional_dependencies()
    print("Dependency status:", status)