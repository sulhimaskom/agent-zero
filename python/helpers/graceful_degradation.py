"""
Graceful degradation utilities for optional dependencies.

This module provides safe imports and fallback implementations for optional features.
"""

from typing import Any, Optional, Union, List
from python.helpers.dependency_checker import safe_import, get_feature_flags
from python.helpers.print_style import PrintStyle


# Vector search capabilities
def safe_import_faiss():
    """Safely import FAISS with graceful degradation."""
    faiss = safe_import('faiss', 'vector search')
    if faiss is None:
        class MockFaiss:
            """Mock FAISS class for graceful degradation."""
            def __init__(self, *args, **kwargs):
                raise NotImplementedError(
                    "FAISS is not available. Vector search features are disabled. "
                    "Install FAISS with: pip install faiss-cpu"
                )
        
        class MockFaissModule:
            """Mock FAISS module with classes."""
            IndexFlatIP = MockFaiss
            IndexFlatL2 = MockFaiss
        
        return MockFaissModule()
    return faiss


def safe_import_langchain():
    """Safely import LangChain components with graceful degradation."""
    langchain_core = safe_import('langchain_core', 'LangChain core functionality')
    langchain_community = safe_import('langchain_community', 'LangChain community integrations')
    
    if langchain_core is None or langchain_community is None:
        return None, None
    
    # Try to import specific components
    documents = safe_import('langchain_core.documents', 'LangChain documents')
    messages = safe_import('langchain_core.messages', 'LangChain messages')
    prompts = safe_import('langchain_core.prompts', 'LangChain prompts')
    embeddings = safe_import('langchain_core.embeddings', 'LangChain embeddings')
    
    return {
        'core': langchain_core,
        'community': langchain_community,
        'documents': documents,
        'messages': messages,
        'prompts': prompts,
        'embeddings': embeddings
    }


def safe_import_sentence_transformers():
    """Safely import sentence transformers with graceful degradation."""
    sentence_transformers = safe_import('sentence_transformers', 'sentence embeddings')
    if sentence_transformers is None:
        class MockSentenceTransformer:
            """Mock SentenceTransformer for graceful degradation."""
            def __init__(self, model_name: str, *args, **kwargs):
                raise NotImplementedError(
                    "Sentence Transformers is not available. "
                    "Sentence embedding features are disabled. "
                    "Install with: pip install sentence-transformers"
                )
        
        return MockSentenceTransformer
    return sentence_transformers.SentenceTransformer


def safe_import_playwright():
    """Safely import Playwright with graceful degradation."""
    playwright = safe_import('playwright', 'browser automation')
    if playwright is None:
        class MockPlaywright:
            """Mock Playwright for graceful degradation."""
            def __init__(self, *args, **kwargs):
                raise NotImplementedError(
                    "Playwright is not available. Browser automation features are disabled. "
                    "Install with: pip install playwright && playwright install"
                )
        
        return MockPlaywright
    return playwright


def safe_import_unstructured():
    """Safely import unstructured document processing."""
    unstructured = safe_import('unstructured', 'document processing')
    if unstructured is None:
        def mock_partition(*args, **kwargs):
            PrintStyle.warning("Unstructured is not available. Document processing is disabled.")
            return []
        return type('MockUnstructured', (), {'partition': mock_partition})()
    return unstructured


def safe_import_pypdf():
    """Safely import PyPDF with graceful degradation."""
    pypdf = safe_import('pypdf', 'PDF processing')
    if pypdf is None:
        class MockPdfReader:
            """Mock PyPDF PdfReader for graceful degradation."""
            def __init__(self, *args, **kwargs):
                raise NotImplementedError(
                    "PyPDF is not available. PDF processing features are disabled. "
                    "Install with: pip install pypdf"
                )
        
        return type('MockPyPDF', (), {'PdfReader': MockPdfReader})()
    return pypdf


def safe_import_psutil():
    """Safely import psutil with graceful degradation."""
    psutil = safe_import('psutil', 'system monitoring')
    if psutil is None:
        class MockPsutil:
            """Mock psutil for graceful degradation."""
            @staticmethod
            def cpu_percent(*args, **kwargs):
                return 0.0
            
            @staticmethod
            def virtual_memory():
                return type('MockMemory', (), {'percent': 0.0})()
            
            @staticmethod
            def disk_usage(path):
                return type('MockDisk', (), {'percent': 0.0})()
        
        return MockPsutil()
    return psutil


def safe_import_paramiko():
    """Safely import paramiko with graceful degradation."""
    paramiko = safe_import('paramiko', 'SSH client')
    if paramiko is None:
        class MockSSHClient:
            """Mock paramiko SSHClient for graceful degradation."""
            def __init__(self, *args, **kwargs):
                raise NotImplementedError(
                    "Paramiko is not available. SSH features are disabled. "
                    "Install with: pip install paramiko"
                )
        
        return type('MockParamiko', (), {'SSHClient': MockSSHClient})()
    return paramiko


def safe_import_newspaper():
    """Safely import newspaper3k with graceful degradation."""
    newspaper = safe_import('newspaper3k', 'news article extraction')
    if newspaper is None:
        class MockArticle:
            """Mock newspaper Article for graceful degradation."""
            def __init__(self, *args, **kwargs):
                raise NotImplementedError(
                    "Newspaper3k is not available. News extraction features are disabled. "
                    "Install with: pip install newspaper3k"
                )
        
        return type('MockNewspaper', (), {'Article': MockArticle})()
    return newspaper


def safe_import_soundfile():
    """Safely import soundfile with graceful degradation."""
    soundfile = safe_import('soundfile', 'audio file processing')
    if soundfile is None:
        def mock_read(*args, **kwargs):
            raise NotImplementedError(
                "Soundfile is not available. Audio processing features are disabled. "
                "Install with: pip install soundfile"
            )
        
        def mock_write(*args, **kwargs):
            raise NotImplementedError(
                "Soundfile is not available. Audio processing features are disabled. "
                "Install with: pip install soundfile"
            )
        
        return type('MockSoundfile', (), {'read': mock_read, 'write': mock_write})()
    return soundfile


def safe_import_kokoro():
    """Safely import kokoro TTS with graceful degradation."""
    kokoro = safe_import('kokoro', 'text-to-speech')
    if kokoro is None:
        class MockKokoro:
            """Mock Kokoro TTS for graceful degradation."""
            def __init__(self, *args, **kwargs):
                raise NotImplementedError(
                    "Kokoro is not available. Text-to-speech features are disabled. "
                    "Install with: pip install kokoro"
                )
        
        return MockKokoro
    return kokoro


def safe_import_simpleeval():
    """Safely import simpleeval with graceful degradation."""
    simpleeval = safe_import('simpleeval', 'safe expression evaluation')
    if simpleeval is None:
        class MockSimpleEval:
            """Mock SimpleEval for graceful degradation."""
            def __init__(self, *args, **kwargs):
                raise NotImplementedError(
                    "SimpleEval is not available. Expression evaluation features are disabled. "
                    "Install with: pip install simpleeval"
                )
        
        return MockSimpleEval
    return simpleeval


def safe_import_gitpython():
    """Safely import GitPython with graceful degradation."""
    gitpython = safe_import('git', 'Git operations')
    if gitpython is None:
        class MockRepo:
            """Mock GitPython Repo for graceful degradation."""
            def __init__(self, *args, **kwargs):
                raise NotImplementedError(
                    "GitPython is not available. Git operations are disabled. "
                    "Install with: pip install GitPython"
                )
        
        return type('MockGit', (), {'Repo': MockRepo})()
    return gitpython


# Feature flag checks
def has_vector_search() -> bool:
    """Check if vector search capabilities are available."""
    flags = get_feature_flags()
    return flags.get('VECTOR_SEARCH_AVAILABLE', False)


def has_langchain() -> bool:
    """Check if LangChain capabilities are available."""
    flags = get_feature_flags()
    return flags.get('LANGCHAIN_AVAILABLE', False)


def has_browser_automation() -> bool:
    """Check if browser automation capabilities are available."""
    flags = get_feature_flags()
    return flags.get('PLAYWRIGHT_AVAILABLE', False)


def has_document_processing() -> bool:
    """Check if document processing capabilities are available."""
    flags = get_feature_flags()
    return any([
        flags.get('PDF_PROCESSING_AVAILABLE', False),
        flags.get('UNSTRUCTURED_AVAILABLE', False),
        flags.get('NEWSPAPER_AVAILABLE', False)
    ])


def has_audio_processing() -> bool:
    """Check if audio processing capabilities are available."""
    flags = get_feature_flags()
    return flags.get('AUDIO_PROCESSING_AVAILABLE', False)


def has_system_monitoring() -> bool:
    """Check if system monitoring capabilities are available."""
    flags = get_feature_flags()
    return flags.get('SYSTEM_MONITORING_AVAILABLE', False)


def has_ssh() -> bool:
    """Check if SSH capabilities are available."""
    flags = get_feature_flags()
    return flags.get('SSH_AVAILABLE', False)


# Convenience functions for common patterns
def get_vector_store_class():
    """Get the appropriate vector store class based on available dependencies."""
    if has_vector_search() and has_langchain():
        langchain = safe_import_langchain()
        if langchain and isinstance(langchain, dict) and langchain.get('community'):
            return langchain['community'].vectorstores.FAISS
    
    # Return a mock class if dependencies are not available
    class MockVectorStore:
        def __init__(self, *args, **kwargs):
            raise NotImplementedError(
                "Vector store requires FAISS and LangChain. "
                "Install with: pip install faiss-cpu langchain-core langchain-community"
            )
    
    return MockVectorStore


def get_embedding_model():
    """Get the appropriate embedding model based on available dependencies."""
    if has_langchain():
        langchain = safe_import_langchain()
        if langchain and isinstance(langchain, dict) and langchain.get('embeddings'):
            # Return a mock embedding class if sentence transformers is not available
            if not has_vector_search():
                class MockEmbeddings:
                    def embed_documents(self, texts: List[str]) -> List[List[float]]:
                        raise NotImplementedError(
                            "Sentence embeddings require sentence-transformers. "
                            "Install with: pip install sentence-transformers"
                        )
                    
                    def embed_query(self, text: str) -> List[float]:
                        raise NotImplementedError(
                            "Sentence embeddings require sentence-transformers. "
                            "Install with: pip install sentence-transformers"
                        )
                
                return MockEmbeddings
            
            return langchain['embeddings'].Embeddings
    
    raise NotImplementedError(
        "Embeddings require LangChain. "
        "Install with: pip install langchain-core"
    )


def safe_import_with_fallback(module_name: str, fallback_class=None, feature_name: Optional[str] = None):
    """
    Generic safe import with optional fallback class.
    
    Args:
        module_name: Name of the module to import
        fallback_class: Optional fallback class to return if import fails
        feature_name: Human-readable name of the feature
        
    Returns:
        Imported module or fallback class
    """
    module = safe_import(module_name, feature_name)
    if module is None and fallback_class is not None:
        return fallback_class
    return module