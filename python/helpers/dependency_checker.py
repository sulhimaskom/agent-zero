"""
Dependency validation utility for Agent Zero.

This module provides functions to check if required dependencies are available
and implements graceful degradation for optional features.
"""

import sys
import importlib
from typing import Dict, List, Optional, Tuple
from python.helpers.print_style import PrintStyle


class DependencyChecker:
    """Utility class for checking dependency availability."""
    
    # Core dependencies that must be available
    CORE_DEPENDENCIES = {
        'flask': 'Flask web framework',
        'docker': 'Docker SDK',
        'aiohttp': 'Async HTTP client',
        'python_dotenv': 'Environment variable management',
        'pytz': 'Timezone handling',
        'nest_asyncio': 'Async event loop patching',
    }
    
    # Optional dependencies with feature flags
    OPTIONAL_DEPENDENCIES = {
        'faiss': 'Vector search and similarity',
        'langchain_core': 'LangChain core functionality',
        'langchain_community': 'LangChain community integrations',
        'litellm': 'LLM interface abstraction',
        'sentence_transformers': 'Sentence embeddings',
        'playwright': 'Browser automation',
        'paramiko': 'SSH client',
        'newspaper3k': 'News article extraction',
        'pypdf': 'PDF processing',
        'unstructured': 'Document processing',
        'soundfile': 'Audio file processing',
        'psutil': 'System monitoring',
        'crontab': 'Cron job scheduling',
        'webcolors': 'Color utilities',
        'markdown': 'Markdown processing',
        'browser_use': 'Browser automation framework',
        'GitPython': 'Git operations',
        'inputimeout': 'Input timeout handling',
        'kokoro': 'Text-to-speech',
        'simpleeval': 'Safe expression evaluation',
        'fastmcp': 'MCP protocol implementation',
        'fasta2a': 'Additional MCP utilities',
        'flask_basicauth': 'Basic authentication',
        'flaredantic': 'FastAPI integration',
        'a2wsgi': 'ASGI to WSGI adapter',
        'ansio': 'Async utilities',
        'duckduckgo_search': 'DuckDuckGo search',
        'lxml_html_clean': 'HTML cleaning',
        'pathspec': 'Path pattern matching',
        'aiofiles': 'Async file operations',
        'tiktoken': 'Token counting',
        'openai': 'OpenAI API client',
    }
    
    def __init__(self):
        self._checked_cache: Dict[str, bool] = {}
    
    def is_available(self, module_name: str) -> bool:
        """
        Check if a module is available.
        
        Args:
            module_name: Name of the module to check
            
        Returns:
            True if module is available, False otherwise
        """
        if module_name in self._checked_cache:
            return self._checked_cache[module_name]
        
        try:
            importlib.import_module(module_name)
            self._checked_cache[module_name] = True
            return True
        except ImportError:
            self._checked_cache[module_name] = False
            return False
    
    def check_core_dependencies(self) -> Tuple[bool, List[str]]:
        """
        Check all core dependencies.
        
        Returns:
            Tuple of (all_available, missing_dependencies)
        """
        missing = []
        
        for module, description in self.CORE_DEPENDENCIES.items():
            if not self.is_available(module):
                missing.append(f"{module} ({description})")
        
        return len(missing) == 0, missing
    
    def check_optional_dependencies(self) -> Dict[str, bool]:
        """
        Check all optional dependencies.
        
        Returns:
            Dictionary mapping module names to availability
        """
        result = {}
        
        for module, description in self.OPTIONAL_DEPENDENCIES.items():
            result[module] = self.is_available(module)
        
        return result
    
    def validate_dependencies(self, verbose: bool = True) -> bool:
        """
        Validate all dependencies and print status.
        
        Args:
            verbose: Whether to print detailed status
            
        Returns:
            True if all core dependencies are available
        """
        if verbose:
            PrintStyle.info("Checking Agent Zero dependencies...")
        
        # Check core dependencies
        core_available, core_missing = self.check_core_dependencies()
        
        if verbose:
            if core_available:
                PrintStyle.success("✓ All core dependencies are available")
            else:
                PrintStyle.error("❌ Missing core dependencies:")
                for dep in core_missing:
                    PrintStyle.error(f"  - {dep}")
        
        # Check optional dependencies
        optional_status = self.check_optional_dependencies()
        available_optional = [mod for mod, available in optional_status.items() if available]
        missing_optional = [mod for mod, available in optional_status.items() if not available]
        
        if verbose:
            PrintStyle.info(f"✓ {len(available_optional)} optional dependencies available")
            if missing_optional:
                PrintStyle.warning(f"⚠ {len(missing_optional)} optional dependencies missing:")
                for mod in missing_optional:
                    description = self.OPTIONAL_DEPENDENCIES.get(mod, "Unknown feature")
                    PrintStyle.warning(f"  - {mod} ({description})")
        
        return core_available
    
    def get_feature_flags(self) -> Dict[str, bool]:
        """
        Get feature flags based on available dependencies.
        
        Returns:
            Dictionary of feature flags
        """
        flags = {}
        
        # Vector search capabilities
        flags['VECTOR_SEARCH_AVAILABLE'] = self.is_available('faiss')
        flags['SENTENCE_EMBEDDINGS_AVAILABLE'] = self.is_available('sentence_transformers')
        
        # LLM capabilities
        flags['LANGCHAIN_AVAILABLE'] = self.is_available('langchain_core')
        flags['LITELLM_AVAILABLE'] = self.is_available('litellm')
        
        # Browser automation
        flags['PLAYWRIGHT_AVAILABLE'] = self.is_available('playwright')
        flags['BROWSER_USE_AVAILABLE'] = self.is_available('browser_use')
        
        # Document processing
        flags['PDF_PROCESSING_AVAILABLE'] = self.is_available('pypdf')
        flags['UNSTRUCTURED_AVAILABLE'] = self.is_available('unstructured')
        flags['NEWSPAPER_AVAILABLE'] = self.is_available('newspaper3k')
        
        # Audio processing
        flags['AUDIO_PROCESSING_AVAILABLE'] = self.is_available('soundfile')
        flags['TTS_AVAILABLE'] = self.is_available('kokoro')
        
        # System utilities
        flags['SSH_AVAILABLE'] = self.is_available('paramiko')
        flags['SYSTEM_MONITORING_AVAILABLE'] = self.is_available('psutil')
        flags['CRON_AVAILABLE'] = self.is_available('crontab')
        
        # Development tools
        flags['GIT_AVAILABLE'] = self.is_available('GitPython')
        
        return flags


# Global instance for easy access
_dependency_checker = DependencyChecker()


def validate_dependencies(verbose: bool = True) -> bool:
    """
    Validate all dependencies.
    
    Args:
        verbose: Whether to print detailed status
        
    Returns:
        True if all core dependencies are available
    """
    return _dependency_checker.validate_dependencies(verbose)


def is_dependency_available(module_name: str) -> bool:
    """
    Check if a specific dependency is available.
    
    Args:
        module_name: Name of the module to check
        
    Returns:
        True if module is available, False otherwise
    """
    return _dependency_checker.is_available(module_name)


def get_feature_flags() -> Dict[str, bool]:
    """
    Get feature flags based on available dependencies.
    
    Returns:
        Dictionary of feature flags
    """
    return _dependency_checker.get_feature_flags()


def require_dependency(module_name: str, feature_name: Optional[str] = None) -> bool:
    """
    Require a dependency and raise an error if not available.
    
    Args:
        module_name: Name of the required module
        feature_name: Human-readable name of the feature
        
    Returns:
        True if dependency is available
        
    Raises:
        ImportError: If dependency is not available
    """
    if not _dependency_checker.is_available(module_name):
        feature = feature_name or module_name
        raise ImportError(
            f"Required dependency '{module_name}' is not available. "
            f"This dependency is needed for {feature}. "
            f"Please install it using: pip install {module_name}"
        )
    return True


def safe_import(module_name: str, feature_name: Optional[str] = None):
    """
    Safely import a module with graceful degradation.
    
    Args:
        module_name: Name of the module to import
        feature_name: Human-readable name of the feature
        
    Returns:
        The imported module or None if not available
    """
    try:
        return importlib.import_module(module_name)
    except ImportError:
        feature = feature_name or module_name
        PrintStyle.warning(
            f"Optional dependency '{module_name}' is not available. "
            f"Some {feature} features will be disabled."
        )
        return None


# Command-line interface for dependency checking
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Check Agent Zero dependencies")
    parser.add_argument("--quiet", action="store_true", help="Only show errors")
    parser.add_argument("--features", action="store_true", help="Show feature flags")
    
    args = parser.parse_args()
    
    if args.features:
        flags = get_feature_flags()
        PrintStyle.info("Feature Flags:")
        for flag, available in flags.items():
            status = "✓" if available else "❌"
            PrintStyle.standard(f"  {status} {flag}")
    else:
        success = validate_dependencies(verbose=not args.quiet)
        sys.exit(0 if success else 1)