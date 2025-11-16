#!/usr/bin/env python3
"""
Dependency validation utility for Agent Zero.
Checks if all required dependencies are available and provides helpful error messages.
"""

import sys
import importlib
import platform
from typing import Dict, List, Tuple


class DependencyChecker:
    """Validates that required dependencies are installed and compatible."""
    
    def __init__(self):
        self.platform_info = {
            'system': platform.system(),
            'machine': platform.machine(),
            'python_version': platform.python_version(),
        }
        
        # Define required dependencies and their friendly names
        self.required_deps = {
            'flask': 'Flask web framework',
            'docker': 'Docker SDK',
            'aiohttp': 'Async HTTP client',
            'aiofiles': 'Async file operations',
            'python_dotenv': 'Environment variable management',
            'pytz': 'Timezone handling',
            'nest_asyncio': 'Nested async support',
            'crontab': 'Cron scheduling',
            'pathspec': 'Path pattern matching',
            'psutil': 'System utilities',
            'soundfile': 'Audio file handling',
            'webcolors': 'Color utilities',
        }
        
        # Define optional dependencies and their features
        self.optional_deps = {
            'faiss': 'Vector similarity search (FAISS)',
            'langchain_core': 'LangChain core functionality',
            'langchain_community': 'LangChain community integrations',
            'langchain_unstructured': 'Document processing with LangChain',
            'sentence_transformers': 'Sentence embeddings',
            'tiktoken': 'Token counting for LLMs',
            'openai': 'OpenAI API client',
            'playwright': 'Web automation',
            'unstructured': 'Document parsing',
            'browser_use': 'Browser automation',
            'litellm': 'LLM proxy interface',
        }
    
    def check_import(self, module_name: str) -> Tuple[bool, str]:
        """Try to import a module and return success status and error message."""
        try:
            # Handle special cases for module names
            import_name = module_name.replace('-', '_')
            if import_name == 'python_dotenv':
                import_name = 'dotenv'
            elif import_name == 'langchain_unstructured':
                import_name = 'langchain_unstructured'
            
            importlib.import_module(import_name)
            return True, ""
        except ImportError as e:
            return False, str(e)
        except Exception as e:
            return False, f"Unexpected error: {str(e)}"
    
    def check_required_dependencies(self) -> List[Tuple[str, bool, str]]:
        """Check all required dependencies."""
        results = []
        print("Checking required dependencies...")
        
        for module, description in self.required_deps.items():
            success, error = self.check_import(module)
            results.append((module, success, error))
            
            status = "✓" if success else "✗"
            print(f"  {status} {module} ({description})")
            if not success:
                print(f"    Error: {error}")
        
        return results
    
    def check_optional_dependencies(self) -> List[Tuple[str, bool, str]]:
        """Check all optional dependencies."""
        results = []
        print("\nChecking optional dependencies...")
        
        for module, description in self.optional_deps.items():
            success, error = self.check_import(module)
            results.append((module, success, error))
            
            status = "✓" if success else "○"
            print(f"  {status} {module} ({description})")
            if not success:
                print(f"    Note: {description} will not be available")
        
        return results
    
    def check_platform_specific_issues(self) -> List[str]:
        """Check for platform-specific compatibility issues."""
        issues = []
        
        # Check FAISS compatibility on ARM/Mac
        if self.platform_info['system'] == 'Darwin' and self.platform_info['machine'] == 'arm64':
            faiss_success, _ = self.check_import('faiss')
            if not faiss_success:
                issues.append(
                    "FAISS may have compatibility issues on ARM Mac. "
                    "Consider using 'faiss-cpu' with the monkey patch."
                )
        
        # Check Python version compatibility
        python_version = tuple(map(int, self.platform_info['python_version'].split('.')))
        if python_version < (3, 8):
            issues.append("Python 3.8+ is recommended for best compatibility.")
        
        return issues
    
    def generate_install_command(self, missing_deps: List[str]) -> str:
        """Generate pip install command for missing dependencies."""
        if not missing_deps:
            return "All dependencies are available!"
        
        # Convert module names to package names where needed
        package_names = []
        for dep in missing_deps:
            if dep == 'python_dotenv':
                package_names.append('python-dotenv')
            elif dep == 'langchain_core':
                package_names.append('langchain-core')
            elif dep == 'langchain_community':
                package_names.append('langchain-community')
            elif dep == 'langchain_unstructured':
                package_names.append('langchain-unstructured[all-docs]')
            elif dep == 'sentence_transformers':
                package_names.append('sentence-transformers')
            elif dep == 'openai_whisper':
                package_names.append('openai-whisper')
            elif dep == 'lxml_html_clean':
                package_names.append('lxml-html-clean')
            elif dep == 'webcolors':
                package_names.append('webcolors')
            else:
                package_names.append(dep)
        
        return f"pip install {' '.join(package_names)}"
    
    def run_full_check(self) -> bool:
        """Run complete dependency check and return overall status."""
        print(f"Agent Zero Dependency Checker")
        print(f"Platform: {self.platform_info['system']} {self.platform_info['machine']}")
        print(f"Python: {self.platform_info['python_version']}")
        print("=" * 50)
        
        # Check required dependencies
        required_results = self.check_required_dependencies()
        missing_required = [dep for dep, success, _ in required_results if not success]
        
        # Check optional dependencies
        optional_results = self.check_optional_dependencies()
        
        # Check platform-specific issues
        platform_issues = self.check_platform_specific_issues()
        
        # Summary
        print("\n" + "=" * 50)
        print("SUMMARY:")
        
        if missing_required:
            print(f"❌ {len(missing_required)} required dependencies missing:")
            for dep in missing_required:
                desc = self.required_deps.get(dep, dep)
                print(f"   - {dep} ({desc})")
            
            print(f"\nInstall command:")
            print(f"   {self.generate_install_command(missing_required)}")
            
            return False
        else:
            print("✅ All required dependencies are available!")
        
        if platform_issues:
            print(f"\n⚠️  Platform-specific considerations:")
            for issue in platform_issues:
                print(f"   - {issue}")
        
        available_optional = sum(1 for _, success, _ in optional_results if success)
        total_optional = len(optional_results)
        print(f"\n📦 Optional dependencies: {available_optional}/{total_optional} available")
        
        if available_optional < total_optional:
            missing_optional = [dep for dep, success, _ in optional_results if not success]
            print(f"   Missing: {', '.join(missing_optional)}")
            print(f"   Install with: {self.generate_install_command(missing_optional)}")
        
        return True


def main():
    """Main entry point for dependency checking."""
    checker = DependencyChecker()
    success = checker.run_full_check()
    
    if not success:
        print("\n❌ Dependency check failed. Please install missing dependencies.")
        sys.exit(1)
    else:
        print("\n✅ Dependency check passed!")
        sys.exit(0)


if __name__ == "__main__":
    main()