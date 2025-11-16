#!/usr/bin/env python3
"""
Test script to verify that the dependency fixes work correctly.
Tests imports from memory.py and vector_db.py with graceful degradation.
"""

def test_memory_imports():
    """Test that memory.py imports work with graceful degradation."""
    print("Testing memory.py imports...")
    try:
        from python.helpers.memory import Memory
        print("✓ Memory class imported successfully")
        return True
    except Exception as e:
        print(f"✗ Memory import failed: {e}")
        return False

def test_vector_db_imports():
    """Test that vector_db.py imports work with graceful degradation."""
    print("Testing vector_db.py imports...")
    try:
        from python.helpers.vector_db import VectorDB
        print("✓ VectorDB class imported successfully")
        return True
    except Exception as e:
        print(f"✗ VectorDB import failed: {e}")
        return False

def test_safe_imports():
    """Test safe imports utility."""
    print("Testing safe imports utility...")
    try:
        from python.helpers.safe_imports import get_langchain_components, get_faiss
        
        langchain = get_langchain_components()
        faiss, faiss_available = get_faiss()
        
        print(f"✓ LangChain components loaded: {bool(langchain)}")
        print(f"✓ FAISS available: {faiss_available}")
        return True
    except Exception as e:
        print(f"✗ Safe imports failed: {e}")
        return False

def test_dependency_checker():
    """Test dependency checker."""
    print("Testing dependency checker...")
    try:
        from python.helpers.dependency_checker import DependencyChecker
        
        checker = DependencyChecker()
        # Just test that it can be instantiated and run
        required_results = checker.check_required_dependencies()
        print(f"✓ Dependency checker works, checked {len(required_results)} required deps")
        return True
    except Exception as e:
        print(f"✗ Dependency checker failed: {e}")
        return False

def main():
    """Run all tests."""
    print("Agent Zero Dependency Fix Verification")
    print("=" * 50)
    
    tests = [
        test_dependency_checker,
        test_safe_imports,
        test_memory_imports,
        test_vector_db_imports,
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
        print()
    
    print("=" * 50)
    print(f"Tests passed: {passed}/{total}")
    
    if passed == total:
        print("✅ All dependency fixes are working correctly!")
        return True
    else:
        print("❌ Some dependency fixes need attention.")
        return False

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)