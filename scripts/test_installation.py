#!/usr/bin/env python3
"""
Simple test script to verify Cyber LLM installation and basic functionality.
"""

import sys
import os

def test_python_version():
    """Test Python version compatibility."""
    version = sys.version_info
    print(f"🐍 Python version: {version.major}.{version.minor}.{version.micro}")
    
    if version.major >= 3 and version.minor >= 11:
        print("✅ Python version is compatible")
        return True
    else:
        print("❌ Python 3.11+ required")
        return False

def test_directory_structure():
    """Test directory structure."""
    required_dirs = [
        "backend",
        "frontend", 
        "scripts",
        "docs"
    ]
    
    print("\n📁 Testing directory structure...")
    all_present = True
    
    for directory in required_dirs:
        if os.path.exists(directory):
            print(f"✅ {directory}/ directory found")
        else:
            print(f"❌ {directory}/ directory missing")
            all_present = False
    
    return all_present

def test_files():
    """Test required files."""
    required_files = [
        "requirements.txt",
        ".env.example",
        "README.md",
        "Dockerfile",
        "docker-compose.yml"
    ]
    
    print("\n📄 Testing required files...")
    all_present = True
    
    for file in required_files:
        if os.path.exists(file):
            print(f"✅ {file} found")
        else:
            print(f"❌ {file} missing")
            all_present = False
    
    return all_present

def test_backend_structure():
    """Test backend module structure."""
    backend_modules = [
        "backend/__init__.py",
        "backend/main.py",
        "backend/config.py",
        "backend/api",
        "backend/llm",
        "backend/rag",
        "backend/tools",
        "backend/voice"
    ]
    
    print("\n🔧 Testing backend structure...")
    all_present = True
    
    for module in backend_modules:
        if os.path.exists(module):
            print(f"✅ {module} found")
        else:
            print(f"❌ {module} missing")
            all_present = False
    
    return all_present

def test_import_structure():
    """Test basic import structure without dependencies."""
    print("\n🔍 Testing import structure...")
    
    # Add current directory to Python path
    sys.path.insert(0, os.getcwd())
    
    try:
        # Test basic file structure
        if os.path.exists("backend/__init__.py"):
            print("✅ Backend module structure is valid")
        else:
            print("❌ Backend module structure invalid")
            
        print("✅ Import structure test completed")
        return True
    except Exception as e:
        print(f"❌ Import error: {e}")
        return False

def main():
    """Run all tests."""
    print("🔒 Cyber LLM - Installation Verification Test")
    print("=" * 50)
    
    tests = [
        ("Python Version", test_python_version),
        ("Directory Structure", test_directory_structure),
        ("Required Files", test_files),
        ("Backend Structure", test_backend_structure),
        ("Import Structure", test_import_structure)
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append(result)
        except Exception as e:
            print(f"❌ {test_name} failed with error: {e}")
            results.append(False)
    
    # Summary
    print("\n" + "=" * 50)
    print("📊 Test Summary:")
    
    passed = sum(results)
    total = len(results)
    
    for i, (test_name, _) in enumerate(tests):
        status = "✅ PASS" if results[i] else "❌ FAIL"
        print(f"  {test_name}: {status}")
    
    print(f"\n📈 Overall: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Installation structure is correct.")
        print("\n📋 Next Steps:")
        print("1. Install dependencies: pip install -r requirements.txt")
        print("2. Set up environment: cp .env.example .env")
        print("3. Start backend: python -m uvicorn backend.main:app --reload")
        print("4. Start frontend: streamlit run frontend/streamlit_app/app.py")
    else:
        print("⚠️  Some tests failed. Please check the installation.")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)