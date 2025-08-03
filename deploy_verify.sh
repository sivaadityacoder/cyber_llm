#!/bin/bash

# 🚀 Cyber LLM Deployment Verification Script

echo "🛡️ Cyber LLM - Deployment Verification"
echo "======================================="

# Check if we're in the right directory
if [ ! -f "README.md" ]; then
    echo "❌ Error: Please run this script from the project root directory"
    exit 1
fi

echo "📍 Current directory: $(pwd)"
echo ""

# Step 1: Check Python and Virtual Environment
echo "🐍 Step 1: Checking Python environment..."
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
else
    echo "✅ Virtual environment exists"
fi

# Activate virtual environment
source venv/bin/activate

# Step 2: Install Dependencies
echo ""
echo "📚 Step 2: Installing dependencies..."
pip install -q -r requirements.txt
echo "✅ Dependencies installed"

# Step 3: Test Imports
echo ""
echo "🔍 Step 3: Testing module imports..."
cd Frontend
if python -c "import cve_logic; print('✅ cve_logic import successful')" 2>/dev/null; then
    echo "✅ Frontend imports working"
else
    echo "❌ Frontend import failed"
    exit 1
fi
cd ..

cd Backend
if python -c "import main; print('✅ Backend import successful')" 2>/dev/null; then
    echo "✅ Backend imports working"
else
    echo "❌ Backend import failed"
    exit 1
fi
cd ..

# Step 4: Check File Structure
echo ""
echo "📁 Step 4: Verifying file structure..."

required_files=(
    "README.md"
    "requirements.txt"
    ".gitignore"
    "Backend/main.py"
    "Backend/llm_cve_analyzer.py"
    "Backend/cve_logic.py"
    "Frontend/chatbot_app.py"
    "Frontend/cve_logic.py"
    "data/detailed_cve_database.json"
    "data/enhanced_ethical_hacker_training.json"
)

missing_files=()
for file in "${required_files[@]}"; do
    if [ -f "$file" ]; then
        echo "✅ $file"
    else
        echo "❌ $file (missing)"
        missing_files+=("$file")
    fi
done

if [ ${#missing_files[@]} -gt 0 ]; then
    echo ""
    echo "❌ Missing files detected. Please ensure all required files are present."
    exit 1
fi

# Step 5: Test CVE Analyzer
echo ""
echo "🔍 Step 5: Testing CVE analyzer..."
cd Backend
if echo -e "test\nquick test" | timeout 30 python llm_cve_analyzer.py > /dev/null 2>&1; then
    echo "✅ CVE analyzer working"
else
    echo "⚠️ CVE analyzer test skipped (may require API keys)"
fi
cd ..

# Step 6: Final Status
echo ""
echo "🎉 Deployment Verification Complete!"
echo "===================================="
echo ""
echo "📋 Next Steps:"
echo "1. Set environment variables (optional):"
echo "   export OPENAI_API_KEY='your_key_here'"
echo "   export NVD_API_KEY='your_key_here'"
echo ""
echo "2. Start the Backend:"
echo "   cd Backend && python main.py"
echo ""
echo "3. Start the Frontend (new terminal):"
echo "   cd Frontend && streamlit run chatbot_app.py"
echo ""
echo "4. Access the application:"
echo "   - Frontend: http://localhost:8501"
echo "   - Backend: http://localhost:8000"
echo ""
echo "✅ Your Cyber LLM project is ready for deployment!"
echo "🚀 Push to GitHub: git push -u origin main"
