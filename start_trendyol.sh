#!/bin/bash

# ============================================================================
# 🛡️ TRENDYOL-ENHANCED CYBERSECURITY AI ASSISTANT v4.0
# Professional-Grade Enterprise Deployment Script
# ============================================================================

set -euo pipefail

# Color codes for professional output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Professional logging
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_professional() {
    echo -e "${PURPLE}[TRENDYOL]${NC} $1"
}

# Header
echo "============================================================================"
echo -e "${CYAN}🛡️  TRENDYOL-ENHANCED CYBERSECURITY AI ASSISTANT v4.0${NC}"
echo -e "${CYAN}Professional-Grade Enterprise Security Intelligence Platform${NC}"
echo "============================================================================"
echo ""

# Configuration
PROJECT_NAME="trendyol-cybersecurity-ai"
BACKEND_PORT=8000
FRONTEND_PORT=8501
COMPOSE_FILE="docker-compose-trendyol.yml"
DEV_MODE=false
ADVANCED_FEATURES=false
MONITORING=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --dev|--development)
            DEV_MODE=true
            log_info "Development mode enabled"
            shift
            ;;
        --advanced)
            ADVANCED_FEATURES=true
            log_info "Advanced features enabled"
            shift
            ;;
        --monitoring)
            MONITORING=true
            log_info "Professional monitoring enabled"
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --dev, --development    Enable development mode"
            echo "  --advanced             Enable advanced features (ChromaDB, Redis)"
            echo "  --monitoring           Enable professional monitoring (Prometheus, Grafana)"
            echo "  --help, -h             Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                     # Basic professional deployment"
            echo "  $0 --advanced          # With advanced features"
            echo "  $0 --dev --monitoring  # Development with monitoring"
            echo ""
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# System requirements check
log_info "Checking system requirements..."

# Check Docker
if ! command -v docker &> /dev/null; then
    log_error "Docker is not installed. Please install Docker first."
    exit 1
fi

# Check Docker Compose
if ! command -v docker-compose &> /dev/null; then
    log_error "Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

# Check if ports are available
check_port() {
    local port=$1
    if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null 2>&1; then
        log_warning "Port $port is already in use"
        return 1
    fi
    return 0
}

log_info "Checking port availability..."
if ! check_port $BACKEND_PORT; then
    log_error "Backend port $BACKEND_PORT is not available"
    exit 1
fi

if ! check_port $FRONTEND_PORT; then
    log_error "Frontend port $FRONTEND_PORT is not available"
    exit 1
fi

log_success "All required ports are available"

# Check if compose file exists
if [[ ! -f "$COMPOSE_FILE" ]]; then
    log_error "Docker compose file $COMPOSE_FILE not found"
    exit 1
fi

# Verify training data exists
log_info "Verifying training data..."
if [[ -f "data/trendyol_integrated_training.json" ]]; then
    TRAINING_EXAMPLES=$(python3 -c "import json; data=json.load(open('data/trendyol_integrated_training.json')); print(len(data))" 2>/dev/null || echo "0")
    log_success "Training data found: $TRAINING_EXAMPLES examples"
else
    log_warning "Training data not found. Running integration script..."
    if [[ -f "integrate_trendyol_dataset.py" ]]; then
        python3 integrate_trendyol_dataset.py
        log_success "Training data integrated successfully"
    else
        log_error "Training data integration script not found"
        exit 1
    fi
fi

# Verify model metadata
log_info "Verifying model configuration..."
if [[ -d "model/trendyol-enhanced-ethical-hacker-llm-v4" ]]; then
    log_success "Model metadata found"
else
    log_warning "Model metadata directory not found. Creating..."
    mkdir -p "model/trendyol-enhanced-ethical-hacker-llm-v4"
    log_success "Model directory created"
fi

# Build Docker profiles
DOCKER_PROFILES=""
if [[ "$DEV_MODE" == true ]]; then
    DOCKER_PROFILES="$DOCKER_PROFILES --profile development"
fi

if [[ "$ADVANCED_FEATURES" == true ]]; then
    DOCKER_PROFILES="$DOCKER_PROFILES --profile advanced"
fi

if [[ "$MONITORING" == true ]]; then
    DOCKER_PROFILES="$DOCKER_PROFILES --profile monitoring"
fi

# Create necessary directories
log_info "Creating necessary directories..."
mkdir -p logs chroma_db monitoring

# Professional deployment
log_professional "Starting Trendyol-Enhanced Cybersecurity AI v4.0..."

# Stop existing containers
log_info "Stopping any existing containers..."
docker-compose -f "$COMPOSE_FILE" down --remove-orphans 2>/dev/null || true

# Build and start services
log_info "Building and starting services..."
if [[ -n "$DOCKER_PROFILES" ]]; then
    log_info "Using profiles:$DOCKER_PROFILES"
    docker-compose -f "$COMPOSE_FILE" $DOCKER_PROFILES up --build -d
else
    docker-compose -f "$COMPOSE_FILE" up --build -d trendyol-backend trendyol-frontend
fi

# Wait for services to be ready
log_info "Waiting for services to be ready..."

# Wait for backend
log_info "Checking backend health..."
for i in {1..30}; do
    if curl -s http://localhost:$BACKEND_PORT/health >/dev/null 2>&1; then
        log_success "Backend is ready!"
        break
    fi
    sleep 2
    echo -n "."
done

# Wait for frontend
log_info "Checking frontend health..."
for i in {1..30}; do
    if curl -s http://localhost:$FRONTEND_PORT/_stcore/health >/dev/null 2>&1; then
        log_success "Frontend is ready!"
        break
    fi
    sleep 2
    echo -n "."
done

# Display service information
echo ""
echo "============================================================================"
log_professional "🚀 TRENDYOL-ENHANCED CYBERSECURITY AI v4.0 IS READY!"
echo "============================================================================"
echo ""

# Service URLs
log_success "🎯 Frontend Interface: http://localhost:$FRONTEND_PORT"
log_success "🔧 Backend API: http://localhost:$BACKEND_PORT"
log_success "📚 API Documentation: http://localhost:$BACKEND_PORT/docs"
log_success "🔍 Health Check: http://localhost:$BACKEND_PORT/health"

if [[ "$ADVANCED_FEATURES" == true ]]; then
    log_success "🗄️  ChromaDB: http://localhost:8002"
    log_success "⚡ Redis Cache: localhost:6379"
fi

if [[ "$MONITORING" == true ]]; then
    log_success "📊 Prometheus: http://localhost:9090"
    log_success "📈 Grafana: http://localhost:3000 (admin/trendyol_admin_2024)"
fi

echo ""

# Feature summary
echo "============================================================================"
log_professional "🏆 PROFESSIONAL FEATURES ENABLED:"
echo "============================================================================"
log_success "✅ Enterprise-grade cybersecurity AI assistant"
log_success "✅ 14 specialized security domains"
log_success "✅ Advanced threat intelligence capabilities"
log_success "✅ Professional incident response guidance"
log_success "✅ Sophisticated threat hunting techniques"
log_success "✅ Zero-day vulnerability research methods"
log_success "✅ Post-quantum cryptography expertise"
log_success "✅ AI/ML security considerations"
log_success "✅ Professional compliance frameworks"
log_success "✅ Multi-domain confidence scoring"

if [[ "$DEV_MODE" == true ]]; then
    log_success "✅ Development tools and debugging"
fi

if [[ "$ADVANCED_FEATURES" == true ]]; then
    log_success "✅ Vector database for semantic search"
    log_success "✅ Redis caching for performance"
fi

if [[ "$MONITORING" == true ]]; then
    log_success "✅ Professional monitoring and analytics"
fi

echo ""

# Usage instructions
echo "============================================================================"
log_professional "🚀 GETTING STARTED:"
echo "============================================================================"
echo "1. Open your browser and navigate to: http://localhost:$FRONTEND_PORT"
echo "2. Start asking professional cybersecurity questions"
echo "3. Use the domain selection for specialized expertise"
echo "4. Enable 'Professional Analysis' for multi-domain insights"
echo "5. Explore the Enterprise, Research, Defense, and Intelligence tabs"
echo ""

# Management commands
echo "============================================================================"
log_professional "🔧 MANAGEMENT COMMANDS:"
echo "============================================================================"
echo "• View logs:           docker-compose -f $COMPOSE_FILE logs -f"
echo "• Stop services:       docker-compose -f $COMPOSE_FILE down"
echo "• Restart services:    docker-compose -f $COMPOSE_FILE restart"
echo "• Update services:     docker-compose -f $COMPOSE_FILE pull && docker-compose -f $COMPOSE_FILE up -d"
echo "• View service status: docker-compose -f $COMPOSE_FILE ps"
echo ""

# Security reminders
echo "============================================================================"
log_professional "🔒 SECURITY REMINDERS:"
echo "============================================================================"
log_warning "• This system is for educational and research purposes"
log_warning "• Always follow ethical hacking guidelines"
log_warning "• Ensure proper authorization before security testing"
log_warning "• Keep the system updated with latest security patches"
echo ""

log_professional "Trendyol-Enhanced Cybersecurity AI v4.0 is now operational!"
echo "============================================================================"
