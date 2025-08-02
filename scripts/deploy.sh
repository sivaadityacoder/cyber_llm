#!/bin/bash

# Cyber LLM Docker Deployment Script

set -e

echo "🐳 Cyber LLM - Docker Deployment"
echo "================================="

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is required but not installed."
    echo "Please install Docker and try again."
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is required but not installed."
    echo "Please install Docker Compose and try again."
    exit 1
fi

echo "✅ Docker and Docker Compose found"

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p {data/{models,vectorstore},logs,reports,docker/ssl}

# Copy environment file if it doesn't exist
if [ ! -f ".env" ]; then
    echo "⚙️ Creating environment configuration..."
    cp .env.example .env
fi

# Function to deploy with Docker Compose
deploy() {
    echo "🚀 Building and starting containers..."
    docker-compose up --build -d
    
    echo "⏳ Waiting for services to start..."
    sleep 10
    
    # Check service health
    echo "🔍 Checking service health..."
    
    if curl -f http://localhost:8000/health >/dev/null 2>&1; then
        echo "✅ Backend API is healthy"
    else
        echo "⚠️ Backend API may not be ready yet"
    fi
    
    if curl -f http://localhost:8501 >/dev/null 2>&1; then
        echo "✅ Frontend is accessible"
    else
        echo "⚠️ Frontend may not be ready yet"
    fi
}

# Function to show status
show_status() {
    echo "📊 Container status:"
    docker-compose ps
}

# Function to show logs
show_logs() {
    echo "📋 Recent logs:"
    docker-compose logs --tail=20
}

# Function to stop services
stop() {
    echo "🛑 Stopping containers..."
    docker-compose down
    echo "✅ All containers stopped"
}

# Function to cleanup
cleanup() {
    echo "🧹 Cleaning up containers and volumes..."
    docker-compose down -v --remove-orphans
    docker system prune -f
    echo "✅ Cleanup completed"
}

# Parse command line arguments
case "${1:-deploy}" in
    deploy)
        deploy
        show_status
        ;;
    start)
        echo "🚀 Starting existing containers..."
        docker-compose start
        show_status
        ;;
    stop)
        stop
        ;;
    restart)
        echo "🔄 Restarting containers..."
        docker-compose restart
        show_status
        ;;
    status)
        show_status
        ;;
    logs)
        show_logs
        ;;
    cleanup)
        cleanup
        ;;
    *)
        echo "Usage: $0 {deploy|start|stop|restart|status|logs|cleanup}"
        echo ""
        echo "Commands:"
        echo "  deploy   - Build and start all containers (default)"
        echo "  start    - Start existing containers"
        echo "  stop     - Stop all containers"
        echo "  restart  - Restart all containers"
        echo "  status   - Show container status"
        echo "  logs     - Show recent logs"
        echo "  cleanup  - Stop containers and clean up"
        exit 1
        ;;
esac

if [ "$1" = "deploy" ] || [ -z "$1" ]; then
    echo ""
    echo "🎉 Deployment completed!"
    echo ""
    echo "🌐 Access points:"
    echo "   Frontend: http://localhost:8501"
    echo "   Backend API: http://localhost:8000"
    echo "   API Docs: http://localhost:8000/docs"
    echo "   Nginx Proxy: http://localhost"
    echo ""
    echo "🔐 Default credentials:"
    echo "   Username: admin"
    echo "   Password: admin123"
    echo ""
    echo "📊 Monitor with: $0 status"
    echo "📋 View logs with: $0 logs"
    echo "🛑 Stop with: $0 stop"
fi