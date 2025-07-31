#!/bin/bash

# Script to run the AWS public resources scanner
# This script handles Docker container configuration and execution

set -e

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Función para mostrar mensajes
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

# Verificar si Docker está disponible
check_docker() {
    if ! command -v docker &> /dev/null; then
        log_error "Docker no está instalado o no está en el PATH"
        exit 1
    fi
    
    if ! docker info &> /dev/null; then
        log_error "Docker no está funcionando. ¿Está el daemon de Docker iniciado?"
        exit 1
    fi
    
    log_success "Docker está disponible"
}

# Verificar si existe el archivo .env
check_env_file() {
    if [ ! -f ".env" ]; then
        log_warning "Archivo .env no encontrado"
        log_info "Creando .env desde .env.example..."
        
        if [ -f ".env.example" ]; then
            cp .env.example .env
            log_warning "Por favor, edita el archivo .env con tus credenciales de AWS antes de continuar"
            log_info "Editando .env..."
            ${EDITOR:-nano} .env
        else
            log_error "Archivo .env.example no encontrado"
            exit 1
        fi
    else
        log_success "Archivo .env encontrado"
    fi
}

# Verificar credenciales en .env
check_credentials() {
    local has_key=$(grep -c "^AWS_ACCESS_KEY_ID=" .env 2>/dev/null || echo "0")
    local has_secret=$(grep -c "^AWS_SECRET_ACCESS_KEY=" .env 2>/dev/null || echo "0")
    
    if [ "$has_key" -eq 0 ] || [ "$has_secret" -eq 0 ]; then
        log_error "Credenciales de AWS no configuradas en .env"
        log_info "Asegúrate de configurar AWS_ACCESS_KEY_ID y AWS_SECRET_ACCESS_KEY"
        exit 1
    fi
    
    # Verificar que no estén vacías
    source .env
    if [ -z "$AWS_ACCESS_KEY_ID" ] || [ -z "$AWS_SECRET_ACCESS_KEY" ]; then
        log_error "Las credenciales de AWS están vacías en .env"
        exit 1
    fi
    
    log_success "Credenciales de AWS configuradas"
}

# Construir imagen Docker
build_image() {
    log_info "Construyendo imagen Docker..."
    docker build -t aws-public-scanner . || {
        log_error "Error construyendo la imagen Docker"
        exit 1
    }
    log_success "Imagen Docker construida exitosamente"
}

# Crear directorio de logs
create_logs_dir() {
    if [ ! -d "logs" ]; then
        mkdir -p logs
        log_info "Directorio logs creado"
    fi
}

# Ejecutar scanner
run_scanner() {
    log_info "Ejecutando scanner de recursos públicos de AWS..."
    log_info "Los logs se mostrarán en tiempo real..."
    echo
    
    docker run --rm \
        --env-file .env \
        -v "$(pwd)/logs:/app/logs" \
        aws-public-scanner || {
        log_error "Error ejecutando el scanner"
        exit 1
    }
    
    echo
    log_success "Scanner completado"
}

# Mostrar resultados
show_results() {
    local latest_report=$(ls -t logs/public_resources_report_*.json 2>/dev/null | head -n1)
    
    if [ -n "$latest_report" ]; then
        log_info "Reporte más reciente: $latest_report"
        
        # Extraer estadísticas básicas del JSON
        local total_resources=$(jq -r '.total_resources_scanned // "N/A"' "$latest_report" 2>/dev/null)
        local public_resources=$(jq -r '.public_resources_found // "N/A"' "$latest_report" 2>/dev/null)
        
        echo
        echo "📊 RESUMEN DEL ESCANEO:"
        echo "├─ Total de recursos escaneados: $total_resources"
        echo "├─ Recursos públicos encontrados: $public_resources"
        echo "└─ Reporte guardado en: $latest_report"
        echo
        
        if [ "$public_resources" != "0" ] && [ "$public_resources" != "N/A" ]; then
            log_warning "⚠️  Se encontraron recursos públicos. Revisa el reporte para detalles."
        else
            log_success "✅ ¡Excelente! No se encontraron recursos públicos."
        fi
    else
        log_warning "No se encontró ningún reporte de resultados"
    fi
}

# Función de ayuda
show_help() {
    echo "AWS Public Resources Scanner"
    echo ""
    echo "Uso: $0 [OPCIÓN]"
    echo ""
    echo "Opciones:"
    echo "  help, -h, --help     Mostrar esta ayuda"
    echo "  build               Solo construir la imagen Docker"
    echo "  run                 Solo ejecutar (asume que la imagen ya existe)"
    echo "  setup               Solo verificar configuración"
    echo "  logs                Mostrar logs del último escaneo"
    echo ""
    echo "Sin argumentos ejecuta el proceso completo: verificación + construcción + ejecución"
}

# Mostrar logs
show_logs() {
    local latest_log=$(ls -t logs/*.log 2>/dev/null | head -n1)
    
    if [ -n "$latest_log" ]; then
        log_info "Mostrando logs del archivo: $latest_log"
        echo
        tail -50 "$latest_log"
    else
        log_warning "No se encontraron archivos de log"
    fi
}

# Función principal
main() {
    echo "🔍 AWS Public Resources Scanner"
    echo "================================="
    echo
    
    case "${1:-}" in
        "help"|"-h"|"--help")
            show_help
            exit 0
            ;;
        "build")
            check_docker
            build_image
            log_success "Construcción completada"
            exit 0
            ;;
        "run")
            check_docker
            check_env_file
            check_credentials
            create_logs_dir
            run_scanner
            show_results
            exit 0
            ;;
        "setup")
            check_docker
            check_env_file
            check_credentials
            log_success "Configuración verificada correctamente"
            exit 0
            ;;
        "logs")
            show_logs
            exit 0
            ;;
        "")
            # Proceso completo
            check_docker
            check_env_file
            check_credentials
            create_logs_dir
            build_image
            run_scanner
            show_results
            ;;
        *)
            log_error "Opción desconocida: $1"
            show_help
            exit 1
            ;;
    esac
}

# Ejecutar función principal
main "$@"
