#!/bin/bash

# Script pour gérer les environnements Docker
# Usage: ./scripts/docker-env.sh [dev|prod|test]

set -e

ENV=${1:-dev}
COMPOSE_FILES="-f docker-compose.yml"

case $ENV in
    dev)
        echo "🚀 Lancement en mode développement..."
        COMPOSE_FILES="$COMPOSE_FILES -f docker-compose.override.yml"
        ;;
    prod)
        echo "🚀 Lancement en mode production..."
        COMPOSE_FILES="$COMPOSE_FILES -f docker-compose.prod.yml"
        ;;
    test)
        echo "🧪 Lancement en mode test..."
        COMPOSE_FILES="$COMPOSE_FILES -f docker-compose.test.yml"
        ;;
    *)
        echo "❌ Environnement invalide. Utilisez: dev, prod, ou test"
        exit 1
        ;;
esac

# Vérifier que le fichier .env existe
if [ ! -f .env ]; then
    echo "⚠️  Fichier .env non trouvé. Copie depuis env.example..."
    cp env.example .env
    echo "📝 Veuillez éditer le fichier .env avec vos paramètres"
    exit 1
fi

# Vérifier les variables critiques
source .env

if [ "$ENV" = "prod" ]; then
    echo "🔍 Vérification des variables de production..."
    
    # Variables critiques pour la production
    CRITICAL_VARS=(
        "SMTP_USERNAME"
        "SMTP_PASSWORD"
        "MONGODB_USERNAME"
        "MONGODB_PASSWORD"
        "MONGODB_CLUSTER_URL"
    )
    
    for var in "${CRITICAL_VARS[@]}"; do
        if [ -z "${!var}" ] || [ "${!var}" = "your_${var,,}" ]; then
            echo "❌ Variable critique manquante ou non configurée: $var"
            exit 1
        fi
    done
    
    echo "✅ Toutes les variables critiques sont configurées"
fi

# Afficher la configuration
echo "📋 Configuration:"
echo "   Environnement: $ENV"
echo "   Fichiers Compose: $COMPOSE_FILES"
echo "   SMTP TLS: ${SMTP_TLS_ADDR:-non défini}"
echo "   SMTP Plain: ${SMTP_PLAIN_ADDR:-non défini}"
echo "   API Server: ${API_SERVER_ADDR:-non défini}"

# Lancer les services
echo "🐳 Lancement des services..."
docker-compose $COMPOSE_FILES up -d

echo "✅ Services lancés avec succès!"
echo "📊 Vérifier l'état: docker-compose $COMPOSE_FILES ps"
echo "📝 Voir les logs: docker-compose $COMPOSE_FILES logs -f" 