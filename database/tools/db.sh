log()
{
	BLUE='\033[0;34m'
	NC='\033[0m'
	echo -e "${BLUE}$(date +"%Y-%m-%d %H:%M:%S") - ${NC}$1"
}

# Attendre quelques secondes pour laisser le service PostgreSQL démarrer complètement
sleep 10

log "Initialisation de la base de données..."

# Exécuter la commande psql pour changer le mot de passe de l'utilisateur postgres
psql -U postgres -c "ALTER USER postgres WITH PASSWORD 'mypasswordpong4!'"

# Vérifier le code de sortie de la commande psql
if [ $? -ne 0 ]; then
	log "Une erreur s'est produite lors de l'exécution de la commande ALTER USER postgres WITH PASSWORD."
	log "Code de sortie: $?"
	exit 1  # Quitter le script avec un code d'erreur
fi

log "Fin du script, tout est bon"
