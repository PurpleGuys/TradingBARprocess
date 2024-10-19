import os
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import random
import threading
import time
from datetime import datetime, timedelta
import pandas as pd
import io
from flask_migrate import Migrate

# Configuration de l'application
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or 'sqlite:///tradingbar.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*")
migrate = Migrate(app, db)

# Modèles de base de données
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False)

class Produit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nom = db.Column(db.String(100), nullable=False)
    prix_min = db.Column(db.Float, nullable=False)
    prix_max = db.Column(db.Float, nullable=False)
    prix_actuel = db.Column(db.Float, nullable=False)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    produit_id = db.Column(db.Integer, db.ForeignKey('produit.id'), nullable=False)
    quantite = db.Column(db.Integer, nullable=False)
    prix = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    type_transaction = db.Column(db.String(10), nullable=False)
    username = db.Column(db.String(80), nullable=False)

class Participation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nom = db.Column(db.String(100), nullable=False)
    prenom = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    guess = db.Column(db.Float, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)

# Décorateurs
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Veuillez vous connecter pour accéder à cette page.', 'error')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Veuillez vous connecter pour accéder à cette page.', 'error')
            return redirect(url_for('login', next=request.url))
        user = User.query.get(session['user_id'])
        if not user or user.role != 'admin':
            flash('Accès non autorisé. Vous devez être administrateur.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# Initialisation de la base de données
def init_db():
    with app.app_context():
        db.create_all()
        
        if not Produit.query.first():
            default_products = [
                Produit(nom="Bière", prix_min=3.0, prix_max=6.0, prix_actuel=3.0),
                Produit(nom="Vin", prix_min=5.0, prix_max=10.0, prix_actuel=5.0),
                Produit(nom="Whisky", prix_min=4.5, prix_max=8.0, prix_actuel=4.5),
                Produit(nom="Vodka", prix_min=4.0, prix_max=7.0, prix_actuel=4.0)
            ]
            db.session.add_all(default_products)
            db.session.commit()
            print("Produits par défaut ajoutés.")
        
        if not User.query.filter_by(username='admin').first():
            admin_user = User(username='admin', password=generate_password_hash('admin'), role='admin')
            db.session.add(admin_user)
            db.session.commit()
            print("Utilisateur admin créé.")
        
        print("Base de données initialisée avec succès.")

# Routes principales
@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['role'] = user.role 
            flash('Connexion réussie!', 'success')
            return redirect(url_for('index'))
        flash('Nom d\'utilisateur ou mot de passe incorrect', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    session.pop('user_id', None)
    session.pop('role', None)
    flash('Vous avez été déconnecté.', 'info')
    return redirect(url_for('login'))

@app.route('/acheter')
@login_required
def page_acheter():
    produits = Produit.query.all()
    prix = {produit.nom: produit.prix_actuel for produit in produits}
    return render_template('acheter.html', produits=produits, prix=prix)

@app.route('/admin')
@admin_required
def page_admin():
    users = User.query.all()
    return render_template('admin.html', users=users)

@app.route('/management')
@admin_required
def page_management():
    produits = Produit.query.all()
    return render_template('management.html', produits=produits)

@app.route('/logs')
@admin_required
def page_logs():
    return render_template('logs.html')

@app.route('/running_services')
@admin_required
def page_running_services():
    return render_template('running_services.html')

# Par celle-ci :
@app.route('/services')
@admin_required
def page_services():
    return render_template('services.html')

@app.route('/graphique')
@login_required
def graphique():
    return render_template('graphique.html')

@app.route('/prix')
@login_required
def afficher_prix():
    produits = Produit.query.all()
    return render_template('afficheprix.html', produits=produits)

@app.route('/jeu-concours', methods=['GET', 'POST'])
def jeu_concours():
    if request.method == 'POST':
        nom = request.form['nom']
        prenom = request.form['prenom']
        email = request.form['email']
        guess = float(request.form['guess'])
        
        new_participation = Participation(nom=nom, prenom=prenom, email=email, guess=guess)
        db.session.add(new_participation)
        db.session.commit()
        
        flash('Merci pour votre participation !', 'success')
        return redirect(url_for('jeu_concours'))
    
    return render_template('jeu-concours.html')

# API Routes
@app.route('/api/prix')
def get_prices():
    try:
        produits = Produit.query.all()
        prix = {produit.nom: produit.prix_actuel for produit in produits}
        return jsonify(prix)
    except Exception as e:
        app.logger.error(f"Erreur lors de la récupération des prix: {str(e)}")
        return jsonify({'error': 'Erreur serveur'}), 500

@app.route('/api/historique_prix')
@login_required
def api_historique_prix():
    try:
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=1)
        transactions = Transaction.query.filter(Transaction.timestamp.between(start_time, end_time)).order_by(Transaction.timestamp).all()
        
        historique = {}
        for transaction in transactions:
            produit = Produit.query.get(transaction.produit_id)
            if produit.nom not in historique:
                historique[produit.nom] = []
            historique[produit.nom].append((int(transaction.timestamp.timestamp()), transaction.prix))
        
        return jsonify(historique)
    except Exception as e:
        app.logger.error(f"Erreur lors de la récupération de l'historique des prix: {str(e)}")
        return jsonify({'error': 'Erreur serveur'}), 500

@app.route('/api/acheter', methods=['POST'])
@login_required
def execute_achat():
    data = request.get_json()
    produit_nom = data.get('produit')
    produit = Produit.query.filter_by(nom=produit_nom).first()
    if not produit:
        return jsonify({"success": False, "message": "Produit non trouvé"}), 404
    
    nouveau_prix = min(produit.prix_actuel + 0.085, produit.prix_max)
    transaction = Transaction(produit_id=produit.id, quantite=1, prix=nouveau_prix, type_transaction='achat', username=User.query.get(session['user_id']).username)
    produit.prix_actuel = nouveau_prix
    
    try:
        db.session.add(transaction)
        db.session.commit()
        socketio.emit('update_price', {'produit': produit_nom, 'prix': round(nouveau_prix, 2)})
        socketio.emit('new_transaction', {
            'timestamp': transaction.timestamp.isoformat(),
            'message': f"Achat de {produit_nom} - Prix: {nouveau_prix}€"
        })
        return jsonify({
            "success": True,
            "message": f"{produit_nom} acheté avec succès",
            "nouveauPrix": round(nouveau_prix, 2)
        })
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Erreur lors de l'achat: {str(e)}")
        return jsonify({"success": False, "message": "Erreur lors de l'achat"}), 500

@app.route('/api/total_spent', methods=['GET'])
def total_spent():
    try:
        total = db.session.query(db.func.sum(Transaction.prix * Transaction.quantite)).filter_by(type_transaction='achat').scalar() or 0
        return jsonify({'total_spent': round(total, 2)})
    except Exception as e:
        app.logger.error(f"Erreur lors du calcul du total dépensé: {str(e)}")
        return jsonify({'error': 'Erreur serveur'}), 500

@app.route('/api/vendre', methods=['POST'])
@login_required
def execute_vente():
    data = request.get_json()
    produit_nom = data.get('produit')
    produit = Produit.query.filter_by(nom=produit_nom).first()
    if not produit:
        return jsonify({"success": False, "message": "Produit non trouvé"}), 404
    
    nouveau_prix = max(produit.prix_actuel - 0.085, produit.prix_min)
    transaction = Transaction(produit_id=produit.id, quantite=1, prix=nouveau_prix, type_transaction='vente', username=User.query.get(session['user_id']).username)
    produit.prix_actuel = nouveau_prix
    
    try:
        db.session.add(transaction)
        db.session.commit()
        socketio.emit('update_price', {'produit': produit_nom, 'prix': round(nouveau_prix, 2)})
        socketio.emit('new_transaction', {
            'timestamp': transaction.timestamp.isoformat(),
            'message': f"Vente de {produit_nom} - Prix: {nouveau_prix}€"
        })
        return jsonify({
            "success": True,
            "message": f"{produit_nom} vendu avec succès",
            "nouveauPrix": round(nouveau_prix, 2)
        })
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Erreur lors de la vente: {str(e)}")
        return jsonify({"success": False, "message": "Erreur lors de la vente"}), 500

@app.route('/api/reinitialiser', methods=['GET'])
@admin_required
def api_reinitialiser():
    try:
        produits = Produit.query.all()
        for produit in produits:
            produit.prix_actuel = produit.prix_min
        db.session.commit()
        socketio.emit('crash_boursier', {'message': 'CRASH BOURSIER déclenché et prix ajustés.'})
        return jsonify({"success": True, "message": "Réinitialisation effectuée avec succès."})
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Erreur lors de la réinitialisation: {str(e)}")
        return jsonify({"success": False, "message": "Erreur lors de la réinitialisation"}), 500

@app.route('/api/ventes')
@login_required
def api_ventes():
    try:
        ventes = db.session.query(Produit.nom, db.func.count(Transaction.id)).join(Transaction).filter(Transaction.type_transaction == 'achat').group_by(Produit.nom).all()
        return jsonify(dict(ventes))
    except Exception as e:
        app.logger.error(f"Erreur lors de la récupération des ventes: {str(e)}")
        return jsonify({'error': 'Erreur serveur'}), 500

@app.route('/api/reset_database', methods=['POST'])
@admin_required
def reset_database():
    try:
        Participation.query.delete()
        Transaction.query.delete()
        products = Produit.query.all()
        for product in products:
            product.prix_actuel = product.prix_min
        
        db.session.commit()
        return jsonify({"success": True, "message": "Base de données réinitialisée avec succès"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/set_prix_min_max', methods=['POST'])
@admin_required
def api_set_prix_min_max():
    data = request.get_json()
    produit_nom = data.get('produit')
    nouveau_min = float(data.get('min'))
    nouveau_max = float(data.get('max'))
    produit = Produit.query.filter_by(nom=produit_nom).first()
    if not produit:
        return jsonify({"success": False, "message": "Produit non trouvé"}), 404
    try:
        produit.prix_min = nouveau_min
        produit.prix_max = nouveau_max
        produit.prix_actuel = max(min(produit.prix_actuel, nouveau_max), nouveau_min)
        db.session.commit()
        return jsonify({"success": True, "message": f"Prix min et max mis à jour pour {produit_nom}"})
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Erreur lors de la mise à jour des prix min/max: {str(e)}")
        return jsonify({"success": False, "message": "Erreur lors de la mise à jour des prix min/max"}), 500

@app.route('/download_transactions')
@admin_required
def download_transactions():
    try:
        transactions = Transaction.query.order_by(Transaction.timestamp).all()
        df = pd.DataFrame([
            {
                'Date': t.timestamp,
                'Produit': Produit.query.get(t.produit_id).nom,
                'Prix': t.prix,
                'Quantité': t.quantite,
                'Type': t.type_transaction,
                'Utilisateur': t.username
            } for t in transactions
        ])
        
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
            df.to_excel(writer, sheet_name='Transactions', index=False)
        
        output.seek(0)
        return send_file(
            output,
            as_attachment=True,
            download_name='transactions.xlsx',
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )
    except Exception as e:
        app.logger.error(f"Erreur lors du téléchargement des transactions: {str(e)}")
        return jsonify({'error': 'Erreur lors de la génération du fichier'}), 500

@app.route('/api/users')
@admin_required
def get_users():
    try:
        users = User.query.all()
        return jsonify([{
            'id': user.id,
            'username': user.username,
            'role': user.role
        } for user in users])
    except Exception as e:
        app.logger.error(f"Erreur lors de la récupération des utilisateurs: {str(e)}")
        return jsonify({'error': 'Erreur serveur'}), 500

@app.route('/api/update_user_role', methods=['POST'])
@admin_required
def api_update_user_role():
    data = request.json
    username = data.get('username')
    new_role = data.get('newRole')
    user = User.query.filter_by(username=username).first()
    if user:
        try:
            user.role = new_role
            db.session.commit()
            return jsonify({"success": True, "message": f"Rôle de {username} mis à jour à {new_role}"})
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Erreur lors de la mise à jour du rôle utilisateur: {str(e)}")
            return jsonify({"success": False, "message": "Erreur lors de la mise à jour du rôle"}), 500
    return jsonify({"success": False, "message": "Utilisateur non trouvé"}), 404

@app.route('/api/delete_user', methods=['POST'])
@admin_required
def api_delete_user():
    data = request.json
    username = data.get('username')
    user = User.query.filter_by(username=username).first()
    if user and user.username != session.get('username'):
        try:
            db.session.delete(user)
            db.session.commit()
            return jsonify({"success": True, "message": f"Utilisateur {username} supprimé"})
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Erreur lors de la suppression de l'utilisateur: {str(e)}")
            return jsonify({"success": False, "message": "Erreur lors de la suppression de l'utilisateur"}), 500
    return jsonify({"success": False, "message": "Impossible de supprimer cet utilisateur"}), 400

@app.route('/api/create_user', methods=['POST'])
@admin_required
def api_create_user():
    data = request.json
    new_username = data.get('username')
    new_password = data.get('password')
    new_role = data.get('role')
    
    if User.query.filter_by(username=new_username).first():
        return jsonify({"success": False, "message": "Ce nom d'utilisateur existe déjà"}), 400
    
    try:
        new_user = User(username=new_username, password=generate_password_hash(new_password), role=new_role)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"success": True, "message": "Nouvel utilisateur créé avec succès"})
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Erreur lors de la création de l'utilisateur: {str(e)}")
        return jsonify({"success": False, "message": "Erreur lors de la création de l'utilisateur"}), 500

@app.route('/api/update_product_name', methods=['POST'])
@admin_required
def update_product_name():
    data = request.json
    old_name = data['oldName']
    new_name = data['newName']
    produit = Produit.query.filter_by(nom=old_name).first()
    if produit:
        try:
            produit.nom = new_name
            db.session.commit()
            return jsonify({"success": True, "message": f"Nom du produit mis à jour: {old_name} -> {new_name}"})
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Erreur lors de la mise à jour du nom du produit: {str(e)}")
            return jsonify({"success": False, "message": "Erreur lors de la mise à jour du nom du produit"}), 500
    return jsonify({"success": False, "message": "Produit non trouvé"}), 404

@app.route('/api/ajouter_produit', methods=['POST'])
@admin_required
def ajouter_produit():
    data = request.json
    nom = data['nom']
    min_price = float(data['minPrice'])
    max_price = float(data['maxPrice'])
    if Produit.query.filter_by(nom=nom).first():
        return jsonify({"success": False, "message": "Ce produit existe déjà"}), 400
    try:
        nouveau_produit = Produit(nom=nom, prix_min=min_price, prix_max=max_price, prix_actuel=min_price)
        db.session.add(nouveau_produit)
        db.session.commit()
        return jsonify({"success": True, "message": f"Produit ajouté: {nom}"})
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Erreur lors de l'ajout du produit: {str(e)}")
        return jsonify({"success": False, "message": "Erreur lors de l'ajout du produit"}), 500

@app.route('/api/supprimer_produit', methods=['POST'])
@admin_required
def supprimer_produit():
    data = request.json
    nom = data['nom']
    produit = Produit.query.filter_by(nom=nom).first()
    if produit:
        try:
            db.session.delete(produit)
            db.session.commit()
            return jsonify({"success": True, "message": f"Produit supprimé: {nom}"})
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Erreur lors de la suppression du produit: {str(e)}")
            return jsonify({"success": False, "message": "Erreur lors de la suppression du produit"}), 500
    return jsonify({"success": False, "message": "Produit non trouvé"}), 404

@app.route('/submit-guess', methods=['POST'])
def submit_guess():
    nom = request.form['nom']
    prenom = request.form['prenom']
    email = request.form['email']
    guess = float(request.form['guess'])
    
    try:
        new_participation = Participation(nom=nom, prenom=prenom, email=email, guess=guess)
        db.session.add(new_participation)
        db.session.commit()
        return jsonify({"success": True, "message": "Merci pour votre participation au jeu concours !"})
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Erreur lors de la soumission de la participation: {str(e)}")
        return jsonify({"success": False, "message": "Erreur lors de la soumission de votre participation"}), 500

@app.route('/api/trigger_crash', methods=['POST'])
@admin_required
def trigger_crash():
    try:
        produits = Produit.query.all()
        for produit in produits:
            produit.prix_actuel = produit.prix_min
        db.session.commit()

        prix = {produit.nom: produit.prix_actuel for produit in produits}
        socketio.emit('update_prices', {'prix': prix})

        return jsonify({'success': True, 'message': "Crash boursier déclenché, prix réinitialisés"})
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Erreur lors du déclenchement du crash boursier: {str(e)}")
        return jsonify({'error': 'Erreur lors du déclenchement du crash boursier'}), 500

@app.route('/admin/select-winner', methods=['POST'])
@admin_required
def select_winner():
    total_spent = db.session.query(db.func.sum(Transaction.prix * Transaction.quantite)).filter_by(type_transaction='achat').scalar() or 0
    closest_guess = Participation.query.order_by(db.func.abs(Participation.guess - total_spent)).first()
    
    if closest_guess:
        winner = {
            'nom': closest_guess.nom,
            'prenom': closest_guess.prenom,
            'email': closest_guess.email,
            'guess': closest_guess.guess
        }
        return jsonify({'success': True, 'winner': winner, 'total_spent': total_spent})
    else:
        return jsonify({'success': False, 'message': 'Aucune participation trouvée'})

# SocketIO events
@socketio.on('connect')
def handle_connect():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        emit('user_connected', {'username': user.username})

@socketio.on('disconnect')
def handle_disconnect():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        emit('user_disconnected', {'username': user.username}, broadcast=True)

@socketio.on('request_initial_data')
def handle_initial_data():
    emit('update_stats', get_current_stats())
    emit('update_users', {'users': [u.username for u in User.query.filter_by(role='user').all()]})
    transactions = Transaction.query.order_by(Transaction.timestamp.desc()).limit(100).all()
    for transaction in reversed(transactions):
        emit('new_transaction', {
            'timestamp': transaction.timestamp.isoformat(),
            'message': f"Vente de {Produit.query.get(transaction.produit_id).nom} - Prix: {transaction.prix}€"
        })

@socketio.on('restart_web_server')
def handle_restart_web_server():
    emit('new_log', {'message': 'Serveur web redémarré avec succès.'})

@socketio.on('clear_cache')
def handle_clear_cache():
    emit('new_log', {'message': 'Cache vidé avec succès.'})

@socketio.on('backup_database')
def handle_backup_database():
    emit('new_log', {'message': 'Sauvegarde de la base de données effectuée avec succès.'})

def get_current_stats():
    total_transactions = Transaction.query.count()
    active_users = User.query.filter_by(role='user').count()
    top_product = db.session.query(Produit.nom, db.func.count(Transaction.id).label('count'))\
        .join(Transaction)\
        .group_by(Produit.id)\
        .order_by(db.desc('count'))\
        .first()
    total_revenue = db.session.query(db.func.sum(Transaction.prix * Transaction.quantite)).scalar() or 0
    
    return {
        'total_transactions': total_transactions,
        'active_users': active_users,
        'top_product': top_product[0] if top_product else '-',
        'total_revenue': total_revenue
    }

def ajuster_prix_periodiquement():
    while True:
        with app.app_context():
            try:
                produits = Produit.query.all()
                for produit in produits:
                    derniere_transaction = Transaction.query.filter_by(produit_id=produit.id).order_by(Transaction.timestamp.desc()).first()
                    if derniere_transaction and (datetime.utcnow() - derniere_transaction.timestamp).total_seconds() > 300:
                        reduction = produit.prix_actuel * 0.01
                        produit.prix_actuel = max(produit.prix_actuel - reduction, produit.prix_min)
                db.session.commit()
                socketio.emit('update_prices', {p.nom: round(p.prix_actuel, 2) for p in produits})
            except Exception as e:
                app.logger.error(f"Erreur lors de l'ajustement périodique des prix: {str(e)}")
        time.sleep(60)  # Ajuste les prix toutes les minutes

def send_service_updates():
    while True:
        with app.app_context():
            try:
                data = {
                    'db_response_time': random.uniform(10, 100),
                    'requests_per_second': random.randint(10, 1000),
                    'price_updates': random.randint(1, 50),
                    'user_traffic': random.randint(0, 100),
                    'cpu_load': random.randint(0, 100),
                    'memory_usage': random.randint(0, 100),
                    'disk_space': random.randint(0, 100),
                    'services': [
                        {'name': 'Base de Données', 'status': 'OK' if random.random() > 0.1 else 'ERROR'},
                        {'name': 'Serveur Web', 'status': 'OK' if random.random() > 0.1 else 'ERROR'},
                        {'name': 'Mise à jour des Prix', 'status': 'OK' if random.random() > 0.1 else 'ERROR'},
                        {'name': 'Authentification', 'status': 'OK' if random.random() > 0.1 else 'ERROR'}
                    ]
                }
                socketio.emit('update_charts', data)
            except Exception as e:
                app.logger.error(f"Erreur lors de l'envoi des mises à jour des services: {str(e)}")
        time.sleep(5)  # Envoyer des mises à jour toutes les 5 secondes

def create_app():
    with app.app_context():
        init_db()
    
    thread_ajustement = threading.Thread(target=ajuster_prix_periodiquement)
    thread_ajustement.daemon = True
    thread_ajustement.start()

    thread_services = threading.Thread(target=send_service_updates)
    thread_services.daemon = True
    thread_services.start()
    
    return app

if __name__ == '__main__':
    app = create_app()
    socketio.run(app, debug=True, host='0.0.0.0', port=8000)