import os
import logging
import secrets
import hashlib
import smtplib
from email.message import EmailMessage
from flask import Flask, request, jsonify
from datetime import datetime, timedelta, timezone
from flask_cors import CORS
from sqlalchemy.exc import IntegrityError
from models import db, User, Profile, Service, Event, EventPack, Reservation, ReservationStatus, TokenBlocklist, PasswordResetToken
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity, get_jwt, decode_token,
    set_access_cookies, set_refresh_cookies, unset_jwt_cookies,
)
from werkzeug.security import check_password_hash
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from collections import OrderedDict
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///eventify.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config['JWT_SECRET_KEY'] = os.getenv("JWT_SECRET_KEY")
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_COOKIE_SECURE'] = os.getenv('JWT_COOKIE_SECURE', 'false').lower() == 'true'
app.config['JWT_COOKIE_SAMESITE'] = 'Lax'
app.config['JWT_COOKIE_CSRF_PROTECT'] = True
app.config['JWT_ACCESS_CSRF_HEADER_NAME'] = 'X-CSRF-TOKEN'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=15)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=7)

db.init_app(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)

# TODO(prod): replace memory:// with redis:// so limits survive restarts and are shared across workers
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[],
    storage_uri=os.getenv("RATELIMIT_STORAGE_URI", "memory://"),
)

_cors_origins = os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")
CORS(app, resources={r"/*": {"origins": _cors_origins}}, supports_credentials=True)

FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")
PASSWORD_RESET_TOKEN_TTL = timedelta(hours=1)

# ── Argon2id password helpers ───────────────────────────────────────────────
_ph = PasswordHasher()

def hash_password(pw: str) -> str:
    return _ph.hash(pw)

def verify_password(stored: str, provided: str) -> bool:
    try:
        _ph.verify(stored, provided)
        return True
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        pass
    # pbkdf2 fallback for hashes created before the Argon2 migration
    try:
        return check_password_hash(stored, provided)
    except Exception:
        return False

# ── Token blocklist ─────────────────────────────────────────────────────────
@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload['jti']
    if db.session.execute(
        db.select(TokenBlocklist).filter_by(jti=jti)
    ).scalar_one_or_none() is not None:
        return True

    # Tokens issued before the user's last password change/reset are no longer valid,
    # even if they haven't individually been blocklisted (e.g. other active sessions).
    user_id = jwt_payload.get('sub')
    if user_id is None:
        return False
    user = db.session.get(User, int(user_id))
    if not user or not user.password_changed_at:
        return False
    changed_at = user.password_changed_at
    if changed_at.tzinfo is None:
        changed_at = changed_at.replace(tzinfo=timezone.utc)
    # jwt 'iat' has whole-second precision, so truncate changed_at the same way —
    # otherwise a token minted in the same second as the change (e.g. logout-all
    # re-issuing cookies right after bumping password_changed_at) would be born revoked.
    changed_at = changed_at.replace(microsecond=0)
    issued_at = datetime.fromtimestamp(jwt_payload['iat'], tz=timezone.utc)
    return issued_at < changed_at


# ── Password reset email ────────────────────────────────────────────────────
def send_password_reset_email(to_email: str, reset_link: str) -> None:
    smtp_host = os.getenv('SMTP_HOST')
    if not smtp_host:
        logger.info("SMTP not configured. Password reset link for %s: %s", to_email, reset_link)
        return
    smtp_port = int(os.getenv('SMTP_PORT', '587'))
    smtp_user = os.getenv('SMTP_USER')
    smtp_password = os.getenv('SMTP_PASSWORD')
    smtp_from = os.getenv('SMTP_FROM', smtp_user)

    msg = EmailMessage()
    msg['Subject'] = 'Recupera tu contraseña - EventifyPro'
    msg['From'] = smtp_from
    msg['To'] = to_email
    msg.set_content(
        "Recibimos una solicitud para restablecer tu contraseña.\n\n"
        f"Haz clic en el siguiente link (válido por 1 hora):\n{reset_link}\n\n"
        "Si no solicitaste esto, puedes ignorar este correo."
    )
    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
            server.starttls()
            if smtp_user and smtp_password:
                server.login(smtp_user, smtp_password)
            server.send_message(msg)
    except Exception as e:
        logger.error("Failed to send password reset email to %s: %s", to_email, e)


def parse_json_body():
    """Returns the parsed JSON body as a dict, or None if missing/malformed/not an object."""
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else None


def _user_info(user):
    return {
        'id': user.id,
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'profile': {
            'phone_number': user.profile.phone_number,
            'address': user.profile.address,
            'description': user.profile.description,
            'company_name': user.profile.company_name,
            'url_portfolio': user.profile.url_portfolio,
            'role': user.profile.role,
        }
    }


def get_reservation_status_in_english(status):
    return {"Pendiente": "PENDING", "Confirmada": "CONFIRMED",
            "Cancelada": "CANCELLED", "Finalizada": "COMPLETED"}.get(status, status)


def get_reservation_status_in_spanish(status):
    return {"PENDING": "Pendiente", "CONFIRMED": "Confirmada",
            "CANCELLED": "Cancelada", "COMPLETED": "Finalizada"}.get(status, status)


################################## LOGIN ##################################
@app.route('/user/login', methods=['POST'])
@limiter.limit("10 per minute")
def login_user():
    data = parse_json_body() or {}
    email = data.get('email')
    password = data.get('password')
    user = User.query.filter_by(email=email).first()
    if not user or not verify_password(user.password, password):
        return jsonify({"msg": "Bad username or password"}), 401
    access_token = create_access_token(identity=str(user.id))
    refresh_token = create_refresh_token(identity=str(user.id))
    resp = jsonify(user=_user_info(user))
    set_access_cookies(resp, access_token)
    set_refresh_cookies(resp, refresh_token)
    return resp, 200


############################### REGISTRO ##################################
@app.route('/user', methods=['POST'])
def create_user():
    data = parse_json_body() or {}
    required = ['email', 'password', 'first_name', 'last_name', 'profile']
    for field in required:
        if field not in data:
            return jsonify({"msg": f"Missing field: {field}"}), 422
    profile_required = ['phone_number', 'address', 'description', 'company_name', 'url_portfolio', 'role']
    for field in profile_required:
        if field not in data.get('profile', {}):
            return jsonify({"msg": f"Missing profile field: {field}"}), 422
    if data['profile']['role'] not in ('Cliente', 'Proveedor'):
        return jsonify({"msg": "Role must be 'Cliente' or 'Proveedor'"}), 422
    if User.query.filter_by(email=data['email']).first():
        return jsonify({"msg": "Email already exists"}), 409
    try:
        user = User(
            email=data['email'],
            password=hash_password(data['password']),
            first_name=data['first_name'],
            last_name=data['last_name'],
        )
        profile = Profile(
            user=user,
            phone_number=data['profile']['phone_number'],
            address=data['profile']['address'],
            description=data['profile']['description'],
            company_name=data['profile']['company_name'],
            url_portfolio=data['profile']['url_portfolio'],
            role=data['profile']['role'],
        )
        db.session.add(user)
        db.session.add(profile)
        db.session.commit()
        access_token = create_access_token(identity=str(user.id))
        refresh_token = create_refresh_token(identity=str(user.id))
        resp = jsonify({"msg": "User created successfully", "user": _user_info(user)})
        set_access_cookies(resp, access_token)
        set_refresh_cookies(resp, refresh_token)
        return resp, 201
    except IntegrityError as e:
        db.session.rollback()
        logger.warning("Integrity error creating user: %s", e)
        return jsonify({"msg": "Email already exists"}), 409
    except Exception as e:
        db.session.rollback()
        logger.error("Error creating user: %s", e)
        return jsonify({"msg": "Error creating user"}), 500


############################### TOKEN REFRESH / LOGOUT ##################################
@app.route('/auth/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh_token():
    identity = get_jwt_identity()
    old_jti = get_jwt()['jti']
    db.session.add(TokenBlocklist(jti=old_jti))
    db.session.commit()
    new_access = create_access_token(identity=identity)
    new_refresh = create_refresh_token(identity=identity)
    resp = jsonify({'msg': 'refreshed'})
    set_access_cookies(resp, new_access)
    set_refresh_cookies(resp, new_refresh)
    return resp, 200


@app.route('/auth/logout', methods=['POST'])
@jwt_required(optional=True)
def logout():
    jwt_data = get_jwt()
    if jwt_data:
        db.session.add(TokenBlocklist(jti=jwt_data['jti']))
    # Also blocklist the refresh token so it can't mint new access tokens after logout
    refresh_cookie = request.cookies.get('refresh_token_cookie')
    if refresh_cookie:
        try:
            refresh_data = decode_token(refresh_cookie, allow_expired=True)
            db.session.add(TokenBlocklist(jti=refresh_data['jti']))
        except Exception:
            pass
    db.session.commit()
    resp = jsonify({'msg': 'logged out'})
    unset_jwt_cookies(resp)
    return resp, 200


@app.route('/auth/forgot-password', methods=['POST'])
@limiter.limit("5 per minute")
def forgot_password():
    data = parse_json_body() or {}
    email = data.get('email')
    generic_response = jsonify({"msg": "Si el email existe, se enviará un link de recuperación"})

    if not email:
        return generic_response, 200

    user = User.query.filter_by(email=email).first()
    if not user:
        return generic_response, 200

    try:
        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        reset_token = PasswordResetToken(
            user_id=user.id,
            token_hash=token_hash,
            expires_at=datetime.now(timezone.utc) + PASSWORD_RESET_TOKEN_TTL,
        )
        db.session.add(reset_token)
        db.session.commit()

        reset_link = f"{FRONTEND_URL}/reset-password?token={raw_token}"
        send_password_reset_email(user.email, reset_link)
    except Exception as e:
        db.session.rollback()
        logger.error("Error generating password reset token for %s: %s", email, e)

    return generic_response, 200


@app.route('/auth/reset-password', methods=['POST'])
@limiter.limit("10 per minute")
def reset_password():
    data = parse_json_body() or {}
    raw_token = data.get('token')
    new_password = data.get('newPassword')

    if not raw_token or not new_password:
        return jsonify({"msg": "Token y nueva contraseña son requeridos"}), 400

    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    reset_token = PasswordResetToken.query.filter_by(token_hash=token_hash).first()
    if not reset_token:
        return jsonify({"msg": "Token inválido o expirado"}), 400

    if reset_token.used_at is not None:
        return jsonify({"msg": "Token inválido o expirado"}), 400

    expires_at = reset_token.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        return jsonify({"msg": "Token inválido o expirado"}), 400

    user = db.session.get(User, reset_token.user_id)
    if not user:
        return jsonify({"msg": "Token inválido o expirado"}), 400

    try:
        now = datetime.now(timezone.utc)
        user.password = hash_password(new_password)
        user.password_changed_at = now
        reset_token.used_at = now
        db.session.commit()
        return jsonify({"msg": "Contraseña actualizada correctamente"}), 200
    except Exception as e:
        db.session.rollback()
        logger.error("Error resetting password for user %s: %s", reset_token.user_id, e)
        return jsonify({"msg": "Error al actualizar la contraseña"}), 500


@app.route('/user/me', methods=['GET'])
@jwt_required()
def get_user_info():
    user_id = int(get_jwt_identity())
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({"msg": "User not found"}), 404
    return jsonify({
        "id": user.id,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "email": user.email,
        "role": user.profile.role,
    }), 200


########################## ACTUALIZAR USUARIOS ############################
@app.route('/user/<int:user_id>', methods=['GET'])
@jwt_required()
def get_user(user_id):
    if int(get_jwt_identity()) != user_id:
        return jsonify({"msg": "Unauthorized"}), 403
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({"msg": "User not found"}), 404
    return jsonify({
        "id": user.id,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "email": user.email,
        "profile": {
            "phone_number": user.profile.phone_number,
            "address": user.profile.address,
            "description": user.profile.description,
            "company_name": user.profile.company_name,
            "url_portfolio": user.profile.url_portfolio,
            "role": user.profile.role,
        }
    }), 200


@app.route('/user/<int:user_id>', methods=['PUT'])
@jwt_required()
def update_user(user_id):
    if int(get_jwt_identity()) != user_id:
        return jsonify({"msg": "Unauthorized"}), 403
    data = parse_json_body() or {}
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({"msg": "User not found"}), 404
    try:
        user.first_name = data.get('first_name', user.first_name)
        user.last_name = data.get('last_name', user.last_name)
        new_email = data.get('email', user.email)
        if new_email != user.email:
            if User.query.filter(User.email == new_email, User.id != user_id).first():
                return jsonify({"msg": "El email ya está en uso"}), 409
        user.email = new_email

        current_password = data.get('currentPassword')
        new_password = data.get('newPassword')
        confirm_password = data.get('confirmPassword')

        if new_password:
            if not current_password:
                return jsonify({"msg": "Se requiere la contraseña actual para cambiarla"}), 400
            if not verify_password(user.password, current_password):
                return jsonify({"msg": "Contraseña actual incorrecta"}), 400
            if new_password != confirm_password:
                return jsonify({"msg": "Las nuevas contraseñas no coinciden"}), 400
            user.password = hash_password(new_password)
            user.password_changed_at = datetime.now(timezone.utc)

        if 'profile' in data:
            user.profile.phone_number = data['profile'].get('phone_number', user.profile.phone_number)
            user.profile.address = data['profile'].get('address', user.profile.address)
            user.profile.description = data['profile'].get('description', user.profile.description)
            user.profile.company_name = data['profile'].get('company_name', user.profile.company_name)
            user.profile.url_portfolio = data['profile'].get('url_portfolio', user.profile.url_portfolio)

        db.session.commit()
        return jsonify({"msg": "User updated successfully", "user": _user_info(user)}), 200
    except IntegrityError as e:
        db.session.rollback()
        logger.warning("Integrity error updating user %s: %s", user_id, e)
        return jsonify({"msg": "El email ya está en uso"}), 409
    except Exception as e:
        db.session.rollback()
        logger.error("Error updating user %s: %s", user_id, e)
        return jsonify({"msg": "Error updating user"}), 500


########################## CUENTA / PERFIL (endpoints divididos) ##########
@app.route('/me', methods=['GET'])
@jwt_required()
def get_me():
    user_id = int(get_jwt_identity())
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({"msg": "User not found"}), 404
    return jsonify(_user_info(user)), 200


@app.route('/me/profile', methods=['PATCH'])
@jwt_required()
def update_my_profile():
    user_id = int(get_jwt_identity())
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({"msg": "User not found"}), 404
    data = parse_json_body() or {}
    try:
        user.first_name = data.get('first_name', user.first_name)
        user.last_name = data.get('last_name', user.last_name)
        user.profile.phone_number = data.get('phone_number', user.profile.phone_number)
        user.profile.address = data.get('address', user.profile.address)
        db.session.commit()
        return jsonify({"msg": "Profile updated successfully", "user": _user_info(user)}), 200
    except Exception as e:
        db.session.rollback()
        logger.error("Error updating profile for user %s: %s", user_id, e)
        return jsonify({"msg": "Error updating profile"}), 500


@app.route('/me/provider-profile', methods=['PATCH'])
@jwt_required()
def update_my_provider_profile():
    user_id = int(get_jwt_identity())
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({"msg": "User not found"}), 404
    if user.profile.role != 'Proveedor':
        return jsonify({"msg": "Unauthorized"}), 403
    data = parse_json_body() or {}
    try:
        user.profile.company_name = data.get('company_name', user.profile.company_name)
        user.profile.url_portfolio = data.get('url_portfolio', user.profile.url_portfolio)
        user.profile.description = data.get('description', user.profile.description)
        db.session.commit()
        return jsonify({"msg": "Business profile updated successfully", "user": _user_info(user)}), 200
    except Exception as e:
        db.session.rollback()
        logger.error("Error updating provider profile for user %s: %s", user_id, e)
        return jsonify({"msg": "Error updating business profile"}), 500


@app.route('/me/account/email', methods=['PATCH'])
@jwt_required()
def update_my_email():
    user_id = int(get_jwt_identity())
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({"msg": "User not found"}), 404
    data = parse_json_body() or {}
    new_email = data.get('new_email')
    current_password = data.get('current_password')

    if not new_email or not current_password:
        return jsonify({"msg": "Email y contraseña actual son requeridos"}), 400
    if not verify_password(user.password, current_password):
        return jsonify({"msg": "Contraseña actual incorrecta"}), 400
    if new_email == user.email:
        return jsonify({"msg": "Email updated successfully", "user": _user_info(user)}), 200
    if User.query.filter(User.email == new_email, User.id != user_id).first():
        return jsonify({"msg": "El email ya está en uso"}), 409

    try:
        user.email = new_email
        db.session.commit()
        return jsonify({"msg": "Email updated successfully", "user": _user_info(user)}), 200
    except IntegrityError as e:
        db.session.rollback()
        logger.warning("Integrity error updating email for user %s: %s", user_id, e)
        return jsonify({"msg": "El email ya está en uso"}), 409
    except Exception as e:
        db.session.rollback()
        logger.error("Error updating email for user %s: %s", user_id, e)
        return jsonify({"msg": "Error updating email"}), 500


@app.route('/me/account/change-password', methods=['POST'])
@jwt_required()
def change_my_password():
    user_id = int(get_jwt_identity())
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({"msg": "User not found"}), 404
    data = parse_json_body() or {}
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    confirm_password = data.get('confirm_password')

    if not current_password or not new_password:
        return jsonify({"msg": "Se requiere la contraseña actual y la nueva"}), 400
    if not verify_password(user.password, current_password):
        return jsonify({"msg": "Contraseña actual incorrecta"}), 400
    if new_password != confirm_password:
        return jsonify({"msg": "Las nuevas contraseñas no coinciden"}), 400

    try:
        user.password = hash_password(new_password)
        user.password_changed_at = datetime.now(timezone.utc)
        db.session.commit()
        return jsonify({"msg": "Contraseña actualizada correctamente"}), 200
    except Exception as e:
        db.session.rollback()
        logger.error("Error changing password for user %s: %s", user_id, e)
        return jsonify({"msg": "Error al actualizar la contraseña"}), 500


@app.route('/me/security/logout-all', methods=['POST'])
@jwt_required()
def logout_all_other_sessions():
    user_id = int(get_jwt_identity())
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({"msg": "User not found"}), 404
    try:
        user.password_changed_at = datetime.now(timezone.utc)
        db.session.commit()
        # Re-issue fresh tokens so the current device stays logged in
        # while every other previously-issued token becomes invalid.
        new_access = create_access_token(identity=str(user_id))
        new_refresh = create_refresh_token(identity=str(user_id))
        resp = jsonify({"msg": "Se cerraron todas las otras sesiones"})
        set_access_cookies(resp, new_access)
        set_refresh_cookies(resp, new_refresh)
        return resp, 200
    except Exception as e:
        db.session.rollback()
        logger.error("Error logging out other sessions for user %s: %s", user_id, e)
        return jsonify({"msg": "Error al cerrar las otras sesiones"}), 500


########################### SERVICIOS #####################################
@app.route('/services', methods=['POST'])
@jwt_required()
def add_service():
    user_id = int(get_jwt_identity())
    user = db.session.get(User, user_id)
    if not user or user.profile.role != 'Proveedor':
        return jsonify({"msg": "Unauthorized"}), 403
    data = parse_json_body() or {}
    required_fields = ['name', 'type', 'price', 'description', 'location']
    for field in required_fields:
        if field not in data:
            return jsonify({"msg": f"Missing field: {field}"}), 422
    try:
        service = Service(
            name=data['name'],
            type=data['type'],
            price=data['price'],
            pricing_type=data.get('pricingType', 'por evento'),
            description=data['description'],
            location=data['location'],
            profile_id=user.profile.id,
        )
        db.session.add(service)
        db.session.commit()
        return jsonify({"msg": "Service added", "service_id": service.id}), 201
    except Exception as e:
        db.session.rollback()
        logger.error("Error adding service for user %s: %s", user_id, e)
        return jsonify({"msg": "Error adding service"}), 500


@app.route('/services', methods=['GET'])
def get_services():
    service_type = request.args.get('type')
    query = Service.query
    if service_type:
        query = query.filter(Service.type == service_type)
    services = query.all()
    services_list = []
    for service in services:
        profile = service.profile
        if profile:
            user = profile.user
            if user:
                services_list.append({
                    "id": service.id,
                    "name": service.name,
                    "type": service.type,
                    "price": service.price,
                    "pricingType": service.pricing_type or 'por evento',
                    "description": service.description,
                    "location": service.location,
                    "provider_first_name": user.first_name,
                    "provider_last_name": user.last_name,
                    "company_name": profile.company_name,
                    "profile_id": profile.id,
                    "created_at": service.created_at.isoformat(),
                })
    return jsonify(services_list), 200


@app.route('/provider/<int:provider_id>/services', methods=['GET'])
@jwt_required()
def get_provider_services(provider_id):
    user_id_from_token = int(get_jwt_identity())
    user = db.session.get(User, user_id_from_token)
    if not user or user.profile.role != 'Proveedor' or user.id != provider_id:
        return jsonify({"msg": "Unauthorized"}), 403
    services = Service.query.filter_by(profile_id=user.profile.id).all()
    return jsonify([{
        "id": s.id,
        "name": s.name,
        "type": s.type,
        "price": s.price,
        "pricingType": s.pricing_type or 'por evento',
        "description": s.description,
        "location": s.location,
        "created_at": s.created_at.isoformat(),
    } for s in services]), 200


@app.route('/services/<int:service_id>', methods=['PUT'])
@jwt_required()
def update_service(service_id):
    user_id = int(get_jwt_identity())
    user = db.session.get(User, user_id)
    service = db.session.get(Service, service_id)
    if not service:
        return jsonify({"msg": "Service not found"}), 404
    if service.profile_id != user.profile.id:
        return jsonify({"msg": "Unauthorized"}), 403
    data = parse_json_body() or {}
    try:
        service.name = data.get('name', service.name)
        service.type = data.get('type', service.type)
        service.price = data.get('price', service.price)
        service.pricing_type = data.get('pricingType', service.pricing_type)
        service.description = data.get('description', service.description)
        service.location = data.get('location', service.location)
        db.session.commit()
        return jsonify({"msg": "Service updated"}), 200
    except Exception as e:
        db.session.rollback()
        logger.error("Error updating service %s: %s", service_id, e)
        return jsonify({"msg": "Error updating service"}), 500


@app.route('/services/<int:service_id>', methods=['DELETE'])
@jwt_required()
def delete_service(service_id):
    user_id = int(get_jwt_identity())
    user = db.session.get(User, user_id)
    service = db.session.get(Service, service_id)
    if not service:
        return jsonify({"msg": "Service not found"}), 404
    if service.profile_id != user.profile.id:
        return jsonify({"msg": "Unauthorized"}), 403
    if Reservation.query.filter_by(service_id=service_id).count() > 0:
        return jsonify({"msg": "No se puede eliminar el servicio porque tiene reservas asociadas"}), 400
    try:
        db.session.delete(service)
        db.session.commit()
        return jsonify({"msg": "Service deleted"}), 200
    except Exception as e:
        db.session.rollback()
        logger.error("Error deleting service %s: %s", service_id, e)
        return jsonify({"msg": "Error deleting service"}), 500


############### EVENTOS ##################################################
@app.route('/events', methods=['POST'])
@jwt_required()
def create_event():
    user_id = int(get_jwt_identity())
    user = db.session.get(User, user_id)
    if user.profile.role != 'Cliente':
        return jsonify({"msg": "Unauthorized"}), 403
    data = parse_json_body() or {}
    required_fields = ['name', 'date', 'location', 'details', 'guests', 'eventype']
    for field in required_fields:
        if field not in data:
            return jsonify({"msg": f"Missing field: {field}"}), 422
    try:
        event = Event(
            name=data['name'],
            date=datetime.fromisoformat(data['date']),
            location=data['location'],
            details=data['details'],
            guests=data['guests'],
            eventype=data['eventype'],
            user_id=user_id,
        )
        db.session.add(event)
        db.session.commit()
        return jsonify({"msg": "Event created", "event_id": event.id}), 201
    except Exception as e:
        db.session.rollback()
        logger.error("Error creating event for user %s: %s", user_id, e)
        return jsonify({"msg": "Error creating event"}), 500


@app.route('/events', methods=['GET'])
@jwt_required()
def get_all_events():
    user_id = int(get_jwt_identity())
    events = Event.query.filter_by(user_id=user_id).all()
    return jsonify([{
        "id": event.id,
        "name": event.name,
        "date": event.date.isoformat(),
        "location": event.location,
        "eventype": event.eventype,
        "details": event.details,
        "guests": event.guests,
        "user_id": event.user_id,
        "created_at": event.created_at.isoformat(),
    } for event in events]), 200


@app.route('/user/<int:user_id>/events', methods=['GET'])
@jwt_required()
def get_user_events(user_id):
    if int(get_jwt_identity()) != user_id:
        return jsonify({"msg": "Unauthorized"}), 403
    events = Event.query.filter_by(user_id=user_id).all()
    if not events:
        return jsonify([]), 200
    return jsonify([{
        "id": e.id,
        "name": e.name,
        "date": e.date.isoformat(),
        "location": e.location,
        "details": e.details,
        "guests": e.guests,
        "eventype": e.eventype,
        "user_id": e.user_id,
        "created_at": e.created_at.isoformat(),
    } for e in events]), 200


@app.route('/events/<int:event_id>', methods=['DELETE'])
@jwt_required()
def delete_event(event_id):
    user_id = int(get_jwt_identity())
    event = db.session.get(Event, event_id)
    if not event:
        return jsonify({"msg": "Event not found"}), 404
    if event.user_id != user_id:
        return jsonify({"msg": "Unauthorized"}), 403
    try:
        db.session.delete(event)
        db.session.commit()
        return jsonify({"msg": "Event deleted"}), 200
    except Exception as e:
        db.session.rollback()
        logger.error("Error deleting event %s: %s", event_id, e)
        return jsonify({"msg": "Error deleting event"}), 500


@app.route('/events/<int:event_id>', methods=['PUT'])
@jwt_required()
def update_event(event_id):
    user_id = int(get_jwt_identity())
    event = db.session.get(Event, event_id)
    if not event:
        return jsonify({"msg": "Event not found"}), 404
    if event.user_id != user_id:
        return jsonify({"msg": "Unauthorized"}), 403
    data = parse_json_body() or {}
    allowed_fields = ['name', 'date', 'location', 'details', 'guests', 'eventype']
    for field in allowed_fields:
        if field in data:
            setattr(event, field, data[field] if field != 'date' else datetime.fromisoformat(data[field]))
    try:
        db.session.commit()
        return jsonify({
            "msg": "Event updated",
            "event_id": event.id,
            "created_at": event.created_at.isoformat(),
        }), 200
    except Exception as e:
        db.session.rollback()
        logger.error("Error updating event %s: %s", event_id, e)
        return jsonify({"msg": "Error updating event"}), 500


############### RESERVAS #################################################
@app.route('/reservations', methods=['POST'])
@jwt_required()
def create_reservation():
    user_id = int(get_jwt_identity())
    user = db.session.get(User, user_id)
    if not user or user.profile.role != 'Cliente':
        return jsonify({"msg": "Unauthorized"}), 403
    data = parse_json_body() or {}
    required_fields = ['date_time_reservation', 'proveedor_id', 'service_id']
    for field in required_fields:
        if field not in data:
            return jsonify({"msg": f"Missing field: {field}"}), 422
    service = db.session.get(Service, data['service_id'])
    if not service:
        return jsonify({"msg": "Service not found"}), 404
    if service.profile_id != data['proveedor_id']:
        return jsonify({"msg": "Service does not belong to the given provider"}), 400
    paquete_evento_id = data.get('paquete_evento_id')
    if paquete_evento_id is not None:
        event_pack = db.session.get(EventPack, paquete_evento_id)
        if not event_pack:
            return jsonify({"msg": "Event pack not found"}), 404
        if event_pack.provider_id != service.profile_id:
            return jsonify({"msg": "Event pack does not belong to the same provider as the service"}), 400
    event_id = data.get('event_id')
    if event_id is not None:
        event = db.session.get(Event, event_id)
        if not event:
            return jsonify({"msg": "Event not found"}), 404
        if event.user_id != user_id:
            return jsonify({"msg": "Event does not belong to the requesting user"}), 403
    try:
        reservation = Reservation(
            status=ReservationStatus.PENDING,
            date_time_reservation=datetime.fromisoformat(data['date_time_reservation']),
            precio=service.price,  # price always comes from the service, never from the client
            proveedor_id=data['proveedor_id'],
            paquete_evento_id=paquete_evento_id,
            event_id=event_id,
            usuario_id=user_id,
            service_id=data['service_id'],
        )
        db.session.add(reservation)
        db.session.commit()
        return jsonify({"msg": "Reservation created", "reservation_id": reservation.id}), 201
    except Exception as e:
        db.session.rollback()
        logger.error("Error creating reservation for user %s: %s", user_id, e)
        return jsonify({"msg": "Error creating reservation"}), 500


@app.route('/reservations', methods=['GET'])
@jwt_required()
def get_all_reservations():
    user_id = int(get_jwt_identity())
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({"msg": "User not found"}), 404
    if user.profile.role == 'Proveedor':
        reservations = Reservation.query.filter_by(proveedor_id=user.profile.id).all()
    else:
        reservations = Reservation.query.filter_by(usuario_id=user_id).all()
    return jsonify([{
        "id": r.id,
        "status": r.status.name,
        "date_time_reservation": r.date_time_reservation.isoformat(),
        "precio": r.precio,
        "proveedor_id": r.proveedor_id,
        "paquete_evento_id": r.paquete_evento_id,
        "event_id": r.event_id,
        "usuario_id": r.usuario_id,
        "service_id": r.service_id,
        "created_at": r.created_at.isoformat(),
    } for r in reservations]), 200


@app.route('/user/<int:user_id>/reservations', methods=['GET'])
@jwt_required()
def get_user_reservations(user_id):
    if int(get_jwt_identity()) != user_id:
        return jsonify({"msg": "Unauthorized"}), 403
    reservations = Reservation.query.filter_by(usuario_id=user_id).all()
    if not reservations:
        return jsonify([]), 200
    reservations_list = []
    for r in reservations:
        service = db.session.get(Service, r.service_id)
        if not service:
            continue
        provider_profile = db.session.get(Profile, service.profile_id)
        if not provider_profile:
            continue
        reservations_list.append({
            "id": r.id,
            "status": get_reservation_status_in_spanish(r.status.name),
            "date_time_reservation": r.date_time_reservation.isoformat(),
            "precio": r.precio,
            "company_name": provider_profile.company_name,
            "email_contacto": provider_profile.user.email,
            "phone_number": provider_profile.phone_number,
            "address": provider_profile.address,
            "service_name": service.name,
            "service_type": service.type,
            "event_name": r.event.name if r.event else None,
            "event_type": r.event.eventype if r.event else None,
            "created_at": r.created_at.isoformat(),
        })
    return jsonify(reservations_list), 200


@app.route('/provider/<int:provider_id>/reservations', methods=['GET'])
@jwt_required()
def get_provider_reservations(provider_id):
    user_id = int(get_jwt_identity())
    user = db.session.get(User, user_id)
    if not user or user.profile.role != 'Proveedor' or user.id != provider_id:
        return jsonify({"msg": "Unauthorized"}), 403
    reservations = Reservation.query.filter_by(proveedor_id=user.profile.id).all()
    reservations_list = []
    for r in reservations:
        service = db.session.get(Service, r.service_id)
        client = db.session.get(User, r.usuario_id)
        if not service or not client:
            continue
        reservations_list.append({
            "id": r.id,
            "status": get_reservation_status_in_spanish(r.status.name),
            "date_time_reservation": r.date_time_reservation.isoformat(),
            "precio": r.precio,
            "service_name": service.name,
            "client_name": f"{client.first_name} {client.last_name}",
            "client_email": client.email,
            "client_phone": client.profile.phone_number if client.profile else None,
            "event_name": r.event.name if r.event else None,
            "event_type": r.event.eventype if r.event else None,
            "event_guests": r.event.guests if r.event else None,
            "created_at": r.created_at.isoformat(),
        })
    return jsonify(reservations_list), 200


@app.route('/reservations/<int:reservation_id>', methods=['GET'])
@jwt_required()
def get_reservation(reservation_id):
    user_id = int(get_jwt_identity())
    user = db.session.get(User, user_id)
    reservation = db.session.get(Reservation, reservation_id)
    if not reservation:
        return jsonify({"msg": "Reservation not found"}), 404
    is_client = reservation.usuario_id == user_id
    is_provider = user and user.profile and reservation.proveedor_id == user.profile.id
    if not (is_client or is_provider):
        return jsonify({"msg": "Unauthorized"}), 403
    return jsonify({
        "id": reservation.id,
        "status": reservation.status.name,
        "date_time_reservation": reservation.date_time_reservation.isoformat(),
        "precio": reservation.precio,
        "proveedor_id": reservation.proveedor_id,
        "paquete_evento_id": reservation.paquete_evento_id,
        "usuario_id": reservation.usuario_id,
        "service_id": reservation.service_id,
        "created_at": reservation.created_at.isoformat(),
    }), 200


@app.route('/reservations/<int:reservation_id>', methods=['PUT'])
@jwt_required()
def update_reservation(reservation_id):
    user_id = int(get_jwt_identity())
    data = parse_json_body() or {}
    reservation = db.session.get(Reservation, reservation_id)
    if not reservation:
        return jsonify({"msg": "Reservation not found"}), 404
    if reservation.usuario_id != user_id:
        return jsonify({"msg": "Unauthorized"}), 403
    try:
        new_status = data.get('status')
        if new_status:
            if new_status != ReservationStatus.CANCELLED.name:
                return jsonify({"msg": "Clients can only cancel reservations"}), 403
            reservation.status = ReservationStatus.CANCELLED
        if 'date_time_reservation' in data:
            reservation.date_time_reservation = datetime.fromisoformat(data['date_time_reservation'])
        if 'paquete_evento_id' in data:
            new_pack_id = data['paquete_evento_id']
            if new_pack_id is not None:
                service = db.session.get(Service, reservation.service_id)
                event_pack = db.session.get(EventPack, new_pack_id)
                if not event_pack:
                    return jsonify({"msg": "Event pack not found"}), 404
                if service and event_pack.provider_id != service.profile_id:
                    return jsonify({"msg": "Event pack does not belong to the same provider as the service"}), 400
            reservation.paquete_evento_id = new_pack_id
        db.session.commit()
        return jsonify({"msg": "Reservation updated"}), 200
    except Exception as e:
        db.session.rollback()
        logger.error("Error updating reservation %s: %s", reservation_id, e)
        return jsonify({"msg": "Error updating reservation"}), 500


@app.route('/reservations/<int:reservation_id>/status', methods=['PATCH'])
@jwt_required()
def update_reservation_status(reservation_id):
    user_id = int(get_jwt_identity())
    user = db.session.get(User, user_id)
    if user.profile.role != 'Proveedor':
        return jsonify({"msg": "Unauthorized"}), 403
    reservation = db.session.get(Reservation, reservation_id)
    if not reservation:
        return jsonify({"msg": "Reservation not found"}), 404
    if reservation.proveedor_id != user.profile.id:
        return jsonify({"msg": "Unauthorized"}), 403
    data = parse_json_body() or {}
    try:
        new_status = data.get('status')
        if new_status not in ReservationStatus._member_names_:
            return jsonify({"msg": "Invalid status"}), 400
        reservation.status = ReservationStatus[new_status]
        db.session.commit()
        return jsonify({"msg": "Reservation status updated"}), 200
    except Exception as e:
        db.session.rollback()
        logger.error("Error updating reservation status %s: %s", reservation_id, e)
        return jsonify({"msg": "Error updating reservation status"}), 500


@app.route('/reservations/<int:reservation_id>', methods=['DELETE'])
@jwt_required()
def delete_reservation(reservation_id):
    user_id = int(get_jwt_identity())
    reservation = db.session.get(Reservation, reservation_id)
    if not reservation:
        return jsonify({"msg": "Reservation not found"}), 404
    if reservation.usuario_id != user_id:
        return jsonify({"msg": "Unauthorized"}), 403
    try:
        db.session.delete(reservation)
        db.session.commit()
        return jsonify({"msg": "Reservation deleted"}), 200
    except Exception as e:
        db.session.rollback()
        logger.error("Error deleting reservation %s: %s", reservation_id, e)
        return jsonify({"msg": "Error deleting reservation"}), 500


if __name__ == '__main__':
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    app.run(host='localhost', port=5500, debug=debug)
