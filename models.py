from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy
from enum import Enum  

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    password = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(200), nullable=False, unique=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    
    profile = db.relationship('Profile', backref='user', uselist=False)
    tickets = db.relationship('SupportTicket', backref='user')
    reviews = db.relationship('Review', backref='user')
    events = db.relationship('Event', back_populates='user')  # Cambiado a back_populates
    reservations = db.relationship('Reservation', back_populates='user')


class Profile(db.Model):
    __tablename__ = 'profile'
    id = db.Column(db.Integer, primary_key=True)
    phone_number = db.Column(db.String(50))
    address = db.Column(db.String(200))
    description = db.Column(db.Text)
    company_name = db.Column(db.String(200), nullable=True)
    url_portfolio = db.Column(db.String(200))
    role = db.Column(db.String(50))
    usuario_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    services = db.relationship('Service', back_populates='profile')
    messages_sent = db.relationship(
        'Message',
        foreign_keys='[Message.client_id]',
        backref=db.backref('client', lazy='joined')
    )
    messages_received = db.relationship(
        'Message',
        foreign_keys='[Message.provider_id]',
        backref=db.backref('provider', lazy='joined')
    )
    event_packs = db.relationship('EventPack', back_populates='profile')
    reservations_as_proveedor = db.relationship('Reservation', foreign_keys='[Reservation.proveedor_id]', back_populates='proveedor')



class Message(db.Model):
    __tablename__ = 'message'
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    client_id = db.Column(db.Integer, db.ForeignKey(
        'profile.id'), nullable=False)
    provider_id = db.Column(
        db.Integer, db.ForeignKey('profile.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)


class Service(db.Model):
    __tablename__ = 'service'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    type = db.Column(db.String(50), nullable=False)
    price = db.Column(db.Float)
    pricing_type = db.Column(db.String(50), nullable=True, default='por evento')
    description = db.Column(db.Text)
    location = db.Column(db.String(200))
    profile_id = db.Column(db.Integer, db.ForeignKey('profile.id'))

    profile = db.relationship('Profile', back_populates='services')
    reservations = db.relationship('Reservation', back_populates='service')
    reviews = db.relationship('Review', backref='service')
    media = db.relationship('Media', backref='service')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)



class SupportTicket(db.Model):
    __tablename__ = 'support_ticket'
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))


class EventPack(db.Model):
    __tablename__ = 'event_pack'
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float)
    provider_id = db.Column(db.Integer, db.ForeignKey('profile.id'))
    
    profile = db.relationship('Profile', back_populates='event_packs')
    reservations_as_event_pack = db.relationship('Reservation', foreign_keys='[Reservation.paquete_evento_id]', back_populates='event_pack')



class Media(db.Model):
    __tablename__ = 'media'
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(50), nullable=False)
    url = db.Column(db.String(200), nullable=False)
    service_id = db.Column(db.Integer, db.ForeignKey('service.id'))


class Promotion(db.Model):
    __tablename__ = 'promotion'
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.Text, nullable=False)
    start_date = db.Column(db.DateTime)
    end_date = db.Column(db.DateTime)
    price = db.Column(db.Float)
    provider_id = db.Column(db.Integer, db.ForeignKey('profile.id'))

class ReservationStatus(Enum):
    PENDING = "PENDING"
    CONFIRMED = "CONFIRMED"
    CANCELLED = "CANCELLED"
    COMPLETED = "COMPLETED"

class Reservation(db.Model):
    __tablename__ = 'reservation'
    id = db.Column(db.Integer, primary_key=True)
    status = db.Column(db.Enum(ReservationStatus), nullable=False, default=ReservationStatus.PENDING)
    date_time_reservation = db.Column(db.DateTime, nullable=False)
    precio = db.Column(db.Float, nullable=False)
    proveedor_id = db.Column(db.Integer, db.ForeignKey('profile.id'), nullable=False)
    paquete_evento_id = db.Column(db.Integer, db.ForeignKey('event_pack.id'), nullable=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    service_id = db.Column(db.Integer, db.ForeignKey('service.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    service = db.relationship('Service', back_populates='reservations')
    user = db.relationship('User', back_populates='reservations')
    proveedor = db.relationship('Profile', foreign_keys=[proveedor_id], back_populates='reservations_as_proveedor')
    event_pack = db.relationship('EventPack', foreign_keys=[paquete_evento_id], back_populates='reservations_as_event_pack')



class Review(db.Model):
    __tablename__ = 'review'
    id = db.Column(db.Integer, primary_key=True)
    comment = db.Column(db.Text, nullable=False)
    date_time = db.Column(db.DateTime)
    provider_id = db.Column(db.Integer, db.ForeignKey('profile.id'))
    score = db.Column(db.Integer)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    service_id = db.Column(db.Integer, db.ForeignKey('service.id'))

class Event(db.Model):
    __tablename__ = 'events'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    location = db.Column(db.String(255), nullable=False)
    details = db.Column(db.Text, nullable=True)
    guests = db.Column(db.Integer, nullable=False)
    eventype = db.Column(db.String(255), nullable=False, server_default='Default')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', back_populates='events')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    def __repr__(self):
        return f'<Event {self.name}>'


    # test
