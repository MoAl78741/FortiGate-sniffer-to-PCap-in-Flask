from . import db
from flask_login import UserMixin
from sqlalchemy.sql import func


class Conversion(UserMixin, db.Model):
    __tablename__ = 'conversion'
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)
    data = db.Column(db.LargeBinary)
    date_created = db.Column(db.DateTime(timezone=True), default=func.now())
    data_converted = db.Column(db.LargeBinary)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __repr__(self):
        return '<Task %r>' % self.id


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    first_name = db.Column(db.String(150))
    conversions = db.relationship('Conversion')
