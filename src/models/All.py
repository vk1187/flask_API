# coding: utf-8
from sqlalchemy import CHAR, Column, Date, DateTime, Float, ForeignKey, LargeBinary, String, TIMESTAMP, Table, Text, text
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.mysql import BIGINT, INTEGER, LONGBLOB, LONGTEXT, MEDIUMTEXT, TINYINT, VARCHAR
from sqlalchemy.ext.declarative import declarative_base

from run import db
# Base = declarative_base()
# metadata = Base.metadata

Base = db.Model


class Language(Base):
    __tablename__ = 'language'

    id = Column(INTEGER(11), primary_key=True)
    name = Column(String(45))
    code = Column(String(45))
    inactive = Column(TINYINT(1), server_default=text("'0'"))




class User(Base):
    __tablename__ = 'user'

    id = Column(INTEGER(11), primary_key=True)
    username = Column(String(255))
    title = Column(String(127))
    firstName = Column(String(255))
    lastName = Column(String(255))
    email = Column(String(255), unique=True)
    secondary_email = Column(String(255))
    defaultEmail = Column(TINYINT(1), comment='1= email, 2=secondary')
    password = Column(String(255))
    image = Column(LargeBinary)
    account_id = Column(ForeignKey('account.id', ondelete='CASCADE', onupdate='CASCADE'), index=True)
    last_login_time = Column(DateTime)
    created_time = Column(DateTime)
    inactive = Column(TINYINT(1), server_default=text("'0'"))
    inactive_datetime = Column(DateTime)
    language_id = Column(ForeignKey('language.id', ondelete='CASCADE', onupdate='CASCADE'), index=True)
    signature = Column(Text)
    coach_id = Column(ForeignKey('user.id'), index=True)
    secondary_coach_id = Column(ForeignKey('user.id'), index=True)
    timezone_offset = Column(Float)
    timezone = Column(INTEGER(11))
    brand_id = Column(INTEGER(11))
    terms_accepted_datetime = Column(TIMESTAMP)
    passwordchanged_time = Column(TIMESTAMP)
    otp = Column(String(255))
    thumbnail = Column(String(255))
    jwt_access_token = Column(String(255))
    jwt_refresh_token = Column(String(255))


class Account(Base):
    __tablename__ = 'account'

    id = Column(INTEGER(11), primary_key=True)
    name = Column(String(45), nullable=False, unique=True)
    created_time = Column(DateTime)
    address = Column(String(45))
    inactive = Column(TINYINT(1), server_default=text("'0'"))
    canEmbedVideos = Column(TINYINT(1), server_default=text("'0'"))
    brandName = Column(INTEGER(11), index=True)
    coach_id = Column(ForeignKey('user.id'), index=True)
    uniqid = Column(String(255))
    video_approval = Column(TINYINT(1), server_default=text("'3'"), comment='1=Required, 2=Preferred, 3=Not Required')
    approval = Column(TINYINT(1), server_default=text("'3'"), comment='1=Required, 2=Preferred, 3=Not Required')
    featured_story = Column(INTEGER(11))
    enable_screencast = Column(String(25), nullable=False, server_default=text("'user'"))

    # coach = relationship('User', primaryjoin='Account.coach_id == User.id')

class user_verification(Base):
    __tablename__ = 'user_verification'
    id = Column(INTEGER(11), primary_key=True)
    user_id = Column(INTEGER(11))
    email = Column(String(255))
    otp = Column(INTEGER(11))
    mfa = Column(INTEGER(11), default=0)
    verified = Column(INTEGER(11), default=0)
    created_time = Column(DateTime)

