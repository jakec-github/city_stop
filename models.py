from sqlalchemy import create_engine, Column, Integer, String, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker

from passlib.apps import custom_app_context as pwd_context

Base = declarative_base()


class User(Base):
    __tablename__ = "user"

    id = Column(Integer, primary_key=True)
    name = Column(String)
    email = Column(String)
    picture = Column(String)


class City(Base):
    __tablename__ = "city"

    id = Column(Integer, primary_key=True)
    name = Column(String)
    picture1 = Column(String)
    picture2 = Column(String)
    user_id = Column(Integer, ForeignKey('user.id'))

    user = relationship(User)

    @property
    def serialize(self):
        return {
            "name": self.name
        }


class Stop(Base):
    __tablename__ = "stop"

    id = Column(Integer, primary_key=True)
    name = Column(String)
    description = Column(String)
    recommendations = Column(Integer)
    user_id = Column(Integer, ForeignKey('user.id'))
    city_id = Column(Integer, ForeignKey('city.id'))

    user = relationship(User)
    city = relationship(City)

    @property
    def serialize(self):
        return {
            "name": self.name,
            "description": self.description,
            "recommendations": self.recommendations
        }


class Recommendation(Base):
    __tablename__ = "recommendation"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user.id'))
    stop_id = Column(Integer, ForeignKey('stop.id'))

    user = relationship(User)
    stop = relationship(Stop)


engine = create_engine("sqlite:///city_stop.db")

Base.metadata.create_all(engine)
