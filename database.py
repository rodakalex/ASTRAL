import logging

from sqlalchemy import create_engine, Column, String, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

DATABASE_URL = "sqlite:///packets.db"
Base = declarative_base()

class Packet(Base):
    __tablename__ = 'packets'
    
    id = Column(Integer, primary_key=True)
    source_ip = Column(String)
    destination_ip = Column(String)
    protocol = Column(String)
    source_port = Column(Integer)
    destination_port = Column(Integer)
    payload = Column(String)

engine = create_engine(DATABASE_URL)
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)
session = Session()

def save_packet(source_ip, destination_ip, protocol, source_port, destination_port, payload):
    packet = Packet(
        source_ip=source_ip,
        destination_ip=destination_ip,
        protocol=str(protocol),
        source_port=source_port,
        destination_port=destination_port,
        payload=payload.decode('utf-8', errors='ignore') if payload else None
    )
    session.add(packet)
    session.commit()
    logging.info("Packet saved to database.")
