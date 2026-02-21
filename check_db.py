#!/usr/bin/env python3
# check_db.py

import sys
import os

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

from backend import create_app, db
from backend.models import User, Device, Message

app = create_app()

with app.app_context():
    print("=" * 60)
    print("DATABASE CONNECTION CHECK")
    print("=" * 60)
    
    # Check connection
    try:
        db.engine.execute("SELECT 1")
        print("✓ Database connection successful")
        print(f"✓ Connected to: {db.engine.url}")
    except Exception as e:
        print(f"✗ Database connection failed: {e}")
        sys.exit(1)
    
    print("\n" + "=" * 60)
    print("USERS TABLE")
    print("=" * 60)
    
    users = User.query.all()
    print(f"Total users: {len(users)}")
    
    if users:
        for user in users:
            print(f"\nUser ID: {user.id}")
            print(f"  Email Hash: {user.email_hash}")
            print(f"  Password Hash: {user.password_hash[:20]}...")
            print(f"  Created At: {user.created_at}")
            print(f"  Has Public Keys: {'Yes' if user.primary_pubkeys else 'No'}")
    else:
        print("⚠ No users found in database")
    
    print("\n" + "=" * 60)
    print("DEVICES TABLE")
    print("=" * 60)
    
    devices = Device.query.all()
    print(f"Total devices: {len(devices)}")
    
    for device in devices:
        print(f"\nDevice ID: {device.id}")
        print(f"  User ID: {device.user_id}")
        print(f"  Device Name: {device.device_name}")
    
    print("\n" + "=" * 60)
    print("MESSAGES TABLE")
    print("=" * 60)
    
    messages = Message.query.all()
    print(f"Total messages: {len(messages)}")
    
    for msg in messages:
        print(f"\nMessage ID: {msg.id}")
        print(f"  From: {msg.sender_email_hash}")
        print(f"  To: {msg.receiver_email_hash}")
        print(f"  Sent At: {msg.sent_at}")
