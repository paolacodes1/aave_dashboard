#!/usr/bin/env python3
"""
Create icon files from the base64 logo for PyInstaller builds
"""
import base64
from PIL import Image
import io
import os

def create_icon_from_base64():
    """Create .ico file from the base64 logo file"""
    try:
        # Read the base64 logo
        with open('logo_raw_b64.txt', 'r') as f:
            logo_b64 = f.read().strip()
        
        # Decode base64 to image
        logo_data = base64.b64decode(logo_b64)
        image = Image.open(io.BytesIO(logo_data))
        
        # Ensure RGBA mode for proper icon creation
        if image.mode != 'RGBA':
            image = image.convert('RGBA')
        
        # Create icon with multiple sizes (standard Windows icon sizes)
        icon_sizes = [(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
        
        # Save as ICO file
        image.save('logo.ico', format='ICO', sizes=icon_sizes)
        print("✓ Created logo.ico")
        
        return True
        
    except Exception as e:
        print(f"✗ Error creating icon: {e}")
        return False

if __name__ == "__main__":
    if os.path.exists('logo_raw_b64.txt'):
        create_icon_from_base64()
    else:
        print("✗ logo_raw_b64.txt not found")