#!/bin/bash

echo "🚀 MHZALY Domain Recon Setup"

# Create venv
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

echo "✅ Setup complete!"
echo "Run: streamlit run domain_recon_app.py"
Make it executable:
chmod +x setup.sh
