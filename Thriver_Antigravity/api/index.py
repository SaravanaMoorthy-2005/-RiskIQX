import sys
import os

# Resolve the backend directory so we can import the FastAPI app correctly
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
backend_dir = os.path.join(root_dir, "backend")

if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

# Import the FastAPI app instance from backend
from app.main import app
