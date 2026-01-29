## Running the Project Locally

## Step 1: Clone the repository
```bash
git clone <repository-url>
cd openapi-security-analyzer
Step 2: Create a virtual environment
python -m venv venv
Step 3: Activate the virtual environment
Windows
venv\Scripts\activate
Linux / macOS
source venv/bin/activate
Step 4: Install dependencies
pip install -r requirements.txt
Step 5: Run the FastAPI application
uvicorn app.main:app --reload
Step 6: Access the application
Health check
http://127.0.0.1:8000/

Swagger UI
http://127.0.0.1:8000/docs

ReDoc
http://127.0.0.1:8000/redoc
