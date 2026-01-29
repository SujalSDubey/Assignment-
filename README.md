How to Run the Project

1. Clone / open the project folder

2. Open Command Prompt
   
3. Create a virtual environment

        -python -m venv venv

4. Activate the virtual environment

        -venv\Scripts\activate

5. Install dependencies

        -pip install -r requirements.txt


6. Run the application

        -uvicorn app.main:app --reload

7. Open the application in browser

        -http://127.0.0.1:8000/docs

Use the Swagger UI to:

  -Paste an OpenAPI specification

  -Upload a YAML/JSON file

  -Provide a URL to fetch an OpenAPI spec
