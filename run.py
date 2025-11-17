from app import create_app
from dotenv import load_dotenv  # <-- Adicione esta linha

load_dotenv()  # <-- Adicione esta linha

app = create_app()

if __name__ == "__main__":
    app.run(debug=True)