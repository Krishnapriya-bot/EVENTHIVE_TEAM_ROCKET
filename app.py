# IMPORTS
from flask import Flask, jsonify, request, render_template
# ROUTES

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

if __name__ == '__main__':
    print("Starting Flask server...")
    app.run(debug=True)