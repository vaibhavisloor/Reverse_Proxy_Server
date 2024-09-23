from flask import Flask

app=Flask(__name__)

@app.route('/')
def hello_world():
    return "Hello from the dummy Flask server 2 !"

if __name__ == '__main__':
    app.run(host='localhost', port=8001)