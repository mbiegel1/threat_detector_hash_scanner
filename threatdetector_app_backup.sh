cd src
sudo apt-get -y install python3-pip
sudo apt install python3-venv
python3 -m venv app_env
source app_env/bin/activate
pip install Flask
python3 app.py