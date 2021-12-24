FROM python:3.9-slim
RUN apt-get update
RUN apt-get install net-tools
RUN apt-get install -y libcap-dev
RUN apt-get install -y tcpdump
RUN useradd --create-home --shell /bin/bash igris
WORKDIR /home/igris
RUN mkdir app
RUN mkdir loot
WORKDIR /home/igris/app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["python","/home/igris/app/main.py"]
WORKDIR /home/igris
