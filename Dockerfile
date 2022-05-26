FROM python:3.9-slim-bullseye
# Necessary Packages
RUN apt-get update
RUN apt-get install net-tools
RUN apt-get install -y libcap-dev
RUN apt-get install -y tcpdump
RUN apt-get install -y proxychains
RUN apt-get install -y vim 
RUN apt-get install -y wget 
RUN apt-get install -y unzip

# Create user igris and installation of lsd
RUN useradd --create-home --shell /bin/bash igris
RUN wget https://github.com/Peltoche/lsd/releases/download/0.21.0/lsd_0.21.0_amd64.deb
RUN dpkg -i lsd_0.21.0_amd64.deb
RUN rm lsd_0.21.0_amd64.deb
RUN echo "alias ls='lsd --group-dirs=first'" >> /home/igris/.bashrc
RUN mkdir -p /usr/share/fonts/truetype/
COPY ./mononoki.ttf ./
RUN install -m644 mononoki.ttf /usr/share/fonts/truetype/
RUN rm ./mononoki.ttf

# Components required for the application
WORKDIR /home/igris
RUN mkdir app
RUN mkdir loot
WORKDIR /home/igris/app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY proxychains.conf /etc/proxychains.conf 
COPY . .

# Start of the application
CMD ["python","/home/igris/app/main.py"]
WORKDIR /home/igris
