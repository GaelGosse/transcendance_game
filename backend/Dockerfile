FROM python:3.12-slim

#Initialisation du repertoire de travail dans le conteneur
WORKDIR /app

COPY requirements.txt ./

RUN apt-get update && \
	apt-get install -y libpq-dev gcc

# apt-get upgrade -y

#installation de pip et des dependances
RUN pip install --upgrade pip && \
	pip install -r requirements.txt

RUN mkdir -p /code

COPY ./mysite /code/

# RUN mkdir /tools

COPY ./tools/server.sh ./
# COPY . .

# RUN chmod +x ./server.sh

# EXPOSE 8000

# CMD ["/bin/ls", "-la"]

CMD ["sh", "server.sh"]