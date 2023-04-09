FROM python:3-slim

########################################
# add a user so we're not running as root
########################################
RUN useradd useruser

RUN apt-get update
RUN apt-get install -y git
RUN apt-get clean

RUN mkdir -p /home/useruser/certbrother
RUN chown useruser /home/useruser -R

USER useruser

WORKDIR /home/useruser/certbrother

COPY pyproject.toml .
COPY poetry.lock .
COPY certbrother.py .
COPY README.md .
COPY .env.example .env

RUN python -m pip install .

ENTRYPOINT ["/home/useruser/.local/bin/certbrother"]
CMD [""]