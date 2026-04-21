FROM python:3.13-slim

RUN pip install --no-cache-dir uv

########################################
# add a user so we're not running as root
########################################
RUN useradd useruser

RUN apt-get update
RUN apt-get install -y git
RUN apt-get clean

RUN mkdir -p /home/useruser/certbrother
WORKDIR /home/useruser/certbrother

COPY pyproject.toml .
COPY uv.lock .
COPY certbrother.py .
COPY README.md .
COPY .env.example .env
RUN chown useruser:useruser /home/useruser -R

USER useruser
ENV UV_LINK_MODE=copy
RUN uv --no-config sync --no-dev

ENTRYPOINT ["/home/useruser/certbrother/.venv/bin/certbrother"]
CMD [""]
