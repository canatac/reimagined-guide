From rust:1.70
ARG USER=default_user
RUN adduser --disabled-password --gecos "" ${USER}

# Utilisation de la variable USER
RUN echo "Current user is $USER"

VOLUME /data

# Set a different target directory
# Create the target directory

RUN mkdir -p /app && chown -R ${USER} /app

WORKDIR /app
USER ${USER}

COPY . .

RUN rustup override set nightly
RUN cargo version
RUN cargo install --path .

ENV ROCKET_ADDRESS=0.0.0.0
EXPOSE 2525
CMD ["cargo", "run"]
