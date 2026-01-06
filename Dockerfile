FROM jetpackio/devbox:latest

# Installing your devbox project
WORKDIR /code
USER root:root
RUN mkdir -p /code && chown ${DEVBOX_USER}:${DEVBOX_USER} /code
USER ${DEVBOX_USER}:${DEVBOX_USER}
COPY --chown=${DEVBOX_USER}:${DEVBOX_USER} devbox.json devbox.json
COPY --chown=${DEVBOX_USER}:${DEVBOX_USER} devbox.lock devbox.lock
COPY --chown=${DEVBOX_USER}:${DEVBOX_USER} noir/requirements.txt /code/noir/requirements.txt

RUN devbox run -- echo "Installed Packages." && nix-store --gc && nix-store --optimise

COPY --chown=${DEVBOX_USER}:${DEVBOX_USER} docknetwork /code/docknetwork
COPY --chown=${DEVBOX_USER}:${DEVBOX_USER} noir /code/noir

CMD ["devbox", "shell"]
