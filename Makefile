IMAGE_NAME?=zkp-pocs
IMAGE_TAG?=latest
CONTAINER=$(IMAGE_NAME):$(IMAGE_TAG)

DOCKER_RUN_COMMAND = docker run --rm -it \
    -v $(PWD)/.cargo-cache/target:/app/docknetwork/target \
    -v $(PWD)/.cargo-cache/registry:/usr/local/cargo/registry \
	-v $(PWD)/.cargo-cache/git/db:/home/appuser/.cargo/git/db \
	-v $(PWD)/.cargo-cache/git/checkouts:/home/appuser/.cargo/git/checkouts \
    -v $(PWD)/.sccache:/home/appuser/.cache/sccache \
    $(CONTAINER)

.PHONY: build
build:
	docker build -f docker/prover-and-verifier/Dockerfile -t $(CONTAINER) .


.PHONY: clean-image
clean-image:
	docker rmi $(CONTAINER) || true

define run_in_container
$(DOCKER_RUN_COMMAND) bash -c 'set -Eeuo pipefail; cd /app; '"$(1)"
endef

.PHONY: dock-all
dock-all:
	$(call run_in_container, cd docknetwork && make all)

.PHONY: noir-all
noir-all:
	$(call run_in_container, cd noir && make all)
.PHONY: noir-clean
noir-clean:
	$(call run_in_container, cd noir && make clean)

.PHONY: all
all:
	$(call run_in_container, (cd docknetwork && make all) && (cd noir && make all))

.PHONY: clean
clean:
	$(call run_in_container, (cd noir && make clean) && (cd docknetwork && make clean))

.PHONY: debug-shell
debug-shell:
	$(DOCKER_RUN_COMMAND) bash