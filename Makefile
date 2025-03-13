IMAGE ?= ghcr.io/cozystack/cozystack/cozy-proxy
TAG ?= latest
PUSH ?= true
LOAD ?= false

image: image-cozy-proxy

image-cozy-proxy:
	docker buildx build . \
		--provenance false \
		--tag $(IMAGE):$(TAG) \
		--cache-from type=registry,ref=$(IMAGE):latest \
		--cache-to type=inline \
		--push=$(PUSH) \
		--label "org.opencontainers.image.source=https://github.com/cozystack/cozy-proxy" \
		--load=$(LOAD)
