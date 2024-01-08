
BUILD_GOVERSION = $(subst go,,$(shell $(GO) env GOVERSION))

go_major_minor = $(subst ., ,$(BUILD_GOVERSION))
GO_MAJOR_VERSION = $(word 1, $(go_major_minor))
GO_MINOR_VERSION = $(word 2, $(go_major_minor))

GO_VERSION_VALIDATION_ERR_MSG = Golang version ($(BUILD_GOVERSION)) is not supported, please use at least $(BUILD_REQUIRE_GO_MAJOR).$(BUILD_REQUIRE_GO_MINOR)


.PHONY: goversion
goversion: $(if $(findstring devel,$(shell $(GO) env GOVERSION)),goversion_devel,goversion_check)


.PHONY: goversion_devel
goversion_devel:
	$(warning WARNING: You are using a development version of Golang ($(BUILD_GOVERSION)) which is not supported. For production environments, use a stable version (at least $(BUILD_REQUIRE_GO_MAJOR).$(BUILD_REQUIRE_GO_MINOR)))
	$(info )


.PHONY: goversion_check
goversion_check:
	@if [ $(GO_MAJOR_VERSION) -gt $(BUILD_REQUIRE_GO_MAJOR) ]; then \
		exit 0; \
	elif [ $(GO_MAJOR_VERSION) -lt $(BUILD_REQUIRE_GO_MAJOR) ]; then \
		echo '$(GO_VERSION_VALIDATION_ERR_MSG)';\
		exit 1; \
	elif [ $(GO_MINOR_VERSION) -lt $(BUILD_REQUIRE_GO_MINOR) ] ; then \
		echo '$(GO_VERSION_VALIDATION_ERR_MSG)';\
		exit 1; \
	fi
