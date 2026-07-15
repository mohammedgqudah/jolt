.PHONY: hooks
hooks:
	chmod +x $(realpath ./hooks/pre-commit.sh)
	ln -sf $(realpath ./hooks/pre-commit.sh) $(CURDIR)/.git/hooks/pre-commit

.PHONY: dev
dev:
	watchexec -e zig -e h -e c -- "clear && zig build"

.PHONY: install
install:
	zig build -p ~/.local -Doptimize=ReleaseSmall

.PHONY: clean
clean:
	rm -rf .zig-cache zig-out .cache ./src/prog.bpf.o
