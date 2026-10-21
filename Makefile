.PHONY: build run clean

AGENT_DIR := agent
BIN       := exec-monitor

build:
	cd $(AGENT_DIR) && go generate ./...
	cd $(AGENT_DIR) && go build -o ../$(BIN) .

run: build
	sudo ./$(BIN)

clean:
	rm -f $(BIN) $(AGENT_DIR)/*_bpfel.o $(AGENT_DIR)/*_bpfel.go
