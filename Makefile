build_spec = echo "bot_net_build on $(OS)"

ifeq ($(OS), Windows_NT)
	build_spec := gcc -g -I npcap/Include -o build/bot_node bot_node.c utils.c -L npcap/Lib/x64 -lwpcap
else
	build_spec := gcc -g -I npcap/Include -o build/bot_node bot_node.c utils.c -lpcap
endif	

all:
	$(build_spec)
