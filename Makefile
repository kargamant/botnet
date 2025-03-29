build_spec = echo "bot_net_build on $(OS)"

ifeq ($(OS), Windows_NT)
	build_spec := gcc -g -w -I npcap/Include -o build/bot_node bot_node.c utils.c -L npcap/Lib/x64 -lwpcap ; gcc -g -w -I npcap/Include -o build/bot_master bot_master.c utils.c -L npcap/Lib/x64 -lwpcap
else
	build_spec := gcc -g -w -I npcap/Include -o build/bot_node bot_node.c utils.c -lpcap ; gcc -g -w -I npcap/Include -o build/bot_master bot_master.c utils.c -lpcap
endif	

all:
	$(build_spec)
