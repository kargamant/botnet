all:
	mkdir -p build
	gcc -g -I npcap/Include -o build/bot_node bot_node.c -lpcap
linux:
	gcc -g -I npcap/Include -o bot_node bot_node.c -lpcap