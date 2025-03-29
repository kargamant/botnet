#pragma once
#include <stdbool.h>
#define DEBUG

static const char* adapter_id = "eth0";

void print_availiable();
bool is_adapter_availiable(const char* adapter);