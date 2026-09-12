# SPDX-License-Identifier: MIT
CC ?= gcc
CFLAGS ?= -std=c11 -Wall -Wextra -O2
CPPFLAGS ?=
LDFLAGS ?=
LDLIBS ?= -lcrypto

TARGET := rinsign
OBJDIR := obj

all: $(TARGET)

$(OBJDIR):
	@if not exist $(OBJDIR) mkdir $(OBJDIR)

$(OBJDIR)/rinsign.o: src/rinsign.c | $(OBJDIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJDIR)/rinsign.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

clean:
	@if exist $(OBJDIR) rmdir /s /q $(OBJDIR)
	@if exist $(TARGET) del /q $(TARGET)
	@if exist $(TARGET).exe del /q $(TARGET).exe

.PHONY: all clean
