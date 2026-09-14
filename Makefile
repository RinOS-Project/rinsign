# SPDX-License-Identifier: Apache-2.0
CC ?= gcc
CFLAGS ?= -std=c11 -Wall -Wextra -O2
CPPFLAGS ?=
LDFLAGS ?=
LDLIBS ?= -lcrypto

# GNU make supplies a built-in `CC=cc`.  On Windows that command is often not
# installed even when the selected GCC toolchain is available, so use gcc for
# the built-in default while still honoring an explicit CC override.
ifeq ($(origin CC),default)
CC = gcc
endif

TARGET := rinsign
OBJDIR := obj

ifeq ($(OS),Windows_NT)
MKDIR_P = if not exist "$(1)" mkdir "$(1)"
RM_RF = if exist "$(1)" rmdir /s /q "$(1)"
RM_F = if exist "$(1)" del /q "$(1)"
else
MKDIR_P = mkdir -p "$(1)"
RM_RF = rm -rf "$(1)"
RM_F = rm -f "$(1)"
endif

all: $(TARGET)

$(OBJDIR):
	$(call MKDIR_P,$(OBJDIR))

$(OBJDIR)/rinsign.o: src/rinsign.c | $(OBJDIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJDIR)/rinsign.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

clean:
	$(call RM_RF,$(OBJDIR))
	$(call RM_F,$(TARGET))
	$(call RM_F,$(TARGET).exe)

.PHONY: all clean
