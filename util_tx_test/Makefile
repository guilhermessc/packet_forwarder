### Application-specific constants

APP_NAME := util_tx_test

### Constant symbols

CC := $(CROSS_COMPILE)gcc
AR := $(CROSS_COMPILE)ar

CFLAGS := -O2 -Wall -Wextra -std=c99 -Iinc -I.

OBJDIR = obj
INCLUDES = $(wildcard inc/*.h)

### General build targets

all: $(APP_NAME)

clean:
	rm -f $(OBJDIR)/*.o
	rm -f $(APP_NAME)

### Sub-modules compilation

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(OBJDIR)/%.o: src/%.c $(INCLUDES) | $(OBJDIR)
	$(CC) -c $(CFLAGS) $< -o $@

# vitor begin

#### Main program assembly
#
#$(APP_NAME): $(OBJDIR)/$(APP_NAME).o  $(OBJDIR)/base64.o
#	$(CC) $< $(OBJDIR)/base64.o -o $@
#
#### EOF

### Main program assembly

$(APP_NAME): $(OBJDIR)/$(APP_NAME).o $(OBJDIR)/aes.o $(OBJDIR)/cmac.o $(OBJDIR)/base64.o $(OBJDIR)/parson.o
	$(CC) $< $(OBJDIR)/aes.o $(OBJDIR)/cmac.o $(OBJDIR)/base64.o $(OBJDIR)/parson.o -o $@ 

### EOF

# vitor end
