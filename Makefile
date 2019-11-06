TARGET=sepsplit

all: $(TARGET)

$(TARGET): sepsplit.c
	gcc $< -o $@ -Iinclude

clean:
	rm -f $(TARGET)
