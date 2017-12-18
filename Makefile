CC:=gcc #Compiler
EDL:=gcc #Linker
ARFLAGS:=rcs
CCFLAGS:=-Wall -g #Compiler options
EDLFLAGS:=-Wall -g #Linker options
EXE:=rt_netlink
DEFINES:=DEBUG #Preprocessor definitions
ECHO:=@echo

OBJ:=rt_netlink.o

.PHONY: all clean

all: $(EXE)

$(EXE): $(OBJ)
	@echo building $<
	$(EDL) -o $(EXE) $(EDLFLAGS) $(OBJ)
	@echo done

./%.o : %.c *.h
	@echo compiling $< ...
	$(CC) $(CCFLAGS) -c -D $(DEFINES) -o $@ $<
	@echo done

clean:
	@rm -rf $(EXE)
	@rm -rf *.o
	@rm -f *~
	@echo cleaned
