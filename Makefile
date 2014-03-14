#---------------------------------------------
#-	AES 	 模块链接		http://www.gladman.me.uk/
#-	Mersenne 模块链接		http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/emt.html
#-	LZMA	 模块			官方网站 920版本
#-	MD5	 忘了..	
#-	
#-
#---------------------------------------------
NAME		:= as3crypt
MODULES		:= aes tinymt md5 base64

BUILD_DIR	:= build


CC	:=	gcc
CCC	:=	g++ -fno-rtti

$(BUILD_DIR)/%.o: %.c
	@echo $(notdir $<)
	$(CC) -c $(INCLUDES) $(OPTIMISE) $< -o $@
#-ffast-math	
INCLUDES :=  -I. -I/cygdrive/d/alchemy/avm2-libc/include -L/cygdrive/d/alchemy/avm2-libc/lib 
OPTIMISE :=  -fomit-frame-pointer -fdata-sections -ffunction-sections -fno-exceptions -Wall -W -Wno-unused-parameter -O3


VPATH 		:=	%.c $(MODULES)

CFILES		:=	$(foreach dir,$(MODULES),$(wildcard $(dir)/*.c))
CFILES		+=	alchemy.c

ifdef LZMA
CFILES		+=	$(addprefix lzma/,Alloc.c LzFind.c LzmaDec.c LzmaEnc.c 7zFile.c 7zStream.c)
VPATH		+= lzma
OPTIMISE	+= -D_7ZIP_ST -DLZMA
endif

OBJS		:= 	$(patsubst %.c,$(BUILD_DIR)/%.o,$(notdir $(CFILES)))





.PHONY: all clean

all: $(BUILD_DIR) $(NAME)

$(NAME): $(OBJS)
	$(CC) $(OBJS) -swc -o $(NAME).swc -O3 -Wl,--gc-sections
	
$(BUILD_DIR) :
	@mkdir -p $@
	
clean:
	@echo clean....
	@rm -rf $(BUILD_DIR) *.achacks.*