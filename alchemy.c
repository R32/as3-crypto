#include "AS3.h"

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>

#include "aes/aes.h"	// 注释掉 aesopt.h 169行  #define VIA_ACE_POSSIBLE
#include "md5/md5.h"
#include "base64/base64.h"
#include "tinymt/tinymt32.h"	// 由于随机 IV 值需要用到这个方法,暂时就这样

static AS3_Val gg_lib = NULL;
static AS3_Val no_params = NULL;
static AS3_Val zero_param = NULL;
static AS3_Val ByteArray_class = NULL;





//same as function rfc3686_inc
static void ctr_inc(unsigned char ctr_buf[16]){

    if(!(++(ctr_buf[15])))

        if(!(++(ctr_buf[14])))

            if(!(++(ctr_buf[13])))

                ++(ctr_buf[12]);

}

 //same as function rfc3686_init
//4Bytes nounce+8Bytes iv+4Bytes counter
static void ctr_init( unsigned char nonce[4], unsigned char iv[8], unsigned char ctr_buf[16]){

    memcpy(ctr_buf, nonce, 4);

    memcpy(ctr_buf +  4, iv, 8);

    memset(ctr_buf + 12, 0, 4);

    ctr_inc(ctr_buf);
}


static void ggInit(){
	//sztrace("setting up as3_crypto_wrapper library");

	/* setup some useful constants */
	no_params = AS3_Array("");
	zero_param = AS3_Int(0);
	AS3_Val flash_utils_namespace = AS3_String("flash.utils");
	ByteArray_class = AS3_NSGetS(flash_utils_namespace, "ByteArray");
	AS3_Release(flash_utils_namespace);
}

static void gg_reg(AS3_Val lib, const char *name, AS3_ThunkProc p) {
	AS3_Val fun = AS3_Function(NULL, p);
	AS3_SetS(lib, name, fun);
	AS3_Release(fun);
}

/**
*
* @param byteArray
* @param &size
***/
static void* newMallocFromByteArray(AS3_Val byteArray, size_t* size){
	AS3_Val byteArraySize = AS3_GetS(byteArray, "length");
	*size = AS3_IntValue(byteArraySize);
	AS3_Release(byteArraySize);
	void* bytes = malloc(*size);
	AS3_SetS(byteArray, "position", zero_param);
	AS3_ByteArray_readBytes((char*)bytes, byteArray, (int)*size);
	return bytes;
}

/**
* 和 newMallocFromByteArray 类似,但是 这个函数不会计算 length 属性
* @param byteArray
* @param int size 这是int 类型,不是 地址
**/
static void* mallocFromByteArray(AS3_Val byteArray, size_t size){
	void* bytes = malloc(size);	
	AS3_SetS(byteArray, "position", zero_param);
	AS3_ByteArray_readBytes((char*)bytes, byteArray, (int)size);
	return bytes;
}


/* Make a new ByteArray containing the data passed */
static AS3_Val newByteArrayFromMalloc(void *data, size_t size){
	AS3_Val byteArray = AS3_New(ByteArray_class, no_params);
	AS3_ByteArray_writeBytes(byteArray, data, size);
	return byteArray;
}


// 因为 char 容易被二进制工具查找得到,所以 short 形式好像安全一些
#define AES_KEY_LIST_LENGTH 3
#define AES_KEY_LIST_STRING_LENGTH 12
static unsigned short aes_key_list[AES_KEY_LIST_LENGTH][AES_KEY_LIST_STRING_LENGTH] = {
	{137, 117,  97, 114,  97, 121,122, 101, 114, 123,   0, 0},	 //yaf
	{120, 119, 140, 141, 112, 64, 113, 113,  54,  99, 119, 117}, // email
	{ 73,  73,  54,  54,  75, 54,  48,  50, 101, 113, 115, 0}	 // web.site
	
};
/*
		通过 Chrome 控制台 或其它Javascript 工具 运行下列函数,生成这些数字
		// 随便输入一些字符串就好,,长度在 控制在 12 就好了 
		会在C端多出 (12 * sizeof(short)) * n 字节..
		// encode 不支持中文
		function ecc(str){
			str = str.substring(0,12);
			var i, ret = [] ,len = str.length;
			for(i=0 ; i<len ; i+=1){
				ret.push( (str.charCodeAt(i) + len) ^ len  ); // 注意: 解密时也要反过来操作
			}
			for(i=len; i<12 ;i+=1){// 不足补 0 
				ret.push(0)
			};
			return ret
		}
		// decode
		function dcc(arr){
			var i, len = 12,ret = [];
			
			for(i = 0; i< len; i+=1){
				if(arr[i]==0){
					len = i;
					break;
				}
			}
			for(i=0; i< len; i += 1){
				ret.push(	String.fromCharCode ((arr[i] ^ len) - len) )// 反向操作
			}
			return ret.join("")
		}
	
*/


/**
* 一些临时变量.	
*/
static int ctx_ready = 0;	//是否已经设置
static aes_encrypt_ctx e_ctx[1];
static aes_decrypt_ctx d_ctx[1];

static unsigned char ctr_buf[AES_BLOCK_SIZE];	// for AES CTR RFC3638

static tinymt32_t tinymt;	

static unsigned char iv_aes[16];		// 新增. 考虑到 md5_static 的值因为调用md5而经常变动
static unsigned char iv_random[16]; 	// 内部的随机 iv 变量.
static unsigned char iv_outer[16]; 		// iv_outer 很可能是外部提供的一个 16 位 iv byteArray 值,如果外部没提供 则为 iv_random 的副本

static unsigned char md5_static[16];	// md5 计算结果

static void pt(unsigned char *md,int size){
	int i;
	unsigned char ch[size * 2 + 1];
	char * pch = (char*)ch;
	for (i=0; i<size; i++){
		sprintf(pch,"%02x",md[i]);
		pch += 2;
	}
	*++pch = 0;
	fprintf(stderr,"hex %s",ch);
}

/**
* 使用内嵌的 aes_key 值
* @param which 值 应该要小于 AES_KEY_LIST_LENGTH
*/
static AS3_Val thunk_aes_embed_key(void* self, AS3_Val args){
	unsigned char *ch;
	int i=0,len = AES_KEY_LIST_STRING_LENGTH ,which = 0;
	
	AS3_ArrayValue(args, "IntType", &which);
	
	if(which){// limit
		which = which % AES_KEY_LIST_LENGTH;
	}
	
	
	// find length value
	for(; i < len ; i +=1 ){
		if( aes_key_list[which][i] == 0 ){
			len = i;
			break;
		}
	}
	ch = (unsigned char *)malloc(len);
	for(i = 0; i < len ; i += 1){
		ch[i] = (( (unsigned char)aes_key_list[which][i] ) ^ len) - len;
	}
	//md5 生成的值刚好是 16字,128位
	
	md5(ch	,	len	,	iv_aes);
	
	//pt(iv_aes,16); // done
	
	free(ch);
	
	if(aes_encrypt_key(iv_aes, 16, e_ctx) == 0 && aes_decrypt_key(iv_aes, 16, d_ctx) == 0){
		ctx_ready = 1;
	}else{
		ctx_ready = 0;
	}
	//fprintf(stderr,"ctx_ready?? %d",ctx_ready);
	return AS3_Null();
}

/**
*
* tinymt32_generate_floatOO list
*/
static void tinymt32_list(float*list ,unsigned short len){
	int i = 0;
	if(len){
		for(; i < len ; i += 1){
			list[i] = tinymt32_generate_floatOO(&tinymt);
		}
	}
}

/**
* 更新随机 iv(iv_random[16])的值
* 不推荐使用,建议使用由 AS3 生成的随机 iv 值传递到 iv_outer
*/
static void random_iv(){
	int j, i ,n;
	uint32_t num;
	for(j=0; j < 4 ; j+=1){
		
		num = tinymt32_generate_uint32(&tinymt);
		//printf("\n%10u",num);
		for(i = 0; i < 4 ; i+=1 , num >>=8){
			n = (j << 2) + i;
			//printf("  AND %3d-%2d",0xff & num,n);
			//memset((void*)(iv_random + n) ,(char)(0xff & num),	1 );
			iv_random[n] = (unsigned char)(0xff & num);
		}
	}
	//iv_random[16] = 0;
	//printf("\n%16s",iv_random);
}

/**
* 返回当前 随机 iv(iv_random[16]) 的值
* @param [update=0]{int} 是否更新
* @return ByteArray	
*/
static AS3_Val thunk_get_iv(void* self, AS3_Val args){
	int update = 0;
	AS3_ArrayValue(args, "IntType", &update);
	if(update){
		random_iv();
	}
	return newByteArrayFromMalloc((void*)iv_random , 16);
}


/**
*	AS端设置 aes_key
* 仅用于测试, 由于AS端数据容易被识别,建议使用内嵌 iv_aes
* @param byte_aes_key{ByteArray} AS3_Val
*/
static AS3_Val thunk_aes_key_byte(void* self, AS3_Val args){
	
	unsigned char *key = NULL;
	
	int err,key_len = 0;
	
	AS3_Val data = NULL;
	
	AS3_ArrayValue(args, "AS3ValType,IntType", &data,	&key_len);
	
	key = (unsigned char*)mallocFromByteArray(data,key_len);

	memcpy((void*)iv_aes,(void*)key, 16);	// **注意** :请使用 16/128bit 的密钥

	if(aes_encrypt_key(key, key_len, e_ctx) == 0 && aes_decrypt_key(key, key_len, d_ctx) == 0){
		err = 0;
		ctx_ready = 1;
	}else{
		err = -1;
		ctx_ready = 0;
	}
	free(key);
	AS3_Release(data);
	return AS3_Int(err);
}

/**
*	AS 端设置 aes_key 以 char * 的方式
*	仅用于测试, 由于AS端数据容易被识别,建议使用内嵌 iv_aes
* @param string_aes_key{String} // char *
*/
static AS3_Val thunk_aes_key_str(void* self, AS3_Val args){
	
	char 	*cp , ch,key[32];
	int 	i = 0 ,key_len =0, by = 0 , err =0;
	
	AS3_ArrayValue(args, "StrType", &cp);// 字符串指针,不知道 传递过来有没有将最后符串置 0 ?
	
	//fprintf(stderr,"the strlen %d ,and ",strlen(cp));
	
	while(i < 64 && *cp){
		 ch = toupper(*cp++); 
		
		if(ch >= '0' && ch <= '9')
            by = (by << 4) + ch - '0';
        else if(ch >= 'A' && ch <= 'F')
            by = (by << 4) + ch - 'A' + 10;
        else{
			//fprintf( stderr, "key must be in hexadecimal notation\n" );
            err = -2; goto exit;
        }
		if(i++ & 1)
            key[i / 2 - 1] = by & 0xff;
	}
	if(*cp){
		//fprintf(stderr ,"The key value is too long\n");
        err = -3; goto exit;
	}else if( i < 32 || (i & 15) ){
		//fprintf(stderr,"The key length must be 32, 48 or 64 hexadecimal digits\n");
        err = -4; goto exit;
	}
	
	key_len = i / 2;

	memcpy((void*)iv_aes,(void*)key, 16); // **注意** :请使用 16/128bit 的密钥
	 
	if(aes_encrypt_key((unsigned char*)key, key_len, e_ctx) == 0 && aes_decrypt_key((unsigned char*)key, key_len, d_ctx) == 0){
		err = 0;
		ctx_ready = 1;
	 }else{
		err = -1;
		ctx_ready = 0;
	}
exit:
	free(cp);
	return AS3_Int(err);
}


/**
*	aes_mode_reset 重设
*/
static AS3_Val thunk_aes_mode_reset(void* self, AS3_Val args){
	return AS3_Int(aes_mode_reset(e_ctx));
}

/**
*	这个函数之前要先设置 aes_key,	自动16x及清除
* @param byte{ByteArray}
* @param size 由于C 不太好操作AS端的东西.所以改为由 AS提供.
* @param [encode=false]{Boolean}
* @return AS3_Int 0 表示无错误发生.程序将会修改 param byte
***/
static AS3_Val thunk_aes_ecb(void* self, AS3_Val args){
	
	int encode  = 0;
	int err = -1;
	int pad = 0;	//
	size_t size = 0;
	AS3_Val data =NULL; //直接修改这个 data 还是新建一个??
	unsigned char *ibuf;
	AS3_ArrayValue(args, "AS3ValType,IntType,IntType", 	&data, &size ,&encode);
	
	if(ctx_ready){
		if(encode){
			
			pad = 16 - 	(size & (AES_BLOCK_SIZE - 1));
			
			ibuf = (unsigned char*)mallocFromByteArray(data, size + pad);
			
			memset((void*)(ibuf + size) , (char)pad , pad );
			
			size += pad;
			
			err = aes_ecb_encrypt(ibuf , ibuf, size , e_ctx);
			
		}else{
			
			ibuf = (unsigned char*)mallocFromByteArray(data, size);
			
			err = aes_ecb_decrypt(ibuf , ibuf, size , d_ctx);
			
			pad = (char)*(ibuf + size -1);
			
			size -= pad;
		}
		
		//fprintf(stderr,"is encode?%d,and the size is:%d,...padding:%d",encode,size,pad);
		if(err == 0){
			AS3_SetS(data, "length", zero_param);
			AS3_ByteArray_writeBytes(data, ibuf, size);
		}
		free(ibuf);
	}
	
	AS3_Release(data);
	return AS3_Int(err);;
}

/**
*
* @param byte{ByteArray}
* @param [iv=null]{ByteArray}
* @param len{int} byte.length 
* @param [encode = false]{Boolean}
*/
static AS3_Val thunk_aes_cbc(void* self, AS3_Val args){
	int pad,encode,err = -1;
	AS3_Val fiv = NULL;
	AS3_Val data = NULL;
	
	size_t size = 0;
	
	unsigned char *ibuf = NULL;

	AS3_ArrayValue(args, "AS3ValType,AS3ValType,IntType,IntType", 	&data,	&fiv, &size	,&encode);
	if(ctx_ready){
		
		if(fiv){
			AS3_SetS(fiv, "position", zero_param);
			AS3_ByteArray_readBytes(iv_outer, fiv, 16);
		}else{
			memcpy((void*)iv_outer,(void*)iv_random , 16);
		}
		
		if(encode){
			
			pad = 16 - 	(size & (AES_BLOCK_SIZE - 1));
			
			ibuf = (unsigned char*)mallocFromByteArray(data, size + pad);
			
			memset((void*)(ibuf + size) , (char)pad , pad );
			
			size += pad;
			
			err = aes_cbc_encrypt(ibuf, ibuf , size , iv_outer , e_ctx);
			
		}else{
			
			ibuf = (unsigned char*)mallocFromByteArray(data, size);
			
			err = aes_cbc_decrypt(ibuf, ibuf , size , iv_outer , d_ctx);
			
			pad = (char)*(ibuf + size -1);
			
			size -= pad;
		}
		//fprintf(stderr,"final size is %d,and the pad:%d....enCode ?%d",size,pad,encode);
		if(err == 0){
			AS3_SetS(data, "length", zero_param); //长度清 0
			AS3_ByteArray_writeBytes(data, ibuf, size);
		}
		free(ibuf);
	}
	AS3_Release(data);
	AS3_Release(fiv);
	return AS3_Int(err);
}

static AS3_Val thunk_aes_cfb(void* self, AS3_Val args){
	int err = -1,encode  = 0;
	AS3_Val fiv = NULL;
	AS3_Val data = NULL;
	
	size_t size = 0;
	unsigned char *ibuf = NULL;
	AS3_ArrayValue(args, "AS3ValType,AS3ValType,IntType,IntType", 	&data,	&fiv , &size	,&encode);
	if(ctx_ready){
		ibuf = (unsigned char*)mallocFromByteArray(data, size);
		
		if(fiv){
			AS3_SetS(fiv, "position", zero_param);
			AS3_ByteArray_readBytes(iv_outer, fiv, 16);
		}else{
			memcpy((void*)iv_outer,(void*)iv_random , 16);
		}
		
		aes_mode_reset(e_ctx);
		
		if(encode){
			err = aes_cfb_encrypt(ibuf, ibuf , size , iv_outer , e_ctx);
		}else{
			err = aes_cfb_decrypt(ibuf, ibuf , size , iv_outer , e_ctx);
		}
		
		if(err == 0){ //
			AS3_SetS(data, "position", zero_param);
			AS3_ByteArray_writeBytes(data, ibuf, size);
		}
		free(ibuf);
	}
	AS3_Release(data);
	AS3_Release(fiv);
	return AS3_Int(err);
}

static AS3_Val thunk_aes_ofb(void* self, AS3_Val args){
	int err = -1;
	AS3_Val fiv = NULL;
	AS3_Val data = NULL;
	
	size_t size = 0;
	
	unsigned char *ibuf = NULL;
	
	AS3_ArrayValue(args, "AS3ValType,AS3ValType,IntType", 	&data, &fiv ,&size);
	if(ctx_ready){
		ibuf = (unsigned char*)mallocFromByteArray(data,size);

		if(fiv){
			AS3_SetS(fiv, "position", zero_param);
			AS3_ByteArray_readBytes(iv_outer, fiv, 16);
		}else{
			memcpy((void*)iv_outer,(void*)iv_random , 16);
		}
		
		aes_mode_reset(e_ctx);
		
		err = aes_ofb_crypt(ibuf, ibuf , size , iv_outer , e_ctx);
	
		if(err == 0){
			AS3_SetS(data, "position", zero_param);
			AS3_ByteArray_writeBytes(data, ibuf, size);
		}
		free(ibuf);
	}
	AS3_Release(data);
	AS3_Release(fiv);
	return AS3_Int(err);
}

static AS3_Val thunk_aes_ctr_3638(void* self, AS3_Val args){
	int err = -1;
	AS3_Val fiv = NULL;
	AS3_Val data = NULL;
	size_t size = 0;
	unsigned char *ibuf = NULL;
	
	
	AS3_ArrayValue(args, "AS3ValType,AS3ValType,IntType", 	&data,	&fiv , &size);
	if(ctx_ready){
		ibuf = (unsigned char*)mallocFromByteArray(data,size);
		if(fiv){
			AS3_SetS(fiv, "position", zero_param);
			AS3_ByteArray_readBytes(iv_outer, fiv, 16);
		}else{
			memcpy((void*)iv_outer,(void*)iv_random , 16);
		}
		
		aes_mode_reset(e_ctx);
		
		ctr_init(iv_outer,iv_outer+4,ctr_buf);//we set iv as the nouce
			
		err = aes_ctr_crypt(ibuf, ibuf , size , ctr_buf, ctr_inc ,e_ctx);

		if(err == 0){
			AS3_SetS(data, "position", zero_param);
			AS3_ByteArray_writeBytes(data, ibuf, size);
		}
		free(ibuf);
	}
	AS3_Release(data);
	AS3_Release(fiv);
	return AS3_Int(err);
}


//#ifdef _TINYMT	由于 随机 IV 值需要这个来生成随机数，这库其实很小，换

// -------------------- 随机数 -------------------------
/**
*	初使化
* @param [mat1=123] {uint}
* @param [mat2=456] {uint}
* @param [tmat=789] {uint}
* @param [seed=1] {uint}
*/
static AS3_Val thunk_init_tinymt32(void* self, AS3_Val args){
	unsigned int seed = 1;
	
	AS3_ArrayValue(args, "IntType,IntType,IntType,IntType",&tinymt.mat1,&tinymt.mat2,&tinymt.tmat,&seed);
	
	tinymt32_init(&tinymt,seed);
	
	return AS3_Null();
}

static AS3_Val thunk_array_init_tinymt32(void* self, AS3_Val args){
	uint32_t *par;
	int i = 0,len = 0;
	AS3_Val list;
	
	AS3_Val length;
	AS3_Val item;
	AS3_ArrayValue(args, "AS3ValType",&list);
	
	length = AS3_GetS(list, "length");
	len = AS3_IntValue(length);
	AS3_Release(length);
	if(len){
		par = (uint32_t *)malloc(sizeof(uint32_t) * len);
		
		for(; i<len ; i += 1){
			item = AS3_CallS( "shift", list, no_params );
			par[i] = AS3_IntValue(item);
			AS3_Release(item);
		}
		tinymt32_init_by_array(&tinymt , par , len);
		free(par);
	}
	AS3_Release(list);
	return AS3_Null();
}

static AS3_Val thunk_tinymt32_int(void* self, AS3_Val args){
	return AS3_Int(tinymt32_generate_uint32(&tinymt));
}

static AS3_Val thunk_tinymt32(void* self, AS3_Val args){
	int which = 0;
	double ret = 0.0;
	
	AS3_ArrayValue(args, "IntType",&which);
	
	switch(which){//tinymt32_generate_floatOO default
		case 1:
			ret = (double)tinymt32_generate_float(&tinymt);
			break;
		case 2:
			ret = (double)tinymt32_generate_float12(&tinymt);
			break;
		case 3:
			ret = (double)tinymt32_generate_floatOC(&tinymt);
			break;
		case 4:
			ret = tinymt32_generate_32double(&tinymt);
			break;	
		default: 
			ret = (double)tinymt32_generate_floatOO(&tinymt); // 因为这个返回 0 < r < 1 之间的数字
			break;
	}
	return AS3_Number(ret);
}

/**
*
* @param 返回一个AS数组,这个方法返回的值不正确..
***/
static AS3_Val thunk_tinymt32_array(void* self, AS3_Val args){
	unsigned short len = 2;
	float *pf = NULL;
	AS3_Val ret = NULL;
	
	AS3_ArrayValue(args, "IntType",&len);
	if(len > 0){
		pf = (float*)malloc(sizeof(float) * len);
		tinymt32_list(pf,len);
		ret = newByteArrayFromMalloc((void*)pf , len * sizeof(float));
		free(pf);
		return ret;
	}
	return AS3_Null();
}


static AS3_Val thunk_md5(void* self, AS3_Val args){
	
	size_t size = 0;
	unsigned char* bytes = NULL;
	
	AS3_Val data =NULL;
	
	AS3_ArrayValue(args, "AS3ValType,IntType",  &data , &size);
	
	bytes = (unsigned char*)mallocFromByteArray(data, size);
	
	md5(bytes	,	size	,	md5_static);
	
	//pt(md5_static,16);
	
	AS3_Release(data);

	free(bytes);
	return newByteArrayFromMalloc(md5_static,16);
}

/**
*
* @param str{String}
* @param encode{int}
* @return {String}
*/
static AS3_Val thunk_base64(void* self, AS3_Val args){
	
	unsigned char *data = NULL, *r = NULL;
	
	int encode = 0;
	
	int input_length,output_length;
	
	AS3_Val ret = NULL;
	
	AS3_ArrayValue(args, "StrType,IntType,IntType",  &data, &input_length, &encode);
	
	if(encode){
		r = base64_encode(data,input_length,&output_length);
	}else{
		r = base64_decode(data,input_length,&output_length);
	}

	ret = AS3_StringN((char *)r	,	output_length);
	
	free(r);
	
	free(data);
	return ret;
}

// 一个针对 byteArray的.
/* static AS3_Val thunk_base64a(void* self, AS3_Val args){
	
	int encode = 0,input_length,output_length;
	
	unsigned char *data = NULL, *r = NULL;
	
	AS3_Val asByte = NULL, ret = NULL;
	
	AS3_ArrayValue(args, "AS3ValType,IntType,IntType",  &asByte , &input_length, &encode);
	
	data = (unsigned char*)mallocFromByteArray(asByte, input_length);
	
	if(encode){
		r = base64_encode(data,input_length,&output_length);
	}else{
		r = base64_decode(data,input_length,&output_length);
	}
	ret = newByteArrayFromMalloc((void*)r,output_length);
	free(r);
	free(data);
	return ret;
} */

/**
*	这里可以自已设置一些 隐藏数字,外部用 xor 来解密
*	由于 throw 可以抛出变量,这种形式并非安全,因此需要添加一个 xora 的方法
*/
int IntList[8] = {1023,201,397,6771,8013,291,6187,1396}; // 随机乱数字
AS3_Val thunk_getx(void *data, AS3_Val args){
	int who = 0;
	 AS3_ArrayValue(args, 
				   "IntType",&who
	);
	return AS3_Int(IntList[who < 8 && who > -1 ? who : 0]);
}

/**
*
*@param byte{ByteArray}
*@return ByteArray 返回新的
**/
static AS3_Val thunk_xora(void* self, AS3_Val args){
	size_t size = 0;
	size_t len = 0;

	int pos = 0;
	
	AS3_Val data =NULL;
	AS3_Val AS_Ret = NULL;
	unsigned char* bytes = NULL;
	unsigned int* bytes4 = NULL;
	unsigned char* ret = NULL;
	unsigned int* ret4 = NULL;
	unsigned char* val = NULL;	// 使用外部提供的 key.
	
	AS3_ArrayValue(args, "AS3ValType,StrType", 	&data, &val);


	if(val == NULL){
		memcpy((void*)iv_outer, (void*)iv_aes , 16);
	}else{
		md5(val, (size_t)strlen(val), iv_outer);
	}

	bytes = (unsigned char*)newMallocFromByteArray(data, &size );
	bytes4 = (unsigned int*)bytes;
	
	ret = (unsigned char*)malloc(size);
	ret4 = (unsigned int*)ret;
	len = size;
	while(len >=4){
		*(ret4++) = *(bytes4++) ^ (iv_outer[pos % 16] | (iv_outer[pos+1 % 16] << 8) | (iv_outer[pos+2 % 16] << 16) | (iv_outer[pos+3 % 16] << 24));
		pos += 4;
		len -= 4;
	}
	while(len > 0){
		*(ret + pos) = *(bytes + pos) ^ iv_outer[pos % 16];
		pos += 1;
		len -= 1;
	}
	AS_Ret = newByteArrayFromMalloc(ret,size);
	free(ret);
	free(bytes);
	return AS_Ret;
}





#ifdef LZMA
#include "lzma/Alloc.h"
#include "lzma/7zFile.h"
#include "lzma/7zVersion.h"
#include "lzma/LzmaDec.h"
#include "lzma/LzmaEnc.h"

static void *SzAlloc(void *p, size_t size) { p = p; return MyAlloc(size); }
static void SzFree(void *p, void *address) { p = p; MyFree(address); }
static ISzAlloc g_Alloc = { SzAlloc, SzFree };

#define IN_BUF_SIZE (1 << 18)	// 16
#define OUT_BUF_SIZE (1 << 18) //16

static SRes Decode2(CLzmaDec *state, AS3_Val stream, ISeqInStream *inStream,
    UInt64 unpackSize)
{
  int thereIsSize = (unpackSize != (UInt64)(Int64)-1);
  Byte inBuf[IN_BUF_SIZE];
  Byte outBuf[OUT_BUF_SIZE];
  size_t inPos = 0, inSize = 0, outPos = 0;
  LzmaDec_Init(state);
  
  for (;;)
  {
    if (inPos == inSize)
    {
      inSize = IN_BUF_SIZE;
      RINOK(inStream->Read(inStream, inBuf, &inSize));
      inPos = 0;
    }
    {
      SRes res;
      SizeT inProcessed = inSize - inPos;
      SizeT outProcessed = OUT_BUF_SIZE - outPos;
      ELzmaFinishMode finishMode = LZMA_FINISH_ANY;
      ELzmaStatus status;
      if (thereIsSize && outProcessed > unpackSize)
      {
        outProcessed = (SizeT)unpackSize;
        finishMode = LZMA_FINISH_END;
      }
      
      res = LzmaDec_DecodeToBuf(state, outBuf + outPos, &outProcessed,
        inBuf + inPos, &inProcessed, finishMode, &status);
      inPos += inProcessed;
      outPos += outProcessed;
      unpackSize -= outProcessed;
      
     /* if (outStream)
        if (outStream->Write(outStream, outBuf, outPos) != outPos)
          return SZ_ERROR_WRITE;
       */
	  //fprintf( stderr, "OPEN SOUND DEVICE!!" );
	  if((unsigned int)AS3_ByteArray_writeBytes(stream , outBuf, outPos ) != outPos){
	  
		return SZ_ERROR_WRITE;
	  }
      outPos = 0;
      
      if (res != SZ_OK || thereIsSize && unpackSize == 0)
        return res;
      
      if (inProcessed == 0 && outProcessed == 0)
      {
        if (thereIsSize || status != LZMA_STATUS_FINISHED_WITH_MARK)
          return SZ_ERROR_DATA;
        return res;
      }
    }
  }
}

static SRes Decode(AS3_Val stream, ISeqInStream *inStream)
{
  UInt64 unpackSize;
  int i;
  SRes res = 0;

  CLzmaDec state;

  /* header: 5 bytes of LZMA properties and 8 bytes of uncompressed size */
  unsigned char header[LZMA_PROPS_SIZE + 8];

  /* Read and parse header */

  RINOK(SeqInStream_Read(inStream, header, sizeof(header)));

  unpackSize = 0;
  for (i = 0; i < 8; i++)
    unpackSize += (UInt64)header[LZMA_PROPS_SIZE + i] << (i * 8);

  LzmaDec_Construct(&state);
  RINOK(LzmaDec_Allocate(&state, header, LZMA_PROPS_SIZE, &g_Alloc));
  res = Decode2(&state, stream, inStream, unpackSize);
  LzmaDec_Free(&state, &g_Alloc);
  return res;
}


AS3_Val thunk_unlzma(void* self, AS3_Val args)
{
  CFileSeqInStream inStream;
  
  char *is; // filename
  
  AS3_Val stream = AS3_Null();
 
  
  AS3_ArrayValue(args, "StrType",&is);
  
  
  FileSeqInStream_CreateVTable(&inStream);
  
  File_Construct(&inStream.file);
  
  {
    size_t t4 = sizeof(UInt32);
    size_t t8 = sizeof(UInt64);
    if (t4 != 4 || t8 != 8)
      goto exit;
  }

	if (InFile_Open(&inStream.file, is) != 0){
		goto exit;
	}
	
	stream = AS3_New(ByteArray_class, no_params);
	
	Decode(stream,  &inStream.s);

	File_Close(&inStream.file);
exit:
	free(is);
	return stream;// 这样返回不同值
}
#endif

int main(int argc, char **argv) {
	
	ggInit();
	
	gg_lib = AS3_Object("");
	
	gg_reg(gg_lib, "getx", thunk_getx);
//>>>>>>>> AES Start	
	gg_reg(gg_lib, "aes_key_str", thunk_aes_key_str);
	
	gg_reg(gg_lib, "aes_key_byte", thunk_aes_key_byte);
	
	gg_reg(gg_lib, "aes_embed_key", thunk_aes_embed_key);
	
	gg_reg(gg_lib, "aes_ecb", thunk_aes_ecb);
	
	gg_reg(gg_lib, "aes_cbc", thunk_aes_cbc);
	
	gg_reg(gg_lib, "aes_cfb", thunk_aes_cfb);
	
	gg_reg(gg_lib, "aes_ofb", thunk_aes_ofb);
	
	gg_reg(gg_lib, "aes_ctr_3638", thunk_aes_ctr_3638);
	
	gg_reg(gg_lib, "aes_mode_reset", thunk_aes_mode_reset);
	
	gg_reg(gg_lib, "current_iv", thunk_get_iv);
//>>>>>>>> AES End
		
	gg_reg(gg_lib, "md5", thunk_md5);
	
	gg_reg(gg_lib, "base64", thunk_base64);
	
	gg_reg(gg_lib, "init_tinymt32", thunk_init_tinymt32);
	
	gg_reg(gg_lib, "array_init_tinymt32", thunk_array_init_tinymt32);
	
	gg_reg(gg_lib, "tinymt32_int", thunk_tinymt32_int);
	
	gg_reg(gg_lib, "tinymt32", thunk_tinymt32);
	
	gg_reg(gg_lib, "tinymt32_byte", thunk_tinymt32_array);

	gg_reg(gg_lib, "xora", thunk_xora);
	
#ifdef LZMA
	gg_reg(gg_lib, "unlzma", thunk_unlzma);
#endif
	
	AS3_LibInit(gg_lib);
	
	aes_init() ; // init aes
	
	return 0;
}
