/**
 * 关于 AES 加密操作,参看 aes目录下的aes.txt 文档
 *
 *  更改模式时,必须重新设置 AES_Key.
 *  对于  CFB, OFB and CTR 还必须调用 aes_mode_reset
 *
 *
 *
 * **重要:**最好将 AES_KEY 内嵌于 C语言端, 你需要重新编译 源代码,使用 Alchemy而不是Flascc,找到 aes_key_list 那一行,那里有一些自动生成数字的JS脚本..
 *
 */
package ming{
	import cmodule.as3crypt.CLibInit;
	import flash.utils.ByteArray;

	public class Crypt {

		public function Crypt() {
		}

		static private const UPPER:Vector.<String >  = Vector.<String > ('0123456789ABCDEF'.split(''));
		static private const LOWER:Vector.<String >  = Vector.<String > ('0123456789abcdef'.split(''));

		private static var _load:cmodule.as3crypt.CLibInit;
		private static var _lib:*;

		public static function get load():cmodule.as3crypt.CLibInit {
			return _load;
		}

		public static function get lib():* {
			return _lib;
		}

		/**
		 *
		 * @param seed
		 */
		public static function init(seed:uint=1) {
			_load = new cmodule.as3crypt.CLibInit  ;

			_lib = _load.init();

			_lib.init_tinymt32( ~   ~  Math.random() * 10000000, ~   ~  Math.random() * 2000000, ~   ~  Math.random() * 300000,seed);

			_lib.current_iv(1);
			// 初使化一个 IV 值,到 C 的缓存,避免 没有传递 iv 值而产生错误;

			_lib.aes_embed_key(0);
		}
		// 预置一个 内嵌的 AES Key 值,每次更改 aes 模式时,需要重新设置;

	

	public static function md5(data:ByteArray):ByteArray {
		return _lib.md5(data,data.length);
	}

	/**
	 * 注意 返回的ByteArray 的 position 位于最后，请自行调整 为 0
	 * @paramdata
	 * @paramname名字可以随便是什么字符串,不同文件不要用相同名就可以了因为会缓存
	 * @return
	 */
	public static function unlzma(data:ByteArray,name:String):ByteArray {
		_load.supplyFile(name,data);
		return _lib.unlzma(name);
	}

	/**
	 *Base64 encode/decode
	 * @paramstr
	 * @paramencode
	 * @return
	 */
	public static function base64(str:String,encode:Boolean=true):String {
		return _lib.base64(str,str.length,encode);
	}

	/**
	 * tinymt32 初使化,参看 init 函数最后一条
	 * @parammat1
	 * @parammat2
	 * @paramtmat
	 * @paramseed
	 */
	public static function init_tinymt32(mat1:uint,mat2:uint,tmat:uint,seed:uint=1):void {
		_lib.init_tinymt32(mat1,mat2,tmat,seed);
	}

	/**
	 * tinymt32 通过数组的形式设置 tinymt32
	 * @paramarray
	 */
	public static function array_init_tinymt32(array:Array):void {
		_lib.array_init_tinymt32(array);
	}

	/**
	 * tinymt32
	 * @return
	 */
	public static function tinymt32_int():uint {
		return _lib.tinymt32_int();
	}

	/**
	 *
	 * @paramwhich
	 * 1:tinymt32_generate_floatr (0.0 <= r < 1.0)
	   2:tinymt32_generate_float12r (1.0 <= r < 2.0)
	   3:tinymt32_generate_floatOCr (0.0 < r <= 1.0)
	   4: tinymt32_generate_32doubler (0.0 < r <= 1.0)
	
	   default:tinymt32_generate_floatOOr (0.0 < r < 1.0)
	 * @return
	 */
	public static function tinymt32(which:int=0):Number {
		return _lib.tinymt32(which);
	}

	/**
	 * 得到 当前 IV 值..应该在下次 加密或解密之前拿到这个值,当然如果从AS端传送的IV值,可以忽略这个方法
	 * @paramrefresh if true,将刷新一个新的IV值再返回,否则为以前那个
	 * @return
	 */
	public static function current_iv(refresh:Boolean=false):ByteArray {
		return _lib.current_iv(refresh);
	}

	/**
	 * 使用内嵌 AES....如需更改其它值,你需要 修改 alchemy.c 并从新编译..
	 * @paramwhich
	 */
	public static function aes_embed_key(which:int=0):void {
		_lib.aes_embed_key(which);
	}

	/**
	 * 切换 AES 加密模式时,需要更改 AES_Key,支持 128,192,256长度Key
	 * @param Key
	 * @return 0 表示无错误
	 */
	public static function aes_key_byte(Key:ByteArray):int {
		return _lib.aes_key_byte(Key,Key.length);
	}

	/**
	 *  32|48|64 字符长度分别对应 128|192|256 长度 AES_Key
	 * @paramKey 的16进制字符串
	 * @return 0 表示无错误
	 */
	public static function aes_key_str(Key:String):int {
		return _lib.aes_key_str(Key);
	}

	/**
	 * 更改AES模式时,CTR,CFB,OFB 需要调用这个函数,详情见 aes.txt 文档
	 * @param Key
	 * @return 0 表示无错误
	 */
	public static function aes_mode_reset():int {
		return _lib.aes_mode_reset();
	}

	/**
	 * AES CTR RFC3638 标准加密...不分encode和decode.和异或操作类似
	 * @paramdata
	 * @paramiv
	 * @return
	 */
	public static function aes_ctr_3638(data:ByteArray,iv:ByteArray):int {
		return _lib.aes_ctr_3638(data,iv,data.length);
	}

	/**
	 * AES ECB
	 * @paramdata
	 * @paramencode
	 * @return
	 */
	public static function aes_ecb(data:ByteArray,encode:Boolean=true):int {
		return _lib.aes_ecb(data,data.length,encode);
	}

	/**
	 *AES CBC
	 * @paramdata
	 * @paramiv
	 * @paramencode
	 * @return
	 */
	public static function aes_cbc(data:ByteArray,iv:ByteArray,encode:Boolean=true):int {
		return _lib.aes_cbc(data,iv,data.length,encode);
	}

	/**
	 * AES CFB
	 * @paramdata
	 * @paramiv
	 * @return
	 */
	public static function aes_cfb(data:ByteArray,iv:ByteArray,encode:Boolean=true):int {
		return _lib.aes_cfb(data,iv,data.length,encode);
	}

	/**
	 * AES OFB不分encode和decode.和异或操作类似
	 * @paramdata
	 * @paramiv
	 * @return
	 */
	public static function aes_ofb(data:ByteArray,iv:ByteArray):int {
		return _lib.aes_ofb(data,iv,data.length);
	}

	/**
	*	使用内嵌的 16字节/128位 Key 进行 xor 操作
	* @data
	* @return 
	*/
	public static function xora(data:ByteArray):ByteArray{
		data.position = 0;
		return _lib.xora(data,data.length);
	}

	/**
	 * 现在 ECB,CBC 能自已处理,这个函数将被移除
	 * @param bt
	 * @deprecated
	 */
	public static function enpad16(bt:ByteArray):void {
		var i:uint;
		var pad:uint = 16 - bt.length & 15;

		bt.position = bt.length;

		i = pad;

		while (i--) {
			bt.writeByte(pad);
		}
		bt.position = 0;

	}

	/**
	 * 现在 ECB,CBC 能自已处理,这个函数将被移除
	 * @param bt
	 * @deprecated
	 */
	public static function depad16(bt:ByteArray):void {
		bt.position = bt.length - 1;
		var pad:uint = bt.readByte();
		bt.length = bt.length - pad;
		bt.position = 0;

	}

	/**
	 * 将 ByteArray 转换成 可读字符串
	 * @paramarray
	 * @paramupper大写
	 * @return
	 */
	public static function fromByte(array:ByteArray,upper:Boolean=false):String {
		var i:int = 0,cv:Vector.<String >  = upper ? UPPER:LOWER,len:int = array.length,n:uint;
		len +=  len;
		var ret:Vector.<String >  = new Vector.<String > (len,true);
		array.position = 0;
		for (; i < len; i +=  2) {
			n = array.readUnsignedByte();
			ret[i] = cv[((n & 0xf0) >> 4)];
			ret[i + 1] = cv[(n & 0xf)];
		}
		return ret.join("");
	}

	/**
	 * 和 fromByte 相反
	 * @paramhex
	 * @return
	 */
	public static function toByte(hex:String):ByteArray {
		var a:ByteArray = new ByteArray  ;
		var i:int = 0,len:int = hex.length;
		a.position = 0;
		for (; i < len; i +=  2) {
			a.writeByte(parseInt(hex.substr(i,2),16));
		}
		return a;
	}

	/**
	 * 废弃
	 * @paramdata
	 * @paramn
	 * @return
	 */
	public static function xor(bt:ByteArray,num:uint):Boolean {
		var a:uint = 0,len:int = bt.length;

		if ((num > 0xffffff)) {
		} else if ((num > 0xffff)) {
			num = num | ((num & 0xff) << 24);
		} else if ((num > 0xff)) {
			num = num | (num << 16);
		} else {
			num = num | (num << 8) | (num << 16) | (num << 24);
		}

		if ((num > 0)) {

			bt.position = 0;

			while ((len >= 4)) {
				a = bt.readUnsignedInt() ^ num;
				bt.position -=  4;
				bt.writeUnsignedInt(a);
				len -=  4;
			}
			num &=  0xff;
			while (len--) {
				a = bt.readByte() ^ num;
				bt.position -=  1;
				bt.writeByte(a);
			}
		}
		return len === -1;
	}

}

}