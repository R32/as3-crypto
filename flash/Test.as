package  {
	import flash.events.MouseEvent
    import flash.utils.Endian;
	import flash.display.Sprite;
	import flash.utils.ByteArray
	import flash.net.URLLoader;
	import flash.events.Event;
	import flash.net.URLRequest;
	import flash.text.TextField;
	import flash.utils.ByteArray;
	//import flash.utils.CompressionAlgorithm;
	import flash.utils.getTimer;
	import flash.net.FileReference;
	import ming.Crypt
	import net.hires.debug.Stats
	import com.hurlant.util.Base64;
	
	import com.hurlant.crypto.hash.MD5;
	import com.hurlant.crypto.symmetric.AESKey;
	
	import flash.display.SimpleButton;
	
	public class Test extends Sprite {
		
		var sout:TextField = new TextField();
		var soutCount:Number = 0;
		
		var to:Number;
		
		var data:ByteArray;
		
		var ff:FileReference;
		var aes:AESKey;
		var md5:MD5;
		public function Test() {
			// constructor code
			
			//var i:uint = as3crypto_wrapper.md5_begin();
			
			sout.width = this.stage.stageWidth;
			sout.height = this.stage.stageHeight;
			this.addChild(sout)
			ff = new FileReference();
			
			Crypt.init(2);
			
			//as3 aes
			this.md5 = new MD5();
			var key:ByteArray = new ByteArray();
			key.writeMultiByte('yuanaifeng','ansi');
	
			this.aes = new AESKey(Crypt.md5(key))
			
			testTinyMt();
			//trace(Crypt.aes_key_str('12345678901234567890123456789012')) // HexStr(32|48|64)
			
			
			if(false){// test aes
				test_aes_ecb()	// done 
				test_aes_cbc()	// done
				test_aes_cfb()	// done
				test_aes_ofb()	// done
				test_aes_ctr()	// done https://www.rfc-editor.org/rfc/rfc3686.txt
			}//return;

			//testMersenne()
			loadTest('Test.as')
			//DONE 通过 crgwin 自带的压的 m.lzma 和 dos版 lzma920版 压的 m.lzma2
			//test_lzma('test.lzma')	
		
			//return
			//test_aes_timelabel()
			
			
			//trace(Crypt.base64('hello'));
			//trace(Crypt.base64('aG90dXBAcXEuY29t',false))
			
			//
			var xxa:ByteArray = new ByteArray();
			xxa.writeMultiByte('abcdefghijklmnopqrstuvwxyz','utf-8');
			xxa = Crypt.xora(xxa);
			trace(Crypt.fromByte(xxa));
			xxa = Crypt.xora(xxa);
			trace(xxa);
		}
		function onMemoryLeackTest(event:Event){
			
			Crypt.aes_ctr_3638(this.data,undefined)
			
			sout.text = ("\n\n\n\n\n\n\n\n\n\n\n--- "+Crypt.tinymt32_int())
		}
		function test_lzma(url:String){
			// 通过 loadTest 来快速测试
			var zfile:URLLoader = new URLLoader();
			zfile.dataFormat = 'binary';
			zfile.addEventListener(Event.COMPLETE,onZfileLoaded);
			zfile.load(new URLRequest(url))
		}
		function onZfileLoaded(event:Event){
			event.target.removeEventListener(Event.COMPLETE,onZfileLoaded);
			
			var data:ByteArray = event.target.data;
			var d1:ByteArray;
			
			//Crypt.md5(data)
			this.to = getTimer()
			d1 = Crypt.unlzma(data,'test');
			trace(getTimer() - this.to,d1.length/1024)
			trace(d1.toString().substring(0,100))
			//this.to = getTimer()
			//data.uncompress('lzma');
			//trace(getTimer() - this.to,data.length/1024)
			//trace(data)
		}
		//done
		function test_aes_ecb(){
			trace(">>>>>>>>>> Test AES ECB <<<<<<<<<<<<< ");
			// for encode
			var bt:ByteArray = new ByteArray();
			bt.writeMultiByte('hello!','ansi');
			
			// aes key
			var str:String = '29b95dba41aa1fe4fe0dae6f1f0de5f3'
			var key:ByteArray = new ByteArray();
			key.writeMultiByte('012345678912345678901234','ansi'); 
			
			//trace(clib.aes_key_str("12345678901234561234567890123456")); // 
			trace(key.length)
			trace('initail AES Key: ', Crypt.aes_key_byte(key));
			

			
			trace('aes_ecb_encode stage : ',Crypt.aes_ecb(bt,true));
			
			
			str = Crypt.fromByte(bt)
			
			trace(str)
			
			trace('aes_ecb_deboce stage state:',Crypt.aes_ecb(bt,false));
			
			trace('aes_ecb_deboce to String:',bt.toString())
			
			trace(">>>>>>>>>> End Test AES ECB <<<<<<<<<<<<< \n");
		}
		

		
		function test_aes_cbc(){
			trace(">>>>>>>>>> Test AES CBC <<<<<<<<<<<<< ");
			// for encode
			var iv:ByteArray = new ByteArray();
			iv.writeBytes(Crypt.toByte("27f63f5204217f3f80adffeeb92351aa"));
			
			//trace(toArray("27f63f5204217f3f80adffeeb92351aa"));return
			var bt:ByteArray = new ByteArray();
			
			bt.writeMultiByte('Brian Gladman','ansi');
			
			// aes key
			var str:String = ''
			
			var key:ByteArray = new ByteArray();
			
			key.writeMultiByte('0123456789123456','ansi'); 
			
			trace('initail AES Key: ',Crypt.aes_key_byte(key));
		
			
			
			trace('aes_cbc_encode stage : ',Crypt.aes_cbc(bt,iv,true));
			
			trace(Crypt.fromByte(bt))
			trace(bt.length)
			
			trace('aes_cbc_deboce stage state:',Crypt.aes_cbc(bt,iv,false));
		
			trace('aes_cbc_deboce to String:',bt.toString())
			
			trace(">>>>>>>>>> End Test AES CBC <<<<<<<<<<<<< \n");
		}
		
		function test_aes_cfb(){
			trace(">>>>>>>>>> Test AES CFB <<<<<<<<<<<<< ");
			// for encode
			var iv:ByteArray = new ByteArray();
			iv.writeBytes(Crypt.toByte("DC7E84BFDA79164B7ECD8486985D3860"));
			
			//trace(toArray("27f63f5204217f3f80adffeeb92351aa"));return
			var bt:ByteArray = new ByteArray();
			bt.writeMultiByte('Test AES CFB Long LOng Text','ansi');
			
			// aes key
			var str:String = ''
			var key:ByteArray = new ByteArray();
			key.writeMultiByte('0123456789123456','ansi'); 
			Crypt.aes_key_byte(key);
	//trace('initail AES Key: ',Crypt.aes_key_str("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"));
			
			
			trace('aes_cfb_encode stage : ',Crypt.aes_cfb(bt,iv,true));
			
			str = Crypt.fromByte(bt)
			trace(str)
			sout.appendText('\n'+str)
			trace('aes_cfb_deboce stage state:',Crypt.aes_cfb(bt,iv,false));
			trace('aes_cfb_deboce to String:',bt.toString())
			trace(">>>>>>>>>> End Test AES CFB <<<<<<<<<<<<< \n");
		}
		
		function test_aes_ofb(){
			trace(">>>>>>>>>> Test AES OFB <<<<<<<<<<<<< ");
			// for encode
			var iv:ByteArray = new ByteArray();
			iv.writeBytes(Crypt.toByte("27f63f5204217f3f80adffeeb92351aa"));
			
			//trace(toArray("27f63f5204217f3f80adffeeb92351aa"));return
			var bt:ByteArray = new ByteArray();
			bt.writeMultiByte('Brian Gladman Brian Gladman Brian Gladman','ansi');
			
			// aes key
			var str:String = ''
			var key:ByteArray = new ByteArray();
			key.writeMultiByte('0123456789123456','ansi'); 
			
			trace('initail AES Key: ',		Crypt.aes_key_byte(key));
		
			
			trace('aes_ofb_encode state : ',Crypt.aes_ofb(bt,iv) );
			
			str = Crypt.fromByte(bt)
			sout.appendText('\naes_ofb encode : '+str)
			trace('aes_ofb encode : ',str)
			
			trace('aes_ofb_deboce state error:',Crypt.aes_ofb(bt,iv));
			
			trace('aes_ofb_deboce toString:\n',bt.toString())
			
			trace(">>>>>>>>>> End Test AES OFB <<<<<<<<<<<<< \n");
		}
		
		function test_aes_ctr(){
			trace(">>>>>>>>>> Test AES CTR RFC3686<<<<<<<<<<<<< ");
			// for encode
			var iv:ByteArray = new ByteArray();
			// 将 Nonce 写在 前 4位, 接着是AES-CTR IV 的 8位
			iv.writeBytes(Crypt.toByte("001CC5B751A51D70A1C1114811111111"));
			
			var bt:ByteArray = new ByteArray();
			bt.writeBytes(Crypt.toByte('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20212223'));
			
			// aes key
			var str:String = ''
			
			trace(Crypt.aes_key_str('FF7A617CE69148E4F1726E2F43581DE2AA62D9F805532EDFF1EED687FB54153D')); 
			
			
			var ooo:* = Crypt.current_iv();
			trace('aes_ctr_encode state error: '  ,Crypt.lib.aes_ctr_3638(bt,undefined,bt.length));
			
			str = Crypt.fromByte(bt);
			trace(str)
			//sout.appendText('\naes_ctr_3638 encode '+str)
			
			trace('aes_ctr_3638 decode state error :',Crypt.aes_ctr_3638(bt,ooo));
			trace('aes_ctr_3638 deboce toString:\n',Crypt.fromByte(bt))
			
			trace(">>>>>>>>>> End Test AES CTR RFC3638<<<<<<<<<<<<< \n");
		}
		
		function loadTest(url:String):void{
			var ff:URLLoader = new URLLoader(null);
			ff.dataFormat = 'binary';
			ff.addEventListener(Event.COMPLETE,onTestLoaded)
			ff.load(new URLRequest(url))
		}
		function onTestLoaded(event:Event):void{
	sout.appendText('\tFile loaded,filesize : '+((event.target.data.length)/1024).toFixed(2)+'Kb .点击flash 查看测试\n');
	this.sout.appendText ( '\t AS3\t\t microsec \t\t\t C Lib \t microsec');
	this.data = event.target.data;
			// ----------- C -----------------
			//var key:ByteArray = Crypt.toByte("acf70a16359bf3658bdfb74bda1c4419")
			/*for(var i=0; i<30; i +=1){
			Crypt.aes_key_byte(key);
			to = getTimer();
			Crypt.md5(event.target.data);
			trace(' timelabel : ',getTimer() - to)
			//Crypt.aes_ctr_3638(event.target.data,Crypt.current_iv())
			//
			}*/
	//trace(Crypt.fromByte(Crypt.md5(event.target.data)),' timelabel : ',getTimer() - to)
		
		//trace((event.target.data.toString()))
		//sout.appendText('begin test memory leak')
		
		//this.addChild(new Stats())
		//Crypt.tinymt32()
		
		//this.addEventListener(Event.ENTER_FRAME,onMemoryLeackTest);
		//trace(this.data)
		
		//trace(Crypt.unlzma(this.data,'test'))
		this.stage.addEventListener(MouseEvent.CLICK,onClick);
		//trace(this.data)
		}
		function onClick(event:Event){
			var as_data:ByteArray,c_data:ByteArray;
			var as_str:String,c_str:String;
			var as_num:Number,c_num:Number;
			this.soutCount += 1;
			if(this.soutCount === 8){
				this.sout.text = '\t AS3\\tt micro sec \t\t\t C Lib \t micro sec';
				this.soutCount = 0;
			}
			
			this.to = getTimer();
			as_data = this.md5.hash(this.data);
			sout.appendText('\n\tAS MD5 : \t\t'+String(getTimer() - to))
		
			this.to = getTimer();
			c_data = Crypt.md5(this.data);
			sout.appendText('\t\t\tC MD5:\t\t'+String(getTimer() - to))
			
			sout.appendText('\t'+Crypt.fromByte(as_data)+'\t\t'+Crypt.fromByte(c_data))
			
			this.to = getTimer();
			as_str = Base64.encode(this.data.toString());
			sout.appendText('\n\tAS BASE64:\t'+String(getTimer() - to))
			this.to = getTimer();
			c_str = Crypt.base64(this.data.toString());
			sout.appendText('\t\t\tC BASE64:\t\t'+String(getTimer() - to))
			
			sout.appendText('\t'+as_str.substr(0,26)+'...\t'+c_str.substr(0,26)+'...')
			
			// 这二个 aes 都会 自已修改 this.data 的原值.所以对比 结果
			this.data.position = 0
			this.to = getTimer();
			
			this.as3_aes_ecb_encode(this.data);
			
			sout.appendText('\n\tAS AES ECB:\t'+String(getTimer() - to))
			this.to = getTimer();
			Crypt.lib.aes_ecb(this.data,this.data.length,0);//解密出来.否则数据不对
			sout.appendText('\t\t\tC AES ECB:\t'+String(getTimer() - to))
			sout.appendText("\n")
		}
		
		

        
		
	
		
		function testTinyMt(){
			trace(">>>>>>>>>> Test TinyMt <<<<<<<<<<<<< ");
			
			trace("TinyMt Array init : ",Crypt.array_init_tinymt32([~~(Math.random()*1234567),~~(Math.random()*69875453),~~(Math.random()*642179),~~(Math.random()*6399874),~~(Math.random()*70893145)]));
			trace("TinyMt 32int: ",uint(Crypt.tinymt32_int()));
			trace("tinymt32_generate_float 		1: ",Crypt.tinymt32(1));
			trace("tinymt32_generate_float12 	2: ",Crypt.tinymt32(2));
			trace("tinymt32_generate_floatOC 	3: ",Crypt.tinymt32(3));
			trace("tinymt32_generate_32double	4: ",Crypt.tinymt32(4));
			trace("tinymt32_generate_floatOO:	 ",Crypt.tinymt32(0));
			//var byte:ByteArray = Crypt.tinymt32_byte(50);tinymt32_byte 返回的值不正确,不过可以当成随机 ByteArray
			trace(">>>>>>>>>> End Test TinyMt <<<<<<<<<<<<< ");
		}
		
		function test_aes_timelabel(){
			to = getTimer();
			
			var iv:ByteArray = new ByteArray();
			iv.writeBytes(Crypt.toByte("27f63f5204217f3f80adffeeb92351aa"));
			
			var bt:ByteArray = new ByteArray();
			bt.writeMultiByte('Brian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian GladmanBrian Gladman','ansi');
			
			//this.enpadding16(bt);
			
			var key:ByteArray = new ByteArray();
			key.writeMultiByte('0123456789123456','ansi'); 
			
			Crypt.aes_key_byte(key);
			/**
			* 文本长度 : 1216 , 重复加密次数 10000;
			* ecb : 8192ms
			* cbc : 10994ms
			* cfb : 10950ms
			*/
			for(var i=0; i<0; i+=1){
				Crypt.aes_cfb(bt,iv,1)
				//trace(fromArray(bt));
				Crypt.aes_cfb(bt,iv,0)
				//depadding16(bt)
				//trace(bt);
			}
			sout.appendText('\n加密文本长度为 : '+ bt.length);
			sout.appendText('\n加密次数 : '+ i);
			sout.appendText('\n耗时 : '+(getTimer() - to))
		}
		
		function as3_aes_ecb_encode(data:ByteArray){
			var ecb:* = this.aes;
			Crypt.enpad16(data);
			var len:int = data.length &~ 15;
			var p:int =0;
			while(p < len){
				ecb.encrypt(data , p);
				p +=16;
			}
			return;
		}
		
	}
	
}
