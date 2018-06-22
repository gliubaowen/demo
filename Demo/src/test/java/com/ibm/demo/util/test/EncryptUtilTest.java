package com.ibm.demo.util.test;


import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.util.Map;

import org.junit.Test;

import com.ibm.demo.util.DESEncryptUtil;
import com.ibm.demo.util.DHEncryptUtil;
import com.ibm.demo.util.DSAEncryptUtil;
import com.ibm.demo.util.EncryptUtil;
import com.ibm.demo.util.PBEEncryptUtil;
import com.ibm.demo.util.RSAEncryptUtil;



/**
 * 加密测试类
 * @author liubaowen
 *
 */
public class EncryptUtilTest {
	
	
	@Test
	public void SimpleEncryptTest() throws Exception {
		String inputStr = "简单加密";
		System.err.println("原文:\n" + inputStr);

		byte[] inputData = inputStr.getBytes();
		String code = EncryptUtil.encryptBASE64(inputData);

		System.err.println("BASE64加密后:\n" + code);

		byte[] output = EncryptUtil.decryptBASE64(code);

		String outputStr = new String(output);

		System.err.println("BASE64解密后:\n" + outputStr);

		// 验证BASE64加密解密一致性
		assertEquals(inputStr, outputStr);

		// 验证MD5对于同一内容加密是否一致
		assertArrayEquals(EncryptUtil.encryptMD5(inputData), EncryptUtil
				.encryptMD5(inputData));

		// 验证SHA对于同一内容加密是否一致
		assertArrayEquals(EncryptUtil.encryptSHA(inputData), EncryptUtil
				.encryptSHA(inputData));

		String key = EncryptUtil.initMacKey();
		System.err.println("Mac密钥:\n" + key);

		// 验证HMAC对于同一内容，同一密钥加密是否一致
		assertArrayEquals(EncryptUtil.encryptHMAC(inputData, key), EncryptUtil.encryptHMAC(
				inputData, key));

		BigInteger md5 = new BigInteger(EncryptUtil.encryptMD5(inputData));
		System.err.println("MD5:\n" + md5.toString(16));

		BigInteger sha = new BigInteger(EncryptUtil.encryptSHA(inputData));
		System.err.println("SHA:\n" + sha.toString(32));

		BigInteger mac = new BigInteger(EncryptUtil.encryptHMAC(inputData, inputStr));
		System.err.println("HMAC:\n" + mac.toString(16));
	}

	@Test
	public void DESEncryptTest() throws Exception {
		String inputStr = "DES12";
		String key = DESEncryptUtil.initKey("abc");
		System.err.println("原文:\t" + inputStr);

		System.err.println("密钥:\t" + key);

		byte[] inputData = inputStr.getBytes();
		inputData = DESEncryptUtil.encrypt(inputData, key);

		String encryptBASE64 = DESEncryptUtil.encryptBASE64(inputData);
		System.err.println("加密后:\t" + encryptBASE64);

		byte[] decryptBASE64 = DESEncryptUtil.decryptBASE64(encryptBASE64);
		
		byte[] outputData = DESEncryptUtil.decrypt(decryptBASE64, key);
		
		String outputStr = new String(outputData);

		System.err.println("解密后:\t" + outputStr);

	}
	
	@Test
	public void PBEEncryptTest() throws Exception {
		String inputStr = "abc";
		System.err.println("原文: " + inputStr);
		byte[] input = inputStr.getBytes();
 
		String pwd = "efg";
		System.err.println("密码: " + pwd);
 
		byte[] salt = PBEEncryptUtil.initSalt();
 
		byte[] data = PBEEncryptUtil.encrypt(input, pwd, salt);
 
		System.err.println("加密后: " + PBEEncryptUtil.encryptBASE64(data));
 
		byte[] output = PBEEncryptUtil.decrypt(data, pwd, salt);
		String outputStr = new String(output);
 
		System.err.println("解密后: " + outputStr);
		assertEquals(inputStr, outputStr);
	}
	
	private String publicKey;
	private String privateKey;

	/*@Before
	public void setUp() throws Exception {
		Map<String, Object> keyMap = RSAEncryptUtil.initKey();

		publicKey = RSAEncryptUtil.getPublicKey(keyMap);
		privateKey = RSAEncryptUtil.getPrivateKey(keyMap);
		System.err.println("公钥: \n\r" + publicKey);
		System.err.println("私钥： \n\r" + privateKey);
	}*/

	@Test
	public void RSAEncryptTest() throws Exception {
		
		Map<String, Object> keyMap = RSAEncryptUtil.initKey();
		publicKey = RSAEncryptUtil.getPublicKey(keyMap);
		privateKey = RSAEncryptUtil.getPrivateKey(keyMap);
		System.err.println("公钥: \n\r" + publicKey);
		System.err.println("私钥： \n\r" + privateKey);
		
		System.err.println("公钥加密——私钥解密");
		String inputStr = "abc";
		byte[] data = inputStr.getBytes();

		byte[] encodedData = RSAEncryptUtil.encryptByPublicKey(data, publicKey);

		byte[] decodedData = RSAEncryptUtil.decryptByPrivateKey(encodedData,
				privateKey);

		String outputStr = new String(decodedData);
		System.err.println("加密前: " + inputStr + "\n\r" + "解密后: " + outputStr);
		assertEquals(inputStr, outputStr);

	}

	@Test
	public void RSAEncryptTestSign() throws Exception {
		
		Map<String, Object> keyMap = RSAEncryptUtil.initKey();
		publicKey = RSAEncryptUtil.getPublicKey(keyMap);
		privateKey = RSAEncryptUtil.getPrivateKey(keyMap);
		System.err.println("公钥: \n\r" + publicKey);
		System.err.println("私钥： \n\r" + privateKey);
		
		System.err.println("私钥加密——公钥解密");
		String inputStr = "sign";
		byte[] data = inputStr.getBytes();

		byte[] encodedData = RSAEncryptUtil.encryptByPrivateKey(data, privateKey);

		byte[] decodedData = RSAEncryptUtil
				.decryptByPublicKey(encodedData, publicKey);

		String outputStr = new String(decodedData);
		System.err.println("加密前: " + inputStr + "\n\r" + "解密后: " + outputStr);
		assertEquals(inputStr, outputStr);

		System.err.println("私钥签名——公钥验证签名");
		// 产生签名
		String sign = RSAEncryptUtil.sign(encodedData, privateKey);
		System.err.println("签名:\r" + sign);

		// 验证签名
		boolean status = RSAEncryptUtil.verify(encodedData, publicKey, sign);
		System.err.println("状态:\r" + status);
		assertTrue(status);

	}
	
	@Test
	public void DHEncryptTest() throws Exception {
		// 生成甲方密钥对儿
		Map<String, Object> aKeyMap = DHEncryptUtil.initKey();
		String aPublicKey = DHEncryptUtil.getPublicKey(aKeyMap);
		String aPrivateKey = DHEncryptUtil.getPrivateKey(aKeyMap);

		System.err.println("甲方公钥:\r" + aPublicKey);
		System.err.println("甲方私钥:\r" + aPrivateKey);
		
		// 由甲方公钥产生本地密钥对儿
		Map<String, Object> bKeyMap = DHEncryptUtil.initKey(aPublicKey);
		String bPublicKey = DHEncryptUtil.getPublicKey(bKeyMap);
		String bPrivateKey = DHEncryptUtil.getPrivateKey(bKeyMap);
		
		System.err.println("乙方公钥:\r" + bPublicKey);
		System.err.println("乙方私钥:\r" + bPrivateKey);
		
		String aInput = "abc ";
		System.err.println("原文: " + aInput);

		// 由甲方公钥，乙方私钥构建密文
		byte[] aCode = DHEncryptUtil.encrypt(aInput.getBytes(), aPublicKey,
				bPrivateKey);

		// 由乙方公钥，甲方私钥解密
		byte[] aDecode = DHEncryptUtil.decrypt(aCode, bPublicKey, aPrivateKey);
		String aOutput = (new String(aDecode));

		System.err.println("解密: " + aOutput);

		assertEquals(aInput, aOutput);

		System.err.println(" ===============反过来加密解密================== ");
		String bInput = "def ";
		System.err.println("原文: " + bInput);

		// 由乙方公钥，甲方私钥构建密文
		byte[] bCode = DHEncryptUtil.encrypt(bInput.getBytes(), bPublicKey,
				aPrivateKey);

		// 由甲方公钥，乙方私钥解密
		byte[] bDecode = DHEncryptUtil.decrypt(bCode, aPublicKey, bPrivateKey);
		String bOutput = (new String(bDecode));

		System.err.println("解密: " + bOutput);

		assertEquals(bInput, bOutput);
	}

	@Test
	public void DSAEncryptTest() throws Exception {
		String inputStr = "abc";
		byte[] data = inputStr.getBytes();

		// 构建密钥
		Map<String, Object> keyMap = DSAEncryptUtil.initKey();

		// 获得密钥
		String publicKey = DSAEncryptUtil.getPublicKey(keyMap);
		String privateKey = DSAEncryptUtil.getPrivateKey(keyMap);

		System.err.println("公钥:\r" + publicKey);
		System.err.println("私钥:\r" + privateKey);

		// 产生签名
		String sign = DSAEncryptUtil.sign(data, privateKey);
		System.err.println("签名:\r" + sign);

		// 验证签名
		boolean status = DSAEncryptUtil.verify(data, publicKey, sign);
		System.err.println("状态:\r" + status);
		assertTrue(status);

	}
	
	/*@Test
	public void ECCEncryptTest() throws Exception {
		String inputStr = "abc";
		byte[] data = inputStr.getBytes();

		Map<String, Object> keyMap = ECCEncryptUtil.initKey();

		String publicKey = ECCEncryptUtil.getPublicKey(keyMap);
		String privateKey = ECCEncryptUtil.getPrivateKey(keyMap);
		System.err.println("公钥: \n" + publicKey);
		System.err.println("私钥： \n" + privateKey);

		byte[] encodedData = ECCEncryptUtil.encrypt(data, publicKey);

		byte[] decodedData = ECCEncryptUtil.decrypt(encodedData, privateKey);

		String outputStr = new String(decodedData);
		System.err.println("加密前: " + inputStr + "\n\r" + "解密后: " + outputStr);
		assertEquals(inputStr, outputStr);
	}*/
	
}
