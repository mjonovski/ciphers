import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Scanner;

public class ECBDES {
	
	public static String attack(String s) throws UnsupportedEncodingException {
		String result = "";
		int lengthPart = 16;
		int k = s.length() / lengthPart;
		ArrayList<Integer> niza = new ArrayList<>();
		for (int i = 0; i < k; i++) {
			niza.add(i);
		}
		Collections.sort(niza);
		
		Collections.shuffle(niza);
		
		String attacked = "";
		for (int i = 0; i < k; i++) {
			attacked += s.substring(niza.get(i) * lengthPart, niza.get(i) * lengthPart + lengthPart);
		}
		
		System.out.println("this " + attacked);
		return attacked;
	}
	
	public static void main(String[] args) throws Exception {
		
		// ECB
		CipherDES cipherDES = new CipherDES();
		byte[][] subKeys = cipherDES.getSubkeys(cipherDES.hexStringToByteArray("0000000000000000"));
		String text = "10101000101011010110111010101010101010110101001011011101110101101000011100010001000100010001010101";
		System.out.println(text.length());
		int k = text.length() / 16;
		while (k % 16 != 0) {
			text += "0";
			k = text.length();
		}
		System.out.println(k);
		k = k / 16;
		String last = "000000000000000";
		String encrypted = "";
		for (int i = 0; i < k - 1; i++) {
			String l = text.substring(i * 16, i * 16 + 16);
			byte[] theCph;
			if (i == 0) {
				theCph = cipherDES.cipher(cipherDES.hexStringToByteArray(l), subKeys, "encrypt", true);
				
			} else {
				theCph = cipherDES.cipher(cipherDES.doXORBytes(cipherDES.hexStringToByteArray(l), cipherDES.hexStringToByteArray(last)), subKeys, "encrypt", true);
			}
			last = cipherDES.bytesToHex(theCph);
			encrypted += last;
		}
		
		System.out.println(encrypted);
		String decrypted = "";
	encrypted = attack(encrypted);
		k=encrypted.length()/16;
		byte[] lastb=new byte[16];
		for (int i = 0;i<k;i++) {
			String l = encrypted.substring(i * 16, i * 16 + 16);
			byte[] theCph;
	
				theCph = cipherDES.cipher(cipherDES.hexStringToByteArray(l), subKeys, "decrypt", true);
				if(i!=0)
				theCph=cipherDES.doXORBytes(theCph, lastb);
				lastb=cipherDES.hexStringToByteArray(l);
				decrypted+=cipherDES.bytesToHex(theCph);
			
	
		}
		
		
		System.out.println(text);
		System.out.println( decrypted);
		
	}
}
