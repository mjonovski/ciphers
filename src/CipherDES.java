import java.io.*;
import java.util.ArrayList;

public class CipherDES {
	
	
	static ArrayList<Integer> SBoxOuts1=new ArrayList<>();
	static ArrayList<Integer> SBoxOuts2=new ArrayList<>();
	
	
	//izlezite od S-box se po red vo sekoj obid na algoritmot, odnosno se zemaat broevi prvo od 0-tata pa 1-vata itn kutii.
//	public static void main(String[] a) {
//		
//		try {
//			// генерирање на потклучевите за секоја од итерациите на алгоритмот од клучот
//			byte[][] subKeys = getSubkeys(hexStringToByteArray("0000000000000000"));
//			
//			// повик на метод за шифрување со задавање на пораката како аргумент во хексадецимален формат потоа претворена во низа од бајте
//			//System.out.println("Broevi na S-BOX:");
//			byte[] theCph = cipher(hexStringToByteArray("0000000000000000"), subKeys, "encrypt",true);
//			byte[] theCphChanged = cipher(hexStringToByteArray("0000000000020000"), subKeys, "encrypt",true);
//			
//			System.out.println("Izlez: " + bytesToHex(theCph));
//			System.out.println("Izlez so eden izmenet bajt: " + bytesToHex(theCphChanged));
//			//izlez: 00000000 D8D8DBBC od prvata runda 
//			// 000000007A63C8C4 prva runda za site edinici
//			//F40379AB9E0EC533 prva runda so eden izmenet bajt
//			
//				//System.out.println("Kluch i poraka 1:");
//			//System.out.println("Broevi na S-BOX:");
//			//byte[][] subKeys1 = getSubkeys(hexStringToByteArray("1111111111111111"));
//			
//			
//			//byte[] theCph1 = cipher(hexStringToByteArray("1111111111111111"), subKeys1, "encrypt");
//			
//			
//			System.out.println("Kluch i poraka so izmenet 1 bit na porakata:");
//			//System.out.println("Broevi na S-BOX:");
//			byte[][] subKeys3 = getSubkeys(hexStringToByteArray("0000000011111111"));
//			byte[] theCph3 = cipher(hexStringToByteArray("0000000000000000"), subKeys3, "encrypt",false);
//			System.out.println("Kluch 01");
//			System.out.println(bytesToHex(theCph3));
//					
//			byte[][] subKeys4 = getSubkeys(hexStringToByteArray("1111111100000000"));
//			byte[] theCph4 = cipher(hexStringToByteArray("0000000000000000"), subKeys4, "encrypt",false);
//			System.out.println("Kluch 10");
//			System.out.println(bytesToHex(theCph4));
//			byte[][] subKeys5 = getSubkeys(hexStringToByteArray("1111111111111111"));
//			byte[] theCph5 = cipher(hexStringToByteArray("0000000000000000"), subKeys5, "encrypt",false);
//			System.out.println("Kluch 11");
//			System.out.println(bytesToHex(theCph5));
//			compareArrays();
//			//System.out.println(bytesToHex(theCph1));
//		} catch (Exception e) {
//			e.printStackTrace();
//			return;
//		}
//	}
//	
	
	public static void compareArrays(){
		for(int i=0;i<SBoxOuts1.size();i++){
			if(SBoxOuts1.get(i)!=SBoxOuts2.get(i)){
				System.out.println("Promena vo "+ i/16 + " kutija.");
				System.out.println("Promenet bit: " + i%16);
			}
		}
	}
	
	// иницијална низа за пермутација на пораката според табелата RC-1 каде што оргиналниот 58-ми бајт од пораката станува прв во новата порака, 50-тиот станува втор итн.
	static final int[] IP = {
			58, 50, 42, 34, 26, 18, 10, 2,
			60, 52, 44, 36, 28, 20, 12, 4,
			62, 54, 46, 38, 30, 22, 14, 6,
			64, 56, 48, 40, 32, 24, 16, 8,
			57, 49, 41, 33, 25, 17, 9, 1,
			59, 51, 43, 35, 27, 19, 11, 3,
			61, 53, 45, 37, 29, 21, 13, 5,
			63, 55, 47, 39, 31, 23, 15, 7
	};
	
	static final int[] E = {
			32, 1, 2, 3, 4, 5,
			4, 5, 6, 7, 8, 9,
			8, 9, 10, 11, 12, 13,
			12, 13, 14, 15, 16, 17,
			16, 17, 18, 19, 20, 21,
			20, 21, 22, 23, 24, 25,
			24, 25, 26, 27, 28, 29,
			28, 29, 30, 31, 32, 1
	};
	static final int[] P = {
			16, 7, 20, 21,
			29, 12, 28, 17,
			1, 15, 23, 26,
			5, 18, 31, 10,
			2, 8, 24, 14,
			32, 27, 3, 9,
			19, 13, 30, 6,
			22, 11, 4, 25
	};
	static final int[] INVP = {
			40, 8, 48, 16, 56, 24, 64, 32,
			39, 7, 47, 15, 55, 23, 63, 31,
			38, 6, 46, 14, 54, 22, 62, 30,
			37, 5, 45, 13, 53, 21, 61, 29,
			36, 4, 44, 12, 52, 20, 60, 28,
			35, 3, 43, 11, 51, 19, 59, 27,
			34, 2, 42, 10, 50, 18, 58, 26,
			33, 1, 41, 9, 49, 17, 57, 25
	};
	
	// метод за енкрипција со ДЕС алгоритмот. На почеток на пораката се извршува пермутацијата дадена во табелата ПЦ-1. Следно се дели на два дела, лев и десен дел. На левиот дел се доделува вредноста
	// на пртходниот десен дел, додека на десниот дел се доделува вредноста на Фејстеловата функција која прима 32-битна порака и 48-битен клуч и генерира резултат од 32 бита. Ова се повторува во 16
	// итерации. Над десниот дел и претходниот лев дел се врши XOR операција па резултатот се запишува како десен дел од и-тата итерација.
	// Фејстеловата функција работи на тој начин што секој 32-битен вектор прво го претвора во битен со користење на табелата Е која дава алгоритам за дуплирање на одредени вредности и со тоа ги
	// претвора во низи од 48 бајти. Работи на следнито начин: на прво место го запишува 32-иот бајт на второ место првиот итн. со тоа што последните два бајти од секој ред се повторуваат во следниот
	// (кружно). Следно се врши XOR со новите 48бајти добиени од десниот дел од пораката и 48-те бајти од клучот, со тоа добиваме 8 полиња со по 6 бајти. Следно ги користиме куттите S-box.
	// од добиените 8 полиња со по 6 бајти се земаат вредности од Б1 до Б8. Кутиите ни даваат вредности на следниот начин: првиот и псоледниот бајт од Б ни ја даваат колоната а додека средните 4 ни го
	// даваат редот во и-тата С кутија.Се извршува уште една пермутација на вака добиената низа од бајти за десниот дел според векторот П. На крајот се искорува со пртходната лева исе заппѕва
	// вредноста.
	// резултатот е даден со инверзната пермутација на примарната од последниот лев и послениот лев и последниот десен дел.
	public byte[] cipher(byte[] theMsg, byte[][] subKeys,
			String mode,boolean by) throws Exception {
		if (theMsg.length < 8)
			throw new Exception("Message is less than 64 bits.");
		theMsg = selectBits(theMsg, IP); // Initial Permutation
		int blockSize = IP.length;
		byte[] l = selectBits(theMsg, 0, blockSize / 2);
		byte[] r = selectBits(theMsg, blockSize / 2, blockSize / 2);
		int numOfSubKeys = subKeys.length;
		for (int k = 0; k < numOfSubKeys; k++) {
			byte[] rBackup = r;
			r = selectBits(r, E); // Expansion
			if (mode.equalsIgnoreCase("encrypt"))
				r = doXORBytes(r, subKeys[k]); // XOR with the sub key
			else
				r = doXORBytes(r, subKeys[numOfSubKeys - k - 1]);
			r = substitution6x4(r,by); // Substitution
			r = selectBits(r, P); // Permutation
			r = doXORBytes(l, r); // XOR with the previous left half
			l = rBackup; // Taking the previous right half
			
			if (k == 0) {
//			System.out.println("Izlez od prvata runda za kluch " );
//			System.out.println(bytesToHex(l) + " " + bytesToHex(r));
			}
			
		}
		byte[] lr = concatenateBits(r, blockSize / 2, l, blockSize / 2);
		lr = selectBits(lr, INVP); // Inverse Permutation
		return lr;
	}
	
	// функција која врши логички XOR на две низи од бајти и го враќа резултатот како низа од бајти
	public byte[] doXORBytes(byte[] a, byte[] b) {
		byte[] out = new byte[a.length];
		for (int i = 0; i < a.length; i++) {
			out[i] = (byte) (a[i] ^ b[i]);
		}
		return out;
	}
	
	static final int[] S = {
			14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, // S1
			0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
			4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
			15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
			15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, // S2
			3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
			0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
			13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
			10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, // S3
			13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
			13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
			1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
			7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, // S4
			13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
			10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
			3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
			2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, // S5
			14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
			4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
			11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
			12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, // S6
			10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
			9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
			4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
			4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, // S7
			13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
			1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
			6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
			13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, // S8
			1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
			7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
			2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
	};
	
	// функција која врши пресликување на 8 низи од по 6 бајти (како резултат на иксор од клучот и десниот дел од пораката) и ги заменува со 4 битни вредности дадени во кутиите.
	private static byte[] substitution6x4(byte[] in,boolean by) {
		in = splitBytes(in, 6); // Splitting byte[] into 6-bit blocks
		byte[] out = new byte[in.length / 2];
		int lhByte = 0;
		for (int b = 0; b < in.length; b++) { // Should be sub-blocks
			byte valByte = in[b];
			int r = 2 * (valByte >> 7 & 0x0001) + (valByte >> 2 & 0x0001); // 1 and 6
			int c = valByte >> 3 & 0x000F; // Middle 4 bits
			int hByte = S[64 * b + 16 * r + c]; // 4 bits (half byte) output
			
	//	System.out.println("SBOX NUMBER:" + (64 * b + 16 * r + c)/64);
	//System.out.println("Value of S:");
		//	System.out.println(hByte);
			if(by)
			SBoxOuts1.add(hByte);
			else 
			SBoxOuts2.add(hByte);
				
				
			if (b % 2 == 0)
				lhByte = hByte; // Left half byte
			else
				out[b / 2] = (byte) (16 * lhByte + hByte);
		}
		
		return out;
	}
	
	private static byte[] splitBytes(byte[] in, int len) {
		int numOfBytes = (8 * in.length - 1) / len + 1;
		byte[] out = new byte[numOfBytes];
		for (int i = 0; i < numOfBytes; i++) {
			for (int j = 0; j < len; j++) {
				int val = getBit(in, len * i + j);
				setBit(out, 8 * i + j, val);
			}
		}
		return out;
	}
	
	// вектор кој се користи за генерирање на пермутација на клучот со тоа што 57-миот бајт од клучот станува прв, 49-тиот станува втор итн.
	static final int[] PC1 = {
			57, 49, 41, 33, 25, 17, 9,
			1, 58, 50, 42, 34, 26, 18,
			10, 2, 59, 51, 43, 35, 27,
			19, 11, 3, 60, 52, 44, 36,
			63, 55, 47, 39, 31, 23, 15,
			7, 62, 54, 46, 38, 30, 22,
			14, 6, 61, 53, 45, 37, 29,
			21, 13, 5, 28, 20, 12, 4
	};
	
	// табела која ја претставува пермутацијата на потклучевите
	static final int[] PC2 = {
			14, 17, 11, 24, 1, 5,
			3, 28, 15, 6, 21, 10,
			23, 19, 12, 4, 26, 8,
			16, 7, 27, 20, 13, 2,
			41, 52, 31, 37, 47, 55,
			30, 40, 51, 45, 33, 48,
			44, 49, 39, 56, 34, 53,
			46, 42, 50, 36, 29, 32
	};
	
	// вектор по кој се врши шифтирањто на бајтите во клучот во секоја од итерациите така што во првите две се шифтира еден бајт на лево од средината а еден на десно, за третиот по два итн.
	static final int[] SHIFTS = {
			1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
	};
	
	// фунцкија која од даден клуч како низа од бајти генерира низа од клучеви во форма на матрица така што во првиот ред е првиот потклуч. На почеток се зема должината на векторот ПЦ-1 кој е формиран
	// врз база на истоимената табела. Потоа се зема должината на низата за поместување на бајтите во клучот. На почеток се земаат два вектори д0 и ц0 кои претставуваат две половини од иницијалниот
	// клуч. СЛедно, во 16 итерации се врши следното: во првата итерација се земаат левиот и десниот дел и на првиот потклуч му се доделуваат истите вредности поместени за 1 место во лево. За третиот
	// и четвртиот се земаат вторите Ц и Д и се поместуваат на лево (Ц) за две места и на десно (Д) за 2 места и тн. Вредностите за поместување се дадени во вектор.
	// на крајот на секоја итерација се земаат бајтите од левиот и од десниот дел и се запишуваат во вектор од бајти, кој понатаму се сместува како потклуч од и-тата итерација или и-ти клуч откако и
	// врз него ќе биде извршена пермутаицјата дадена во ПЦ-2 табелата..
	public byte[][] getSubkeys(byte[] theKey)
			throws Exception {
		int activeKeySize = PC1.length;
		int numOfSubKeys = SHIFTS.length;
		byte[] activeKey = selectBits(theKey, PC1);
		int halfKeySize = activeKeySize / 2;
		byte[] c = selectBits(activeKey, 0, halfKeySize);
		byte[] d = selectBits(activeKey, halfKeySize, halfKeySize);
		byte[][] subKeys = new byte[numOfSubKeys][];
		for (int k = 0; k < numOfSubKeys; k++) {
			c = rotateLeft(c, halfKeySize, SHIFTS[k]);
			d = rotateLeft(d, halfKeySize, SHIFTS[k]);
			byte[] cd = concatenateBits(c, halfKeySize, d, halfKeySize);
			subKeys[k] = selectBits(cd, PC2);
		}
		return subKeys;
	}
	
	// функција која врши поместување на лево за одреден број зададен како аргумент степ. Влезни параметри: векторот од бајти кој треба да се помести на лево, неговата должина и бројот на места за кои
	// треба да се помести.
	private static byte[] rotateLeft(byte[] in, int len, int step) {
		int numOfBytes = (len - 1) / 8 + 1;
		byte[] out = new byte[numOfBytes];
		for (int i = 0; i < len; i++) {
			int val = getBit(in, (i + step) % len);
			setBit(out, i, val);
		}
		return out;
	}
	
	// функција која врши спојување на две низи во една резултантна низа
	private static byte[] concatenateBits(byte[] a, int aLen, byte[] b,
			int bLen) {
		int numOfBytes = (aLen + bLen - 1) / 8 + 1;
		byte[] out = new byte[numOfBytes];
		int j = 0;
		for (int i = 0; i < aLen; i++) {
			int val = getBit(a, i);
			setBit(out, j, val);
			j++;
		}
		for (int i = 0; i < bLen; i++) {
			int val = getBit(b, i);
			setBit(out, j, val);
			j++;
		}
		return out;
	}
	
	//
	private static byte[] selectBits(byte[] in, int pos, int len) {
		int numOfBytes = (len - 1) / 8 + 1;
		byte[] out = new byte[numOfBytes];
		for (int i = 0; i < len; i++) {
			int val = getBit(in, pos + i);
			setBit(out, i, val);
		}
		return out;
	}
	
	private static byte[] selectBits(byte[] in, int[] map) {
		int numOfBytes = (map.length - 1) / 8 + 1;
		byte[] out = new byte[numOfBytes];
		for (int i = 0; i < map.length; i++) {
			int val = getBit(in, map[i] - 1);
			setBit(out, i, val);
		}
		return out;
	}
	
	private static int getBit(byte[] data, int pos) {
		int posByte = pos / 8;
		int posBit = pos % 8;
		byte valByte = data[posByte];
		int valInt = valByte >> (8 - (posBit + 1)) & 0x0001;
		return valInt;
	}
	
	private static void setBit(byte[] data, int pos, int val) {
		int posByte = pos / 8;
		int posBit = pos % 8;
		byte oldByte = data[posByte];
		oldByte = (byte) (((0xFF7F >> posBit) & oldByte) & 0x00FF);
		byte newByte = (byte) ((val << (8 - (posBit + 1))) | oldByte);
		data[posByte] = newByte;
	}
	
	final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();
	
	public static String bytesToHex(byte[] bytes) {
		char[] hexChars = new char[bytes.length * 2];
		for (int j = 0; j < bytes.length; j++) {
			int v = bytes[j] & 0xFF;
			hexChars[j * 2] = hexArray[v >>> 4];
			hexChars[j * 2 + 1] = hexArray[v & 0x0F];
		}
		return new String(hexChars);
	}
	
	public static byte[] hexStringToByteArray(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
		}
		return data;
	}
	
}