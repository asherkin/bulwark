package org.limetech.bulwark;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class Bulwark {
	
	public static final int IDBSPHEADER = (('P'<<24)+('S'<<16)+('B'<<8)+'V');
	public static final int HEADER_LUMPS = 64;
	
	static class bspheader_t
	{
		public int			ident;			// BSP file identifier
		public int			version;		// BSP file version
		public bsplump_t[]	lumps;			// lump directory array
		public int			mapRevision;	// the map's revision (iteration, version) number 
	};

	static class bsplump_t
	{
		int		fileofs;	// offset into file (bytes)
		int		filelen;	// length of lump(bytes)
		int		version;	// lump format version
		byte[]	fourCC;		// lump ident code
	}
	
	public static void main(String[] args) {
		if (args.length < 1) {
			System.out.println("BSP Entity Encryption Tool (Bulwark) - Asher \"asherkin\" Baker");
			System.out.println("Usage: java -jar Bulwark.jar <map.bsp>");
			System.out.println("Warning: This tool will modify the bsp file directly.");
			System.exit(0);
		}
		
		String mapPath = args[0];
		mapPath = mapPath.substring(0, mapPath.length() - 4);
		
		RandomAccessFile bspFile = null;
		
		try {
			bspFile = new RandomAccessFile(mapPath + ".bsp", "rw");
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			System.exit(1);
		}
		
		ByteBuffer bspReader = ByteBuffer.allocate(1036);
		bspReader.order(ByteOrder.LITTLE_ENDIAN);
		
		try {
			bspFile.read(bspReader.array());
		} catch (IOException e) {
			e.printStackTrace();
			System.exit(1);
		}
		
		// Read the header
		bspheader_t bspHeader = null;
		bspHeader = new bspheader_t();
		bspHeader.ident = bspReader.getInt();
		bspHeader.version = bspReader.getInt();
		bspHeader.lumps = new bsplump_t[HEADER_LUMPS];
		for (int lump = 0; lump < HEADER_LUMPS; lump++) {
			bspHeader.lumps[lump] = new bsplump_t();
			bspHeader.lumps[lump].fileofs = bspReader.getInt();
			bspHeader.lumps[lump].filelen = bspReader.getInt();
			bspHeader.lumps[lump].version = bspReader.getInt();
			bspHeader.lumps[lump].fourCC = new byte[4];
			for (int fourCC = 0; fourCC < 4; fourCC++) {
				bspHeader.lumps[lump].fourCC[fourCC] = bspReader.get();
			}
		}
		bspHeader.mapRevision = bspReader.getInt();
		
		if (bspHeader.ident != IDBSPHEADER) {
			System.err.printf("BSP ident mismatch. (%d != %d)\n", bspHeader.ident, IDBSPHEADER);
			System.exit(1);
		}
		
		//if (bspHeader.version != 20) {
		//	System.err.printf("BSP version mismatch. (%d != %d)\n", bspHeader.version, 20);
		//	System.exit(1);
		//}
		
		byte[] entityLump = new byte[bspHeader.lumps[0].filelen - 1 /* extra null byte */];
		try {
			bspFile.seek(bspHeader.lumps[0].fileofs);
			bspFile.read(entityLump);
		} catch (IOException e) {
			e.printStackTrace();
			System.exit(1);
		}
		
		int endOfWorldspawn = 0;
		while (true) {
			if (entityLump[endOfWorldspawn] == '}')
				break;
			endOfWorldspawn++;
		}
		endOfWorldspawn += 2;
		
		String worldspawn = new String(entityLump, 0, endOfWorldspawn);
		String entities = new String(entityLump, endOfWorldspawn, entityLump.length - endOfWorldspawn - 1);
		
		try {
			bspFile.seek(bspHeader.lumps[0].fileofs + endOfWorldspawn);
		} catch (IOException e) {
			e.printStackTrace();
			System.exit(1);
		}
		
		String playerStartEntity = "\n{\n\"origin\" \"0 0 0\"\n\"angles\" \"0 0 0\"\n\"classname\" \"info_player_start\"\n}\n";
		
		try {
			bspFile.writeBytes(playerStartEntity);
		} catch (IOException e) {
			e.printStackTrace();
			System.exit(1);
		}
		
		for (int i = 0; i < (entityLump.length - endOfWorldspawn - playerStartEntity.length()); i++) {
			try {
				bspFile.write('\0');
			} catch (IOException e) {
				e.printStackTrace();
				System.exit(1);
			}
		}
		
		try {
			bspFile.close();
		} catch (IOException e) {
			e.printStackTrace();
			System.exit(1);
		}
		
		try {
			RandomAccessFile entityFile = new RandomAccessFile(mapPath + ".entities.txt", "rw");
			entityFile.writeBytes(entities);
			entityFile.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			System.exit(1);
		} catch (IOException e) {
			e.printStackTrace();
			System.exit(1);
		}
		
		IceKey entityEncrypter = new IceKey(0);
		entityEncrypter.set("A5fSXbf7".getBytes());
		
		while (entities.length() % entityEncrypter.blockSize() != 0) {
			entities = entities.concat("\0");
		}
		
		byte[] plaintextEntites = entities.getBytes();
		byte[] ciphertextEntites = new byte[entities.length()];
		
		for (int bytes = 0; bytes < entities.length(); bytes += entityEncrypter.blockSize()) {
			byte[] plaintext = new byte[entityEncrypter.blockSize()];
			byte[] ciphertext = new byte[entityEncrypter.blockSize()];
			
			for (int i = 0; i < entityEncrypter.blockSize(); i++) {
				plaintext[i] = plaintextEntites[bytes + i];
			}
			
			entityEncrypter.encrypt(plaintext, ciphertext);
			
			for (int i = 0; i < entityEncrypter.blockSize(); i++) {
				ciphertextEntites[bytes + i] = ciphertext[i];
			}
		}
		
		try {
			RandomAccessFile encryptedEntityFile = new RandomAccessFile(mapPath + ".entities.ctx", "rw");
			encryptedEntityFile.write(ciphertextEntites);
			encryptedEntityFile.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			System.exit(1);
		} catch (IOException e) {
			e.printStackTrace();
			System.exit(1);
		}
	}

}
